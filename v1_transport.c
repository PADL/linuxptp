/**
 * @file v1_transport.c
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2024 PADL Software Pty Ltd, Luke Howard <lukeh@padl.com>
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "address.h"
#include "config.h"
#include "contain.h"
#include "print.h"
#include "sk.h"
#include "ether.h"
#include "transport_private.h"
#include "clock.h"
#include "port.h"
#include "v1_msg.h"
#include "v1_transport.h"

#define EVENT_PORT	319
#define GENERAL_PORT	320

#define MC_ADDR_COUNT	4

__attribute__((weak)) struct clock *port_clock(struct port *p);
__attribute__((weak)) void port_set_version(struct port *p, UInteger8 versionNumber);
__attribute__((weak)) enum fsm_event port_event(struct port *port, int fd_index);

static void free_map_entries(void *arg);

struct v1_transport {
	struct transport t;
	struct address ip;
	struct address mac;
	struct address mcast;
	struct ptp_context_v1 context;
	const struct ptp_message_v1 *last_v1_sync;
};

/* IPv4 multicast: 224.0.1.129...132 */
static struct in_addr ipv4_mcast_addr[MC_ADDR_COUNT] = {
	{ .s_addr = 0xE0000181 },
	{ .s_addr = 0xE0000182 },
	{ .s_addr = 0xE0000183 },
	{ .s_addr = 0xE0000184 },
};

/* IPv6 multicast: FF0X:0:0:0:0:0:0:181...184 */
static struct in6_addr ipv6_mcast_addr[MC_ADDR_COUNT] = {
	{ { "\xFF\x0E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB5" } },
	{ { "\xFF\x0E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB6" } },
	{ { "\xFF\x0E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB7" } },
	{ { "\xFF\x0E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xB8" } },
};

/* Returns TRUE if ptp4l instantiated the transport. */
static inline bool v1_is_ptp_transport_p(const struct v1_transport *v1)
{
	return v1->t.context != NULL && port_clock != NULL &&
		port_set_version != NULL && port_event != NULL;
}

static inline sa_family_t v1_transport_family(const struct v1_transport *v1)
{
	switch (v1->t.type) {
	case TRANS_V1_UDP_IPV4_NP:
		return AF_INET;
	case TRANS_V1_UDP_IPV6_NP:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

static int v1_mcast_bind(int fd, int index, sa_family_t family)
{
	int err;

	switch (family) {
	case AF_INET: {
		struct ip_mreqn req = { .imr_ifindex = index };

		err = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &req, sizeof(req));
		break;
	}
	case AF_INET6: {
		struct ipv6_mreq req = { .ipv6mr_interface = index };

		err = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &req, sizeof(req));
		break;
	}
	default:
		return -EAFNOSUPPORT;
	}

	if (err) {
		pr_err("setsockopt IP%s_MULTICAST_IF failed: %m",
		       family == AF_INET6 ? "V6" : "");
		return -errno;
	}

	return 0;
}

static int v1_mcast_join(int fd, int index, sa_family_t family,
			 const struct address *mcast_addr)
{
	int err, off = 0;

	switch (family) {
	case AF_INET: {
		struct ip_mreqn req = { .imr_ifindex = index };

		req.imr_multiaddr = mcast_addr->sin.sin_addr;
		err = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 &req, sizeof(req));
		break;
	}
	case AF_INET6: {
		struct ipv6_mreq req = { .ipv6mr_interface = index };

		req.ipv6mr_multiaddr = mcast_addr->sin6.sin6_addr;
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				 &req, sizeof(req));
		break;
	}
	default:
		return -EAFNOSUPPORT;
	}

	if (err) {
		pr_err("setsockopt IP%s_ADD_MEMBERSHIP failed: %m",
		       family == AF_INET6 ? "V6" : "");
		return -errno;
	}

	switch (family) {
	case AF_INET:
		err = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP,
				 &off, sizeof(off));
		break;
	case AF_INET6:
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				 &off, sizeof(off));
		break;
	}

	if (err) {
		pr_err("setsockopt IP%s_MULTICAST_LOOP failed: %m",
		       family == AF_INET6 ? "V6" : "");
		return -errno;
	}

	return 0;
}

/*
 * A handle (defined in Annex C of 1588-2002) is an index into a set
 * of network addresess for non-default subdomains. The special value
 * -1 is used to represent the default subdomain, and should be mapped
 * to the first multicast address.
 */

static int v1_get_mcast_address(const struct v1_transport *v1, struct address *addr)
{
	int err, handle;

	err = domainNumber_to_handle(&v1->context, v1->context.domain_number, &handle);
	if (err)
		return err;

	memset(addr, 0, sizeof(*addr));

	/* convert from handle (-1...2) to address index (0...3) */
	if (++handle >= MC_ADDR_COUNT)
		return -ERANGE;

	addr->sa.sa_family = v1_transport_family(v1);
	addr->len = address_length(addr->sa.sa_family);

	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->sin.sin_addr.s_addr = htonl(ipv4_mcast_addr[handle].s_addr);
		break;
	case AF_INET6:
		addr->sin6.sin6_addr = ipv6_mcast_addr[handle];
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

static int v1_transport_close(struct transport *t, struct fdarray *fda)
{
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);

	free_map_entries(&v1->context.domain_map);
	free_map_entries(&v1->context.clock_class_map);
	free_map_entries(&v1->context.priority1_map);
	free_map_entries(&v1->context.priority2_map);

	close(fda->fd[0]);
	close(fda->fd[1]);

	return 0;
}

static int v1_transport_socket(const char *name, sa_family_t family,
			       const struct address *mcast_addr,
			       uint16_t port, int ttl)
{
	struct address addr;
	int err, fd, index, on = 1;

	memset(&addr, 0, sizeof(addr));
	addr.len = address_length(family);

	switch (family) {
	case AF_INET: {
		struct sockaddr_in *sin = &addr.sin;

		sin->sin_family = family;
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
		sin->sin_port = htons(port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = &addr.sin6;

		sin6->sin6_family = family;
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = htons(port);
		break;
	}
	default:
		return -1;
	}

	fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("socket failed: %m");
		goto no_socket;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto no_option;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		pr_err("setsockopt SO_REUSEADDR failed: %m");
		goto no_option;
	}
	if (bind(fd, &addr.sa, addr.len)) {
		pr_err("bind failed: %m");
		goto no_option;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		pr_err("setsockopt SO_BINDTODEVICE failed: %m");
		goto no_option;
	}

	switch (family) {
	case AF_INET:
		err = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
		break;
	case AF_INET6:
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
		break;
	}
	if (err) {
		pr_err("setsockopt %s failed: %m",
		       (family == AF_INET) ? "IP_MULTICAST_TTL"
					   : "IPV6_MULTICAST_HOPS");
		goto no_option;
	}

	if (v1_mcast_join(fd, index, family, mcast_addr))
		goto no_option;
	if (v1_mcast_bind(fd, index, family))
		goto no_option;

	return fd;
no_option:
	close(fd);
no_socket:
	return -1;
}

static int string_to_address(sa_family_t family,
			     const char *src,
			     struct address *address)
{
	int err;
	void *dst;

	switch (family) {
	case AF_INET:
		dst = &address->sin.sin_addr.s_addr;
		break;
	case AF_INET6:
		dst = address->sin6.sin6_addr.s6_addr;
		break;
	default:
		return -EAFNOSUPPORT;
	}

	address->len = address_length(family);
	address->sa.sa_family = family;

	err = inet_pton(family, src, dst);
	if (err == 1)
		return 0;
	else if (err < 0)
		return -errno;
	else
		return -EINVAL;
}

static enum parser_result get_ranged_uint_pair(char *value,
					       unsigned int *min_val, unsigned int *max_val,
					       unsigned int range_min, unsigned int range_max)
{
	enum parser_result r;
	char *p;

	*min_val = range_min;
	*max_val = range_max;

	p = strchr(value, '-');
	if (p == NULL) {
		r = get_ranged_uint(value, min_val, range_min, range_max);
		if (r == PARSED_OK)
			*max_val = *min_val;
		return r;
	}

	*p++ = '\0';

	r = get_ranged_uint(value, min_val, range_min, range_max);
	if (r != PARSED_OK)
		return r;

	r = get_ranged_uint(p, max_val, *min_val, range_max);
	if (r != PARSED_OK)
		return r;

	return PARSED_OK;
}

static enum parser_result parse_domain_map_entry(char *key, char *value, void *arg)
{
	struct ptp_v1_domain_map_entry *entry = arg;
	unsigned int domain;
	size_t len;
	enum parser_result r;

	r = get_ranged_uint(key, &domain, 0, UINT8_MAX);
	if (r != PARSED_OK) {
		pr_err("PTPv1 domain map: invalid domainNumber %s", key);
		return r;
	}

	entry->domainNumber = domain;

	len = strlen(value);
	if (len > PTP_V1_SUBDOMAIN_NAME_LENGTH) {
		pr_err("PTPv1 domain map: subdomain %s is too long", value);
		return OUT_OF_RANGE;
	}

	pr_debug("PTPv1: mapping domainNumber %u to subdomain %s", domain, value);

	memcpy(entry->subdomain, value, len);
	memset(&entry->subdomain[len], 0, PTP_V1_SUBDOMAIN_NAME_LENGTH - len);

	return PARSED_OK;
}

static enum parser_result parse_clockClass_map_entry(char *key, char *value, void *arg)
{
	struct ptp_v1_clockClass_map_entry *entry = arg;
	unsigned int clockClass_min, clockClass_max, stratum;
	enum parser_result r;

	r = get_ranged_uint_pair(key, &clockClass_min, &clockClass_max, 0, UINT8_MAX);
	if (r != PARSED_OK) {
		pr_err("PTPv1 clockClass map: invalid clockClass %s", key);
		return r;
	}

	r = get_ranged_uint(value, &stratum, 0, UINT8_MAX);
	if (r != PARSED_OK) {
		pr_err("PTPv1 clockClass map: invalid stratum %s", value);
		return r;
	}

	pr_debug("PTPv1: mapping clockClass %u-%u to stratum %u",
		 clockClass_min, clockClass_max, stratum);

	entry->clockClass_min = clockClass_min;
	entry->clockClass_max = clockClass_max;
	entry->stratum = stratum;

	return PARSED_OK;
}

static enum parser_result parse_priority1_map_entry(char *key, char *value, void *arg)
{
	struct ptp_v1_priority1_map_entry *entry = arg;
	unsigned int priority1_min, priority1_max, stratum;
	enum parser_result r;
	const char *p;

	r = get_ranged_uint_pair(key, &priority1_min, &priority1_max, 0, UINT8_MAX);
	if (r != PARSED_OK) {
		pr_err("PTPv1 priority1 map: invalid priority1 %s", key);
		return r;
	}

	entry->flags = 0;
	entry->priority1_min = priority1_min;
	entry->priority1_max = priority1_max;

	p = strchr(value, ',');
	if (p == NULL)
		return MALFORMED;
	p++;

	if (strncmp(value, "0,", 2) == 0) {
		;
	} else if (strncmp(value, "1,", 2) == 0) {
		entry->flags |= PTP_V1_PRIORITY_MAP_GM_PREFERRED;
	} else {
		pr_err("PTPv1 priority1 map: invalid GM preferred value %.2s", value);
		return BAD_VALUE;
	}

	if (strcmp(p, "*") != 0) {
		r = get_ranged_uint(p, &stratum, 0, UINT8_MAX);
		if (r != PARSED_OK) {
			pr_err("PTPv1 priority1 map: invalid stratum %s", p);
			return r;
		}

		entry->stratum = stratum;
		entry->flags |= PTP_V1_PRIORITY_MAP_HAS_STRATUM;

		pr_debug("PTPv1: mapping priority1 %u-%u to stratum %u, gmPreferred %u",
			 priority1_min, priority1_max, stratum,
			 !!(entry->flags & PTP_V1_PRIORITY_MAP_GM_PREFERRED));
	} else {
		pr_debug("PTPv1: priority1 %u-%u stratum is determined by clockClass",
			 priority1_min, priority1_max);
	}

	return PARSED_OK;
}

static enum parser_result parse_priority2_map_entry(char *key, char *value, void *arg)
{
	struct ptp_v1_priority2_map_entry *entry = arg;
	unsigned int priority2_min, priority2_max, grandmasterIsBoundaryClock;
	enum parser_result r;

	r = get_ranged_uint_pair(key, &priority2_min, &priority2_max, 0, UINT8_MAX);
	if (r != PARSED_OK) {
		pr_err("PTPv1 priority2 map: invalid priority2 %s", key);
		return r;
	}

	r = get_ranged_uint(value, &grandmasterIsBoundaryClock, 0, 1);
	if (r != PARSED_OK) {
		pr_err("PTPv1 priority2 map: invalid grandmasterIsBoundaryClock %s", value);
		return r;
	}

	pr_debug("PTPv1: mapping priority2 %u-%u to grandmasterIsBoundaryClock %u",
		 priority2_min, priority2_max, grandmasterIsBoundaryClock);

	entry->priority2_min = priority2_min;
	entry->priority2_max = priority2_max;
	entry->grandmasterIsBoundaryClock = grandmasterIsBoundaryClock;

	return PARSED_OK;
}

struct any_entry {
	STAILQ_ENTRY(any_entry) entries;
};

STAILQ_HEAD(any_head, any_entry);

typedef enum parser_result (*parse_callback)(char *key, char *value, void *arg);

static enum parser_result parse_map_entries(const char *item,
					    parse_callback parse_cb,
					    void *head,
					    size_t entry_size)
{
	enum parser_result r;
	char *str, *token;

	str = strdup(item);
	if (str == NULL)
		return NOT_PARSED;

	token = strtok(str, " ");

	while (token != NULL) {
		void *entry;
		char *p;

		p = strchr(token, ':');
		if (p == NULL) {
			r = BAD_VALUE;
			goto out;
		}
		*p++ = '\0';

		entry = calloc(1, entry_size);
		if (entry == NULL) {
			r = NOT_PARSED;
			goto out;
		}

		r = parse_cb(token, p, entry);
		if (r != PARSED_OK) {
			free(entry);
			goto out;
		}

		STAILQ_INSERT_TAIL((struct any_head *)head, (struct any_entry *)entry, entries);
		token = strtok(NULL, " ");
	}

	r = PARSED_OK;

out:
	free(str);

	return r;
}

static void free_map_entries(void *arg)
{
	struct any_head *head = arg;

	while (!STAILQ_EMPTY(head)) {
		struct any_entry *any = STAILQ_FIRST(head);

		STAILQ_REMOVE_HEAD(head, entries);
		free(any);
	}
}

static int v1_transport_open(struct transport *t, struct interface *iface,
			     struct fdarray *fda, enum timestamp_type ts_type,
			     sa_family_t family, const char *mcast_option)
{
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);
	const char *name = interface_name(iface);
	uint8_t event_dscp, general_dscp;
	int efd, gfd, ttl;
	const char *str;
	struct port *port;

	if (!v1_is_ptp_transport_p(v1)) {
		pr_err("PTPv1 transport is only available with ptp4l");
		goto no_event;
	}

	port = v1->t.context;

	/*
	 * Reaching into the port to set its version isn't particularly elegant,
	 * but it confines PTPv1-specific changes to the transport layer and also
	 * ensures the correct version is reported via PMC.
	 */
	port_set_version(port, PTP_V1_VERSION_PTP);

	v1->context.flags = 0;
	v1->context.domain_number = config_get_int(t->cfg, NULL, "domainNumber");
	v1->context.ts = config_get_int(t->cfg, interface_name(iface), "transportSpecific");
	v1->context.clock = port_clock(port);

	str = config_get_string(t->cfg, name, "ptpv1_domain_map");
	if (str) {
		if (parse_map_entries(str, parse_domain_map_entry, &v1->context.domain_map,
				      sizeof(struct ptp_v1_domain_map_entry)) != PARSED_OK)
			goto no_event;
	}

	str = config_get_string(t->cfg, name, "ptpv1_clockClass_map");
	if (str) {
		if (parse_map_entries(str, parse_clockClass_map_entry, &v1->context.clock_class_map,
				      sizeof(struct ptp_v1_clockClass_map_entry)) != PARSED_OK)
			goto no_event;
	}

	str = config_get_string(t->cfg, name, "ptpv1_priority1_map");
	if (str) {
		if (parse_map_entries(str, parse_priority1_map_entry, &v1->context.priority1_map,
				      sizeof(struct ptp_v1_priority1_map_entry)) != PARSED_OK)
			goto no_event;
	}

	str = config_get_string(t->cfg, name, "ptpv1_priority2_map");
	if (str) {
		if (parse_map_entries(str, parse_priority2_map_entry, &v1->context.priority2_map,
				      sizeof(struct ptp_v1_priority2_map_entry)) != PARSED_OK)
			goto no_event;
	}

	ttl = config_get_int(t->cfg, name, "udp_ttl");
	v1->mac.len = 0;
	sk_interface_macaddr(name, &v1->mac);

	v1->ip.len = 0;
	sk_interface_addr(name, family, &v1->ip);

	/*
	 * IEEE 1588-2002 Annex C specifies a mapping of subdomain names to
	 * multicast addresses. This may be overriden by the configuration.
	 */
	str = config_get_string(t->cfg, name, mcast_option);
	if (str) {
		if (string_to_address(family, str, &v1->mcast)) {
			pr_err("invalid %s %s", mcast_option, str);
			goto no_event;
		}
	} else {
		v1_get_mcast_address(v1, &v1->mcast);
	}

	if (family == AF_INET6) {
		v1->mcast.sin6.sin6_addr.s6_addr[1] =
			config_get_int(t->cfg, name, "ptpv1_udp6_scope");
	}

	efd = v1_transport_socket(name, family, &v1->mcast, EVENT_PORT, ttl);
	if (efd < 0)
		goto no_event;

	gfd = v1_transport_socket(name, family, &v1->mcast, GENERAL_PORT, ttl);
	if (gfd < 0)
		goto no_general;

	if (sk_timestamping_init(efd, interface_label(iface), ts_type, t->type,
				 interface_get_vclock(iface)))
		goto no_timestamping;

	if (sk_general_init(gfd))
		goto no_timestamping;

	event_dscp = config_get_int(t->cfg, NULL, "ptpv1_dscp_event");
	general_dscp = config_get_int(t->cfg, NULL, "ptpv1_dscp_general");

	if (event_dscp && sk_set_priority(efd, family, event_dscp))
		pr_warning("Failed to set PTPv1 event DSCP priority.");
	if (general_dscp && sk_set_priority(gfd, family, general_dscp))
		pr_warning("Failed to set PTPv1 general DSCP priority.");

	fda->fd[FD_EVENT] = efd;
	fda->fd[FD_GENERAL] = gfd;

	return 0;

no_timestamping:
	close(gfd);
no_general:
	close(efd);
no_event:
	return -1;
}

static int v1_transport_open_ipv4(struct transport *t, struct interface *iface,
				  struct fdarray *fda, enum timestamp_type ts_type)
{
	return v1_transport_open(t, iface, fda, ts_type, AF_INET, "ptpv1_dst_ipv4");
}

static int v1_transport_open_ipv6(struct transport *t, struct interface *iface,
				  struct fdarray *fda, enum timestamp_type ts_type)
{
	return v1_transport_open(t, iface, fda, ts_type, AF_INET6, "ptpv1_dst_ipv6");
}

static int v1_transport_recv(struct transport *t, int fd, void *buf, int buflen,
			     struct address *addr, struct hw_timestamp *hwts)
{
	const struct ptp_header *v2_hdr = &((struct ptp_message *)buf)->header;
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);
	const struct ptp_message_v1 *v1_msg;
	struct ptp_message_v1 v1_msg_buf;
	int ret;

	if (!v1_is_ptp_transport_p(v1)) {
		pr_err("PTPv1 transport is only available with ptp4l");
		return -EINVAL;
	}

	if (buflen < sizeof(struct message_data))
		return -ERANGE;

	if (v1->last_v1_sync) {
		v1_msg = v1->last_v1_sync;
	} else {
		ret = sk_receive(fd, v1_msg_buf.data.buffer,
				 sizeof(v1_msg_buf.data.buffer),
				 addr, hwts, MSG_DONTWAIT);
		if (ret < 0)
			return ret;

		v1_msg_buf.length = (size_t)ret;
		v1_msg = &v1_msg_buf;
	}

	ret = v1_message_to_v2(&v1->context, v1_msg, buf);
	if (ret < 0) {
		if (ret != -EPROTO)
			pr_warning("failed to translate PTPv1 message to PTPv2: %s",
				   strerror(-ret));
		return ret;
	}

	if (v1->last_v1_sync)
		memcpy(&v1->context.last_announce_rx.data.buffer, buf, buflen);

	if (msg_type(buf) == SYNC) {
		const struct sync_msg *v2_sync = &((struct ptp_message *)buf)->sync;

		/* store epoch as PTPv1 Follow_Up does not include it */
		v1->context.epoch_number_rx = v2_sync->originTimestamp.seconds_msb;

		v1->context.flags |= PTP_V1_CONTEXT_FLAG_SYNC_AS_ANNO;
		v1->last_v1_sync = v1_msg;

		/* reentrantly inject ANNOUNCE into state machine before returning SYNC */
		port_event(t->context, FD_GENERAL);

		v1->last_v1_sync = NULL;
		v1->context.flags &= ~(PTP_V1_CONTEXT_FLAG_SYNC_AS_ANNO);
	}

	return ntohs(v2_hdr->messageLength);
}

static int v1_transport_send(struct transport *t, struct fdarray *fda,
			     enum transport_event event, int peer, void *buf, int len,
			     struct address *addr, struct hw_timestamp *hwts)
{
	const struct ptp_message *v2_hdr = (struct ptp_message *)buf;
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);
	struct ptp_message_v1 v1_msg;
	unsigned char junk[1600];
	ssize_t cnt;
	int fd = -1, err;
	struct address mcast;

	if (!v1_is_ptp_transport_p(v1)) {
		pr_err("PTPv1 transport is only available with ptp4l");
		return -EINVAL;
	}

	/*
	 * PTPv1 does not have an ANNOUNCE message. Cache PTPv2 announcements, to
	 * be coalesced into future PTPv1 SYNC and DELAY_REQ messages.
	 */
	if (msg_type(v2_hdr) == ANNOUNCE) {
		v1->context.flags |= PTP_V1_CONTEXT_FLAG_LAST_ANNO_LOCAL;
		memcpy(&v1->context.last_announce_tx.data.buffer, buf, len);
		return len;
	}

	err = v2_message_to_v1(&v1->context, buf, &v1_msg);
	if (err) {
		if (err != -EPROTO)
			pr_warning("failed to translate PTPv2 message to PTPv1: %s",
				   strerror(-err));
		return err;
	}

	switch (event) {
	case TRANS_GENERAL:
		fd = fda->fd[FD_GENERAL];
		break;
	case TRANS_EVENT:
	case TRANS_ONESTEP:
	case TRANS_P2P1STEP:
	case TRANS_DEFER_EVENT:
		fd = fda->fd[FD_EVENT];
		break;
	}

	mcast = addr ? *addr : v1->mcast;

	switch (mcast.sa.sa_family) {
	case AF_INET:
		mcast.sin.sin_port = htons(event >= TRANS_EVENT ? EVENT_PORT : GENERAL_PORT);
		break;
	case AF_INET6:
		mcast.sin6.sin6_port = htons(event >= TRANS_EVENT ? EVENT_PORT : GENERAL_PORT);
		break;
	}

	if (event == TRANS_ONESTEP)
		len += 2;

	cnt = sendto(fd, v1_msg.data.buffer, v1_msg.length, 0, &mcast.sa, mcast.len);
	if (cnt < 1) {
		pr_err("sendto failed: %m");
		return -errno;
	}

	if (event == TRANS_EVENT) {
		cnt = sk_receive(fd, junk, v1_msg.length, NULL, hwts, MSG_ERRQUEUE);
		if (cnt < 0)
			return cnt;
	}

	/*
	 * The caller expects us to return the number of PTPv2 bytes sent, so
	 * return the original packet length if we sent the entire translated
	 * PDU, else just return a bogus value.
	 */
	return (cnt == v1_msg.length) ? len : 1;
}

static void v1_transport_release(struct transport *t)
{
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);

	free(v1);
}

static int v1_transport_physical_addr(struct transport *t, uint8_t *addr)
{
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);
	int len = 0;

	if (v1->mac.len) {
		len = MAC_LEN;
		memcpy(addr, v1->mac.sll.sll_addr, len);
	}
	return len;
}

static int v1_transport_protocol_addr(struct transport *t, uint8_t *addr)
{
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);
	int len = 0;

	if (v1->ip.len == 0)
		return 0;

	switch (v1_transport_family(v1)) {
	case AF_INET:
		len = sizeof(v1->ip.sin.sin_addr.s_addr);
		memcpy(addr, &v1->ip.sin.sin_addr.s_addr, len);
		break;
	case AF_INET6:
		len = sizeof(v1->ip.sin6.sin6_addr.s6_addr);
		memcpy(addr, &v1->ip.sin6.sin6_addr.s6_addr, len);
		break;
	}

	return len;
}

static int v1_transport_network_protocol(struct transport *t, uint16_t *proto)
{
	struct v1_transport *v1 = container_of(t, struct v1_transport, t);

	switch (v1_transport_family(v1)) {
	case AF_INET:
		*proto = TRANS_UDP_IPV4;
		break;
	case AF_INET6:
		*proto = TRANS_UDP_IPV6;
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

static struct transport *v1_transport_create_common(sa_family_t family)
{
	struct v1_transport *v1 = calloc(1, sizeof(*v1));

	if (v1 == NULL)
		return NULL;

	STAILQ_INIT(&v1->context.domain_map);
	STAILQ_INIT(&v1->context.clock_class_map);
	STAILQ_INIT(&v1->context.priority1_map);
	STAILQ_INIT(&v1->context.priority2_map);

	v1->t.close = v1_transport_close;
	v1->t.open  = (family == AF_INET) ? v1_transport_open_ipv4
					  : v1_transport_open_ipv6;
	v1->t.recv  = v1_transport_recv;
	v1->t.send  = v1_transport_send;
	v1->t.release = v1_transport_release;
	v1->t.physical_addr = v1_transport_physical_addr;
	v1->t.protocol_addr = v1_transport_protocol_addr;
	v1->t.network_protocol = v1_transport_network_protocol;

	return &v1->t;
}

struct transport *v1_udp_transport_create(void)
{
	return v1_transport_create_common(AF_INET);
}

struct transport *v1_udp6_transport_create(void)
{
	return v1_transport_create_common(AF_INET6);
}
