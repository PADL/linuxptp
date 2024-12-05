/**
 * @file udp_private.h
 * @note Copyright (C) 2024 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_UDP_PRIVATE_H
#define HAVE_UDP_PRIVATE_H

#include <netinet/in.h>
#include <arpa/inet.h>

#include "msg.h"
#include "transport.h"

#define EVENT_PORT        319
#define GENERAL_PORT      320

enum { MC_PRIMARY, MC_PDELAY };

struct interface;

int udp_open_socket(struct interface *iface, int event,
		    const struct in_addr *mc_addrs,
		    size_t num_mc_addrs, short port, int ttl,
		    enum timestamp_type ts_type,
		    enum transport_type trans_type);

static inline int is_link_local(struct in6_addr *addr)
{
	return addr->s6_addr[1] == 0x02 ? 1 : 0;
}

int udp6_open_socket(struct interface *iface, int event,
		     const struct in6_addr *mc_addrs,
		     size_t num_mc_addrs, short port,
		     int *interface_index, int hop_limit,
		     enum timestamp_type ts_type,
		     enum transport_type trans_type);

#endif
