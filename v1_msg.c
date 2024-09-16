/**
 * @file v1_msg.c
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2024 PADL Software Pty Ltd, Luke Howard <lukeh@padl.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "contain.h"
#include "msg.h"
#include "print.h"
#include "clock.h"
#include "v1_msg.h"

__attribute__((weak)) struct PortIdentity clock_parent_identity(struct clock *c);

/*
 * Translate PTPv1 (IEEE 1588-2002) to PTPv2 (IEEE 1588-2019) messages per
 * Clause 18 of IEEE 1588-2008. This is done at the transport layer, so it
 * does carry a serialization overhead (at least, on little-endian platforms),
 * but it is also minimally intrusive to the PTPv2 state machine.
 */

/* forward declarations for management translation helpers */

static int v1_management_to_v2(const struct ptp_context_v1 *v1_context,
			       const struct management_msg_v1 *v1_mgmt,
			       struct management_msg *v2_mgmt);

static int append_v2_mgmt_error(struct ptp_message *msg, uint16_t error_id);

static int v2_management_to_v1(const struct ptp_context_v1 *v1_context,
			       const struct management_msg *v2_mgmt,
			       struct management_msg_v1 *v1_mgmt);

/* Annex C */

static uint32_t subdomain_crc(const Octet subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH])
{
	uint32_t crc = 0xFFFFFFFF;
	size_t i, j;

	for (i = 0 ; i < PTP_V1_SUBDOMAIN_NAME_LENGTH; i++) {
		uint8_t data = subdomain[i];

		for (j = 0; j < 8; j++) {
			uint8_t b = (crc ^ data) & 1;

			crc >>= 1;
			if (b)
				crc ^= 0xEDB88320;
			data >>= 1;
		}
	}

	return crc ^ 0xFFFFFFFF;
}

static int subdomain_to_handle(const Octet subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH])
{
	if (memcmp(subdomain, PTP_V1_SUBDOMAIN_DFLT, PTP_V1_SUBDOMAIN_NAME_LENGTH) == 0)
		return -1;
	else if (memcmp(subdomain, PTP_V1_SUBDOMAIN_ALT1, PTP_V1_SUBDOMAIN_NAME_LENGTH) == 0)
		return 0;
	else if (memcmp(subdomain, PTP_V1_SUBDOMAIN_ALT2, PTP_V1_SUBDOMAIN_NAME_LENGTH) == 0)
		return 1;
	else if (memcmp(subdomain, PTP_V1_SUBDOMAIN_ALT3, PTP_V1_SUBDOMAIN_NAME_LENGTH) == 0)
		return 2;
	else
		return subdomain_crc(subdomain) % 3;
}

/* Clause 18.3.1 */

static int domainNumber_to_subdomain(const struct ptp_context_v1 *v1_context,
				     UInteger8 domainNumber,
				     Octet subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH])
{
	struct ptp_v1_domain_map_entry *entry;

	STAILQ_FOREACH(entry, &v1_context->domain_map, entries) {
		if (entry->domainNumber == domainNumber) {
			memcpy(subdomain, entry->subdomain, PTP_V1_SUBDOMAIN_NAME_LENGTH);
			return 0;
		}
	}

	return -EPROTO;
}

static int subdomain_to_domainNumber(const struct ptp_context_v1 *v1_context,
				     const Octet subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH],
				     UInteger8 *domainNumber)
{
	struct ptp_v1_domain_map_entry *entry;

	STAILQ_FOREACH(entry, &v1_context->domain_map, entries) {
		if (memcmp(subdomain, entry->subdomain, PTP_V1_SUBDOMAIN_NAME_LENGTH) == 0) {
			*domainNumber = entry->domainNumber;
			return 0;
		}
	}

	return -EPROTO;
}

int domainNumber_to_handle(const struct ptp_context_v1 *v1_context,
			   UInteger8 domainNumber,
			   int *handle)
{
	Octet subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH];
	int err;

	*handle = -1;

	err = domainNumber_to_subdomain(v1_context, domainNumber, subdomain);
	if (err)
		return err;

	*handle = subdomain_to_handle(subdomain);

	return 0;
}

/* Clause 18.3.2 */

static int stratum_to_clockClass(const struct ptp_context_v1 *v1_context,
				 UInteger8 stratum, UInteger8 *clockClass)
{
	struct ptp_v1_clockClass_map_entry *entry;

	STAILQ_FOREACH(entry, &v1_context->clock_class_map, entries) {
		if (stratum == entry->stratum) {
			*clockClass = entry->clockClass_max;
			return 0;
		}
	}

	*clockClass = 255;

	return -EPROTO;
}

static int clockClass_to_stratum(const struct ptp_context_v1 *v1_context,
				 UInteger8 clockClass, UInteger8 *stratum)
{
	struct ptp_v1_clockClass_map_entry *entry;

	STAILQ_FOREACH(entry, &v1_context->clock_class_map, entries) {
		if (clockClass >= entry->clockClass_min &&
		    clockClass <= entry->clockClass_max) {
			*stratum = entry->stratum;
			return 0;
		}
	}

	*stratum = 255;

	return -EPROTO;
}

/* Clause 18.3.3 */

static int preferred_to_priority1(const struct ptp_context_v1 *v1_context,
				  UInteger8 preferred, UInteger8 *priority1)
{
	struct ptp_v1_priority1_map_entry *entry;
	int found = 0;

	/*
	 * The default map entry is:
	 *
	 *	 0-126:1,0 127:1,* 128:0,* 129-255:0,255
	 *
	 * The logic below (assuming the map entry is sorted) allows this to match
	 * the mapping given in Table 97, where grandmasterIsPreferred 0 is mapped
	 * to priority1 128, and grandmasterIsPreferred 1 to priority1 127.
	 */
	STAILQ_FOREACH(entry, &v1_context->priority1_map, entries) {
		bool entryPreferred = !!(entry->flags & PTP_V1_PRIORITY_MAP_GM_PREFERRED);

		if (entryPreferred != preferred)
			continue;

		*priority1 = preferred ? entry->priority1_max : entry->priority1_min;
		found = 1;

		if (!preferred)
			break;
	}

	if (!found)
		return -EPROTO;

	return 0;
}

static int priority1_to_preferred(const struct ptp_context_v1 *v1_context,
				  UInteger8 priority1,
				  UInteger8 clockClass,
				  UInteger8 *preferred,
				  UInteger8 *clockStratum)
{
	struct ptp_v1_priority1_map_entry *entry;
	int err;

	STAILQ_FOREACH(entry, &v1_context->priority1_map, entries) {
		if (priority1 >= entry->priority1_min &&
		    priority1 <= entry->priority1_max) {
			*preferred = !!(entry->flags & PTP_V1_PRIORITY_MAP_GM_PREFERRED);
			if (entry->flags & PTP_V1_PRIORITY_MAP_HAS_STRATUM) {
				*clockStratum = entry->stratum;
				err = 0;
			} else {
				err = clockClass_to_stratum(v1_context, clockClass, clockStratum);
			}

			if (err == 0)
				return 0;
		}
	}

	return -EPROTO;
}

/* Clause 18.3.4 */

#define ATOMIC_CLOCK		0x10
#define GPS			0x20
#define TERRESTIAL_RADIO	0x30
#define PTP			0x40
#define NTP			0x50
#define HAND_SET		0x60
#define OTHER			0x90

static int clockIdentifer_to_clockAccuracy(const Octet clockIdentifier[PTP_V1_CODE_STRING_LENGTH],
					   Enumeration8 *clockAccuracy,
					   Enumeration8 *pTimeSource)
{
	Enumeration8 timeSource;

	if (memcmp(clockIdentifier, PTP_V1_IDENTIFIER_ATOM,
		   PTP_V1_CODE_STRING_LENGTH) == 0) {
		*clockAccuracy = 0x22;
		timeSource = ATOMIC_CLOCK;
	} else if (memcmp(clockIdentifier, PTP_V1_IDENTIFIER_GPS,
		   PTP_V1_CODE_STRING_LENGTH) == 0) {
		*clockAccuracy = 0x22;
		timeSource = GPS;
	} else if (memcmp(clockIdentifier, PTP_V1_IDENTIFIER_NTP,
		   PTP_V1_CODE_STRING_LENGTH) == 0) {
		*clockAccuracy = 0x2F;
		timeSource = NTP;
	} else if (memcmp(clockIdentifier, PTP_V1_IDENTIFIER_HAND,
		   PTP_V1_CODE_STRING_LENGTH) == 0) {
		*clockAccuracy = 0x30;
		timeSource = HAND_SET;
	} else if (memcmp(clockIdentifier, PTP_V1_IDENTIFIER_INIT,
			  PTP_V1_CODE_STRING_LENGTH) == 0) {
		*clockAccuracy = 0xFD;
		timeSource = OTHER;
	} else if (memcmp(clockIdentifier, PTP_V1_IDENTIFIER_DFLT,
		   PTP_V1_CODE_STRING_LENGTH) == 0) {
		*clockAccuracy = 0xFE;
		timeSource = INTERNAL_OSCILLATOR;
	} else {
		return -EBADMSG;
	}

	if (pTimeSource)
		*pTimeSource = timeSource;

	return 0;
}

static int clockAccuracy_to_clockIdentifier(Enumeration8 clockAccuracy,
					    Octet clockIdentifier[PTP_V1_CODE_STRING_LENGTH])
{
	if (clockAccuracy >= 0x20 && clockAccuracy <= 0x22) {
		memcpy(clockIdentifier, PTP_V1_IDENTIFIER_ATOM, PTP_V1_CODE_STRING_LENGTH);
	} else if (clockAccuracy >= 0x23 && clockAccuracy <= 0x2F) {
		memcpy(clockIdentifier, PTP_V1_IDENTIFIER_NTP, PTP_V1_CODE_STRING_LENGTH);
	} else if (clockAccuracy == 0x30) {
		memcpy(clockIdentifier, PTP_V1_IDENTIFIER_HAND, PTP_V1_CODE_STRING_LENGTH);
	} else if (clockAccuracy >= 0x31 && clockAccuracy <= 0xFD) {
		memcpy(clockIdentifier, PTP_V1_IDENTIFIER_INIT, PTP_V1_CODE_STRING_LENGTH);
	} else if (clockAccuracy == 0xFE) {
		memcpy(clockIdentifier, PTP_V1_IDENTIFIER_DFLT, PTP_V1_CODE_STRING_LENGTH);
	} else {
		return -EBADMSG;
	}

	return 0;
}

/* Clause 18.3.5 */

static int isBoundaryClock_to_priority2(const struct ptp_context_v1 *v1_context,
					UInteger8 isBoundaryClock, UInteger8 *priority2)
{
	struct ptp_v1_priority2_map_entry *entry;

	STAILQ_FOREACH(entry, &v1_context->priority2_map, entries) {
		if (isBoundaryClock == entry->grandmasterIsBoundaryClock) {
			*priority2 = isBoundaryClock ? entry->priority2_max : entry->priority2_min;
			return 0;
		}
	}

	return -EPROTO;
}

static int priority2_to_isBoundaryClock(const struct ptp_context_v1 *v1_context,
					UInteger8 priority2, UInteger8 *isBoundaryClock)
{
	struct ptp_v1_priority2_map_entry *entry;

	STAILQ_FOREACH(entry, &v1_context->priority2_map, entries) {
		if (priority2 >= entry->priority2_min &&
		    priority2 <= entry->priority2_max) {
			*isBoundaryClock = entry->grandmasterIsBoundaryClock;
			return 0;
		}
	}

	return -EPROTO;
}

/* Clause 18.3.6 */

static struct {
	UInteger8 messageType_v1;
	UInteger8 control;
	UInteger8 messageType_v2; /* UInteger4 */
} control_messageType_map[] = {
	{ PTP_V1_MESSAGE_TYPE_EVENT, PTP_V1_MESSAGE_SYNC, SYNC },
	{ PTP_V1_MESSAGE_TYPE_EVENT, PTP_V1_MESSAGE_DELAY_REQ, DELAY_REQ },
	{ PTP_V1_MESSAGE_TYPE_GENERAL, PTP_V1_MESSAGE_FOLLOW_UP, FOLLOW_UP },
	{ PTP_V1_MESSAGE_TYPE_GENERAL, PTP_V1_MESSAGE_DELAY_RESP, DELAY_RESP },
	{ PTP_V1_MESSAGE_TYPE_GENERAL, PTP_V1_MESSAGE_MANAGEMENT, MANAGEMENT },
};

static int control_to_messageType(UInteger8 control,
				  UInteger8 messageType_v1,
				  UInteger8 *messageType_v2)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(control_messageType_map); i++) {
		if (control_messageType_map[i].control == control &&
		    control_messageType_map[i].messageType_v1 == messageType_v1) {
			*messageType_v2 = control_messageType_map[i].messageType_v2;
			return 0;
		}
	}

	return -EBADMSG;
}

static int messageType_to_control(UInteger8 messageType_v2,
				  UInteger8 *messageType_v1,
				  UInteger8 *control)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(control_messageType_map); i++) {
		if (control_messageType_map[i].messageType_v2 == messageType_v2) {
			*control = control_messageType_map[i].control;
			*messageType_v1 = control_messageType_map[i].messageType_v1;
			return 0;
		}
	}

	return -EBADMSG;
}

/* Clause 18.3.7-9 */

static int UUID_to_ClockIdentity(UInteger8 communicationTechnology,
				 const Octet uuid[PTP_V1_UUID_LENGTH],
				 struct ClockIdentity *clockIdentity)
{
	if (communicationTechnology != PTP_V1_ETHER)
		return -EPROTO;

	clockIdentity->id[0] = uuid[0];
	clockIdentity->id[1] = uuid[1];
	clockIdentity->id[2] = uuid[2];
	clockIdentity->id[3] = 0xFF;
	clockIdentity->id[4] = 0xFE;
	clockIdentity->id[5] = uuid[3];
	clockIdentity->id[6] = uuid[4];
	clockIdentity->id[7] = uuid[5];

	return 0;
}

static int ClockIdentity_to_UUID(const struct ClockIdentity *clockIdentity,
				 UInteger8 *communicationTechnology,
				 Octet uuid[PTP_V1_UUID_LENGTH])
{
	if (clockIdentity->id[3] != 0xFF ||
	    clockIdentity->id[4] != 0xFE)
		return -EPROTO;

	*communicationTechnology = PTP_V1_ETHER;

	uuid[0] = clockIdentity->id[0];
	uuid[1] = clockIdentity->id[1];
	uuid[2] = clockIdentity->id[2];
	uuid[3] = clockIdentity->id[5];
	uuid[4] = clockIdentity->id[6];
	uuid[5] = clockIdentity->id[7];

	return 0;
}

static int UUID_to_PortIdentity(UInteger8 communicationTechnology,
				const Octet uuid[PTP_V1_UUID_LENGTH],
				UInteger16 portId,
				struct PortIdentity *portIdentity)
{
	int err;

	err = UUID_to_ClockIdentity(communicationTechnology, uuid,
				    &portIdentity->clockIdentity);
	if (err)
		return err;

	portIdentity->portNumber = portId;

	return 0;
}

static int PortIdentity_to_UUID(const struct PortIdentity *portIdentity,
				UInteger8 *communicationTechnology,
				Octet uuid[PTP_V1_UUID_LENGTH],
				UInteger16 *portId)
{
	int err;

	err = ClockIdentity_to_UUID(&portIdentity->clockIdentity,
				    communicationTechnology, uuid);
	if (err)
		return err;

	*portId = portIdentity->portNumber;

	return 0;
}

/* Clause 18.3.10 */

static int flagField_to_flags(const Octet flagField[2], Octet flags[2])
{
	flags[0] = 0;
	flags[1] = 0;

	if (flagField[0] & TWO_STEP)
		flags[1] |= PTP_V1_ASSIST;

	if (flagField[1] & LEAP_61)
		flags[1] |= PTP_V1_LI_61;
	if (flagField[1] & LEAP_59)
		flags[1] |= PTP_V1_LI_59;
	if (flagField[1] & ALT_MASTER)
		return -EPROTO; /* do not transmit */

	return 0;
}

static void v1_msg_to_flagField(const struct sync_delay_req_msg_v1 *msg,
				Octet flagField[2])
{
	bool is_init_dflt;

	flagField[0] = 0;
	flagField[1] = 0;

	is_init_dflt =
		memcmp(msg->grandmasterClockIdentifier, PTP_V1_IDENTIFIER_INIT,
		       PTP_V1_CODE_STRING_LENGTH) == 0 ||
		memcmp(msg->grandmasterClockIdentifier, PTP_V1_IDENTIFIER_DFLT,
		       PTP_V1_CODE_STRING_LENGTH) == 0;

	if (msg->hdr.flags[1] & PTP_V1_ASSIST)
		flagField[0] |= TWO_STEP;

	if (!is_init_dflt) {
		if (msg->grandmasterClockStratum <= 2)
			flagField[1] |= UTC_OFF_VALID | TIME_TRACEABLE | FREQ_TRACEABLE;
		flagField[1] |= PTP_TIMESCALE;
	}
	if (msg->hdr.flags[1] & PTP_V1_LI_61)
		flagField[1] |= LEAP_61;
	if (msg->hdr.flags[1] & PTP_V1_LI_59)
		flagField[1] |= LEAP_59;
}

/* Clause 18.3.12 */

static void offsetScaledLogVariance_to_clockVariance(UInteger16 offsetScaledLogVariance,
						     Integer16 *clockVariance)
{
	*clockVariance = htons(ntohs(offsetScaledLogVariance) - 0x8000);
}

static void clockVariance_to_offsetScaledLogVariance(Integer16 clockVariance,
						     UInteger16 *offsetScaledLogVariance)
{
	*offsetScaledLogVariance = htons(ntohs(clockVariance) + 0x8000);
}

/* Clause 18.3.13 */

static int TimeRepresentation_to_Timestamp(const struct TimeRepresentation *tr,
					   UInteger16 epochNumber,
					   struct Timestamp *ts)
{
	if (ntohl(tr->nanoseconds) < 0)
		return -EBADMSG;

	ts->nanoseconds = (UInteger32)tr->nanoseconds;
	ts->seconds_msb = epochNumber;
	ts->seconds_lsb = tr->seconds;

	return 0;
}

static int Timestamp_to_TimeRepresentation(const struct Timestamp *ts,
					   UInteger16 *epochNumber,
					   struct TimeRepresentation *tr)
{
	if (ntohl(ts->nanoseconds) & 0x80000000)
		return -EBADMSG;

	tr->nanoseconds = (Integer32)ts->nanoseconds;
	if (epochNumber)
		*epochNumber = ts->seconds_msb;
	tr->seconds = ts->seconds_lsb;

	return 0;
}

static int v1_header_to_v2(const struct ptp_context_v1 *v1_context,
			   const struct ptp_message_v1 *v1_msg,
			   struct ptp_header *v2_hdr)
{
	size_t expected_length;
	int err;

	if (v1_msg->length < sizeof(struct ptp_header_v1))
		return -EBADMSG;

	if (ntohs(v1_msg->hdr.versionPTP) != PTP_V1_VERSION_PTP)
		return -EPROTO;

	if (ntohs(v1_msg->hdr.versionNetwork) != PTP_V1_VERSION_NETWORK)
		return -EBADMSG;

	err = control_to_messageType(v1_msg->hdr.control, v1_msg->hdr.messageType,
				     &v2_hdr->tsmt);
	if (err)
		return err;

	v2_hdr->tsmt |= v1_context->ts;

	v2_hdr->ver = PTP_VERSION;

	switch (v1_msg->hdr.control) {
	case PTP_V1_MESSAGE_SYNC:
		/* fallthrough */
	case PTP_V1_MESSAGE_DELAY_REQ:
		expected_length = sizeof(struct sync_delay_req_msg_v1);
		break;
	case PTP_V1_MESSAGE_FOLLOW_UP:
		expected_length = sizeof(struct follow_up_msg_v1);
		break;
	case PTP_V1_MESSAGE_DELAY_RESP:
		expected_length = sizeof(struct delay_resp_msg_v1);
		break;
	case PTP_V1_MESSAGE_MANAGEMENT: {
		expected_length = sizeof(struct management_msg_v1);
		if (v1_msg->length < expected_length)
			return -EBADMSG;
		expected_length += htons(v1_msg->management.parameterLength);

		/*
		 * A grotesque workaround for the fact that PTP_MM_PARENT_DATA_SET is only
		 * 88 octets long in practice (and some PTPv1 servers will only send this),
		 * but the encoded parameterLength is PTP_V1_MAX_MANAGEMENT_PAYLOAD_SIZE (90).
		 */
		if (v1_msg->management.managementMessageKey == PTP_V1_MM_PARENT_DATA_SET &&
		    ntohs(v1_msg->management.parameterLength) == PTP_V1_MAX_MANAGEMENT_PAYLOAD_SIZE)
			expected_length -= 2;

		break;
	}
	default:
		return -EBADMSG;
	}

	if (v1_msg->length < expected_length)
		return -EBADMSG;

	if ((v2_hdr->tsmt & 0x0F) == SYNC &&
	    (v1_context->flags & PTP_V1_CONTEXT_FLAG_SYNC_AS_ANNO)) {
		v2_hdr->tsmt &= ~(0x0F);
		v2_hdr->tsmt |= ANNOUNCE;
	}

	err = subdomain_to_domainNumber(v1_context, v1_msg->hdr.subdomain, &v2_hdr->domainNumber);
	if (err)
		return err;

	if (v1_msg->hdr.messageType == PTP_V1_MESSAGE_TYPE_EVENT) {
		v1_msg_to_flagField(&v1_msg->sync, v2_hdr->flagField);
	} else if (v1_msg->hdr.messageType == PTP_V1_MESSAGE_FOLLOW_UP) {
		v2_hdr->flagField[0] |= TWO_STEP;
	}

	v2_hdr->correction = 0; /* Clause 18.3.14 */

	err = UUID_to_PortIdentity(v1_msg->hdr.sourceCommunicationTechnology,
				   v1_msg->hdr.sourceUuid,
				   v1_msg->hdr.sourcePortId,
				   &v2_hdr->sourcePortIdentity);
	if (err)
		return err;

	v2_hdr->sequenceId = v1_msg->hdr.sequenceId;

	v2_hdr->control = v1_msg->hdr.messageType;

	switch (v2_hdr->tsmt & 0x0F) {
	case SYNC:
		v2_hdr->logMessageInterval = v1_msg->sync.syncInterval;
		break;
	case DELAY_REQ:
		v2_hdr->logMessageInterval = v1_msg->delay_req.syncInterval + 5;
		break;
	default:
		v2_hdr->logMessageInterval = 0;
		break;
	}

	return 0;
}

static int v1_sync_to_v2_sync(const struct ptp_context_v1 *v1_context,
			      const struct sync_delay_req_msg_v1 *v1_sync,
			      struct sync_msg *v2_sync)
{
	v2_sync->hdr.messageLength = htons(sizeof(struct sync_msg));

	return TimeRepresentation_to_Timestamp(&v1_sync->originTimestamp,
					       v1_sync->epochNumber,
					       &v2_sync->originTimestamp);
}

static int v1_delay_req_to_v2(const struct ptp_context_v1 *v1_context,
			      const struct sync_delay_req_msg_v1 *v1_delay_req,
			      struct delay_req_msg *v2_delay_req)
{
	v2_delay_req->hdr.messageLength = htons(sizeof(struct delay_req_msg));

	return TimeRepresentation_to_Timestamp(&v1_delay_req->originTimestamp,
					       v1_delay_req->epochNumber,
					       &v2_delay_req->originTimestamp);
}

static int v1_follow_up_to_v2(const struct ptp_context_v1 *v1_context,
			      const struct follow_up_msg_v1 *v1_follow_up,
			      struct follow_up_msg *v2_follow_up)
{
	int err;

	v2_follow_up->hdr.messageLength = htons(sizeof(struct follow_up_msg));

	err = TimeRepresentation_to_Timestamp(&v1_follow_up->preciseOriginTimestamp,
					      v1_context->epoch_number_rx,
					      &v2_follow_up->preciseOriginTimestamp);
	if (err)
		return err;

	v2_follow_up->hdr.sequenceId = v1_follow_up->associatedSequenceId;

	return 0;
}

static int v1_delay_resp_to_v2(const struct ptp_context_v1 *v1_context,
			       const struct delay_resp_msg_v1 *v1_delay_resp,
			       struct delay_resp_msg *v2_delay_resp)
{
	int err;

	v2_delay_resp->hdr.messageLength = htons(sizeof(struct delay_resp_msg));

	err = TimeRepresentation_to_Timestamp(&v1_delay_resp->delayReceiptTimestamp,
					      v1_context->epoch_number_rx,
					      &v2_delay_resp->receiveTimestamp);
	if (err)
		return err;

	err = UUID_to_PortIdentity(v1_delay_resp->requestingSourceCommunicationTechnology,
				   v1_delay_resp->requestingSourceUuid,
				   v1_delay_resp->requestingSourcePortId,
				   &v2_delay_resp->requestingPortIdentity);
	if (err)
		return err;

	v2_delay_resp->hdr.sequenceId = v1_delay_resp->requestingSourceSequenceId;

	return 0;
}

static int merge_path_trace_tlv(Enumeration8 communicationTechnology,
				const Octet uuid[PTP_V1_UUID_LENGTH],
				struct ClockIdentity *path,
				size_t *count)
{
	struct ClockIdentity ci;
	size_t i;
	int err;

	err = UUID_to_ClockIdentity(communicationTechnology, uuid, &ci);
	if (err)
		return err;

	for (i = 0; i < *count; i++) {
		if (cid_eq(&path[i], &ci))
			return 0;
	}

	memcpy(&path[i++], &ci, sizeof(ci));
	*count = i;

	return 0;
}

static int v1_sync_to_v2_announce(const struct ptp_context_v1 *v1_context,
				  const struct sync_delay_req_msg_v1 *v1_sync,
				  struct announce_msg *v2_announce)
{
	UInteger16 offsetScaledLogVariance;
	struct ClockIdentity *path;
	struct TLV *tlv;
	size_t count;
	int err;

	err = TimeRepresentation_to_Timestamp(&v1_sync->originTimestamp,
					      v1_sync->epochNumber,
					      &v2_announce->originTimestamp);
	if (err)
		return err;

	v2_announce->currentUtcOffset = v1_sync->currentUTCOffset;

	err = preferred_to_priority1(v1_context, v1_sync->grandmasterPreferred,
				     &v2_announce->grandmasterPriority1);
	if (err)
		return err;

	err = stratum_to_clockClass(v1_context, v1_sync->grandmasterClockStratum,
			      &v2_announce->grandmasterClockQuality.clockClass);
	if (err)
		return err;

	err = clockIdentifer_to_clockAccuracy(v1_sync->grandmasterClockIdentifier,
					      &v2_announce->grandmasterClockQuality.clockAccuracy,
					      &v2_announce->timeSource);
	if (err)
		return err;

	clockVariance_to_offsetScaledLogVariance(v1_sync->grandmasterClockVariance,
						 &offsetScaledLogVariance);
	v2_announce->grandmasterClockQuality.offsetScaledLogVariance = offsetScaledLogVariance;

	err = isBoundaryClock_to_priority2(v1_context,
					   v1_sync->grandmasterIsBoundaryClock,
					   &v2_announce->grandmasterPriority2);
	if (err)
		return err;

	err = UUID_to_ClockIdentity(v1_sync->grandmasterCommunicationTechnology,
				    v1_sync->grandmasterClockUuid,
				    &v2_announce->grandmasterIdentity);
	if (err)
		return err;

	v2_announce->stepsRemoved = v1_sync->localStepsRemoved;

	tlv = (struct TLV *)v2_announce->suffix;
	path = (struct ClockIdentity *)tlv->value;

	count = 0;

	err = merge_path_trace_tlv(v1_sync->grandmasterCommunicationTechnology,
				   v1_sync->grandmasterClockUuid,
				   path, &count);
	if (err == 0)
		err = merge_path_trace_tlv(v1_sync->parentCommunicationTechnology,
					   v1_sync->parentUuid,
					   path, &count);
	if (err == 0)
		err = merge_path_trace_tlv(v1_sync->hdr.sourceCommunicationTechnology,
					   v1_sync->hdr.sourceUuid,
					   path, &count);
	if (err)
		return err;

	tlv->type = htons(TLV_PATH_TRACE);
	tlv->length = htons(count * sizeof(struct ClockIdentity));

	v2_announce->hdr.messageLength = htons(sizeof(struct announce_msg) +
		sizeof(struct TLV) + ntohs(tlv->length));

	return 0;
}

int v1_message_to_v2(const struct ptp_context_v1 *v1_context,
		     const struct ptp_message_v1 *v1_msg,
		     struct ptp_message *v2_msg)
{
	int err;

	memset(v2_msg, 0, sizeof(struct message_data));

	err = v1_header_to_v2(v1_context, v1_msg, &v2_msg->header);
	if (err)
		return err;

	switch (msg_type(v2_msg)) {
	case ANNOUNCE:
		err = v1_sync_to_v2_announce(v1_context, &v1_msg->sync, &v2_msg->announce);
		break;
	case SYNC:
		err = v1_sync_to_v2_sync(v1_context, &v1_msg->sync, &v2_msg->sync);
		break;
	case DELAY_REQ:
		err = v1_delay_req_to_v2(v1_context, &v1_msg->delay_req, &v2_msg->delay_req);
		break;
	case FOLLOW_UP:
		err = v1_follow_up_to_v2(v1_context, &v1_msg->follow_up, &v2_msg->follow_up);
		break;
	case DELAY_RESP:
		err = v1_delay_resp_to_v2(v1_context, &v1_msg->delay_resp, &v2_msg->delay_resp);
		break;
	case MANAGEMENT:
		err = v1_management_to_v2(v1_context, &v1_msg->management, &v2_msg->management);
		if (err == -EPROTO)
			err = append_v2_mgmt_error(v2_msg, MID_NOT_SUPPORTED);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static int v2_header_to_v1(const struct ptp_context_v1 *v1_context,
			   const struct ptp_header *v2_hdr,
			   struct ptp_header_v1 *v1_hdr)
{
	int err;
	UInteger16 sourcePortId;

	/*
	 * PTPv2 messages are generated internally, so no validation checks are performed.
	 */

	v1_hdr->versionPTP = htons(PTP_V1_VERSION_PTP);

	v1_hdr->versionNetwork = htons(PTP_V1_VERSION_NETWORK);

	err = domainNumber_to_subdomain(v1_context, v2_hdr->domainNumber, v1_hdr->subdomain);
	if (err)
		return err;

	err = PortIdentity_to_UUID(&v2_hdr->sourcePortIdentity,
				   &v1_hdr->sourceCommunicationTechnology,
				   v1_hdr->sourceUuid,
				   &sourcePortId);
	if (err)
		return err;

	v1_hdr->sourcePortId = sourcePortId;

	err = messageType_to_control(v2_hdr->tsmt & 0x0F, &v1_hdr->messageType, &v1_hdr->control);
	if (err)
		return err;

	v1_hdr->sequenceId = v2_hdr->sequenceId;

	err = flagField_to_flags(v2_hdr->flagField, v1_hdr->flags);
	if (err)
		return err;

	return 0;
}

static int get_path_trace_tlv(const struct announce_msg *v2_announce,
			      struct ClockIdentity **path)
{
	size_t len = v2_announce->hdr.messageLength - sizeof(*v2_announce);
	const uint8_t *suffix = v2_announce->suffix;

	while (len >= sizeof(struct TLV)) {
		const struct TLV *tlv = (const struct TLV *)suffix;
		size_t length;

		if (ntohs(tlv->type) != TLV_PATH_TRACE) {
			suffix += sizeof(struct TLV);
			len -= sizeof(struct TLV);
			continue;
		}

		length = ntohs(tlv->length);
		if ((length % sizeof(struct ClockIdentity)) != 0)
			return -EBADMSG;

		*path = (struct ClockIdentity *)tlv->value;
		return length / sizeof(struct ClockIdentity);
	}

	return 0;
}

static int v2_sync_to_v1(const struct ptp_context_v1 *v1_context,
			 const struct sync_msg *v2_sync,
			 struct sync_delay_req_msg_v1 *v1_sync)
{
	const struct announce_msg *last_announce;
	struct ClockIdentity *path;
	Integer16 clockVariance;
	UInteger16 epochNumber;
	int path_count;
	int err;

	if (v1_sync->hdr.control == PTP_V1_MESSAGE_DELAY_REQ)
		last_announce = &v1_context->last_announce_rx.announce;
	else
		last_announce = &v1_context->last_announce_tx.announce;

	if ((last_announce->hdr.tsmt & 0x0F) != ANNOUNCE) {
		pr_warning("PTPv1 translation requires at least one announce message");
		return -EPROTO;
	}

	err = Timestamp_to_TimeRepresentation(&v2_sync->originTimestamp, &epochNumber,
					      &v1_sync->originTimestamp);
	if (err)
		return err;

	v1_sync->epochNumber = epochNumber;

	v1_sync->currentUTCOffset = last_announce->currentUtcOffset;

	err = ClockIdentity_to_UUID(&last_announce->grandmasterIdentity,
				    &v1_sync->grandmasterCommunicationTechnology,
				    v1_sync->grandmasterClockUuid);
	if (err)
		return err;

	v1_sync->grandmasterPortId = 0;

	v1_sync->grandmasterSequenceId = 0;

	err = priority1_to_preferred(v1_context,
				     last_announce->grandmasterPriority1,
				     last_announce->grandmasterClockQuality.clockClass,
				     &v1_sync->grandmasterPreferred,
				     &v1_sync->grandmasterClockStratum);
	if (err)
		return err;

	clockAccuracy_to_clockIdentifier(last_announce->grandmasterClockQuality.clockAccuracy,
					 v1_sync->grandmasterClockIdentifier);

	offsetScaledLogVariance_to_clockVariance(
		last_announce->grandmasterClockQuality.offsetScaledLogVariance,
		&clockVariance);
	v1_sync->grandmasterClockVariance = clockVariance;

	err = priority2_to_isBoundaryClock(v1_context,
					   last_announce->grandmasterPriority2,
					   &v1_sync->grandmasterIsBoundaryClock);
	if (err)
		return err;

	v1_sync->syncInterval = v2_sync->hdr.logMessageInterval;

	path_count = get_path_trace_tlv(last_announce, &path);

	if (v1_sync->hdr.control == PTP_V1_MESSAGE_DELAY_REQ ||
	    path_count == 1) { /* SYNC and we are the grandmaster */
		UInteger16 parentPortId;

		err = PortIdentity_to_UUID(&last_announce->hdr.sourcePortIdentity,
					   &v1_sync->parentCommunicationTechnology,
					   v1_sync->parentUuid,
					   &parentPortId);
		if (err)
			return err;

		v1_sync->parentPortId = parentPortId;
	} else if (path_count > 1) {
		err = ClockIdentity_to_UUID(&path[path_count - 2],
					    &v1_sync->parentCommunicationTechnology,
					    v1_sync->parentUuid);
		if (err)
			return err;
		v1_sync->parentPortId = 1;
	}

	v1_sync->estimatedMasterVariance = htons(0xFFFF);

	v1_sync->estimatedMasterDrift = htonl(0x7FFFFFFF);

	v1_sync->utcReasonable = FALSE;

	return 0;
}

static int v2_follow_up_to_v1(const struct ptp_context_v1 *v1_context,
			      const struct follow_up_msg *v2_follow_up,
			      struct follow_up_msg_v1 *v1_follow_up)
{
	int err;

	v1_follow_up->associatedSequenceId = v2_follow_up->hdr.sequenceId;

	err = Timestamp_to_TimeRepresentation(&v2_follow_up->preciseOriginTimestamp,
					      NULL, &v1_follow_up->preciseOriginTimestamp);
	if (err)
		return err;

	return 0;
}

static int v2_delay_resp_to_v1(const struct ptp_context_v1 *v1_context,
			       const struct delay_resp_msg *v2_delay_resp,
			       struct delay_resp_msg_v1 *v1_delay_resp)
{
	int err;
	UInteger16 requestingSourcePortId;

	err = Timestamp_to_TimeRepresentation(&v2_delay_resp->receiveTimestamp,
					      NULL, &v1_delay_resp->delayReceiptTimestamp);
	if (err)
		return err;

	err = PortIdentity_to_UUID(&v2_delay_resp->requestingPortIdentity,
				   &v1_delay_resp->requestingSourceCommunicationTechnology,
				   v1_delay_resp->requestingSourceUuid,
				   &requestingSourcePortId);
	if (err)
		return err;

	v1_delay_resp->requestingSourcePortId = requestingSourcePortId;
	v1_delay_resp->requestingSourceSequenceId = v2_delay_resp->hdr.sequenceId;

	return 0;
}

int v2_message_to_v1(const struct ptp_context_v1 *v1_context,
		     const struct ptp_message *v2_msg,
		     struct ptp_message_v1 *v1_msg)
{
	int err;

	memset(v1_msg, 0, sizeof(*v1_msg));

	err = v2_header_to_v1(v1_context, &v2_msg->header, &v1_msg->hdr);
	if (err)
		return err;

	switch (msg_type(v2_msg)) {
	case SYNC:
		/* fallthrough */
	case DELAY_REQ:
		err = v2_sync_to_v1(v1_context, &v2_msg->sync, &v1_msg->sync);
		break;
	case FOLLOW_UP:
		err = v2_follow_up_to_v1(v1_context, &v2_msg->follow_up, &v1_msg->follow_up);
		break;
	case DELAY_RESP:
		err = v2_delay_resp_to_v1(v1_context, &v2_msg->delay_resp, &v1_msg->delay_resp);
		break;
	case MANAGEMENT:
		err = v2_management_to_v1(v1_context, &v2_msg->management, &v1_msg->management);
		break;
	default:
		return -EPROTO; /* ignore */
	}

	if (err)
		return err;

	switch (msg_type(v2_msg)) {
	case SYNC:
		/* fallthrough */
	case DELAY_REQ:
		v1_msg->length = sizeof(struct sync_delay_req_msg_v1);
		break;
	case FOLLOW_UP:
		v1_msg->length = sizeof(struct follow_up_msg_v1);
		break;
	case DELAY_RESP:
		v1_msg->length = sizeof(struct delay_resp_msg_v1);
		break;
	case MANAGEMENT:
		v1_msg->length = sizeof(struct management_msg_v1) +
			v1_msg->management.parameterLength;
		break;
	}

	return 0;
}

/*
 * We support translating PTPv2 management requests to PTPv1 management requests,
 * and PTPv1 management responses to PTPv2 management responses; this allows the
 * pmc tool to be used to interrogate PTPv1 servers. Providing a PTPv1 interface
 * to ptp4l is out of scope.
 */

static int v1_null_mgmt_to_v2(const struct ptp_context_v1 *v1_context,
			      const struct management_msg_v1 *v1_mgmt,
			      struct management_tlv *v2_mgmt)
{
	return 0;
}

static int v2_null_mgmt_to_v1(const struct ptp_context_v1 *v1_context,
			      const struct management_tlv *v2_mgmt,
			      struct management_msg_v1 *v1_mgmt)
{
	return 0;
}

static int v1_default_data_set_to_v2(const struct ptp_context_v1 *v1_context,
				     const struct management_msg_v1 *v1_mgmt,
				     struct management_tlv *v2_mgmt)
{
	struct default_ds_v1 *v1_dds = (struct default_ds_v1 *) v1_mgmt->messageParameters;
	struct defaultDS *v2_dds = (struct defaultDS *) v2_mgmt->data;
	int err;

	if (htons(v1_mgmt->parameterLength) < sizeof(*v1_dds))
		return -EBADMSG;

	v2_dds->flags = 0;

	if (v1_dds->clockFollowupCapable)
		v2_dds->flags |= DDS_TWO_STEP_FLAG;

	v2_dds->numberPorts = v1_dds->numberPorts;

	err = preferred_to_priority1(v1_context, v1_dds->preferred, &v2_dds->priority1);
	if (err)
		return err;

	err = stratum_to_clockClass(v1_context, v1_dds->clockStratum,
				    &v2_dds->clockQuality.clockClass);
	if (err)
		return err;

	err = clockIdentifer_to_clockAccuracy(v1_dds->clockIdentifier,
					      &v2_dds->clockQuality.clockAccuracy,
					      NULL);
	if (err)
		return err;

	err = isBoundaryClock_to_priority2(v1_context, v1_dds->isBoundaryClock, &v2_dds->priority2);
	if (err)
		return err;

	err = subdomain_to_domainNumber(v1_context, v1_dds->subdomainName, &v2_dds->domainNumber);
	if (err)
		return err;

	err = UUID_to_ClockIdentity(v1_dds->clockCommunicationTechnology,
				    v1_dds->clockUuidField,
				    &v2_dds->clockIdentity);
	if (err)
		return err;

	return sizeof(*v2_dds);
}

static int v1_current_data_set_to_v2(const struct ptp_context_v1 *v1_context,
				     const struct management_msg_v1 *v1_mgmt,
				     struct management_tlv *v2_mgmt)
{
	struct current_ds_v1 *v1_cds = (struct current_ds_v1 *) v1_mgmt->messageParameters;
	struct currentDS *v2_cds = (struct currentDS *) v2_mgmt->data;

	if (htons(v1_mgmt->parameterLength) < sizeof(*v1_cds))
		return -EBADMSG;

	v2_cds->stepsRemoved = v1_cds->stepsRemoved;

	if (v1_cds->offsetFromMaster.seconds)
		return -ERANGE;
	v2_cds->offsetFromMaster = v1_cds->offsetFromMaster.nanoseconds << 16;

	if (v1_cds->oneWayDelay.seconds)
		return -ERANGE;
	v2_cds->meanPathDelay = v1_cds->oneWayDelay.nanoseconds << 16;

	return sizeof(*v2_cds);
}

static int v1_parent_data_set_to_v2(const struct ptp_context_v1 *v1_context,
				    const struct management_msg_v1 *v1_mgmt,
				    struct management_tlv *v2_mgmt)
{
	struct parent_ds_v1 *v1_pds = (struct parent_ds_v1 *) v1_mgmt->messageParameters;
	struct parentDS *v2_pds = (struct parentDS *) v2_mgmt->data;
	UInteger16 offsetScaledLogVariance;
	int err;

	if (htons(v1_mgmt->parameterLength) < sizeof(*v1_pds))
		return -EBADMSG;

	err = UUID_to_PortIdentity(v1_pds->parentCommunicationTechnology,
				   v1_pds->parentUuid,
				   v1_pds->parentPortId,
				   &v2_pds->parentPortIdentity);
	if (err)
		return err;

	v2_pds->parentStats = v1_pds->parentStats;

	if (v2_pds->parentStats) {
		clockVariance_to_offsetScaledLogVariance(v1_pds->parentVariance,
							 &offsetScaledLogVariance);
		v2_pds->observedParentOffsetScaledLogVariance = offsetScaledLogVariance;
	}

	err = preferred_to_priority1(v1_context, v1_pds->grandmasterPreferred,
				     &v2_pds->grandmasterPriority1);
	if (err)
		return err;

	err = stratum_to_clockClass(v1_context, v1_pds->grandmasterStratum,
				    &v2_pds->grandmasterClockQuality.clockClass);
	if (err)
		return err;

	err = clockIdentifer_to_clockAccuracy(v1_pds->grandmasterIdentifier,
					      &v2_pds->grandmasterClockQuality.clockAccuracy,
					      NULL);
	if (err)
		return err;

	clockVariance_to_offsetScaledLogVariance(v1_pds->grandmasterVariance,
						 &offsetScaledLogVariance);
	v2_pds->grandmasterClockQuality.offsetScaledLogVariance = offsetScaledLogVariance;

	err = isBoundaryClock_to_priority2(v1_context, v1_pds->grandmasterIsBoundaryClock,
					   &v2_pds->grandmasterPriority2);
	if (err)
		return err;

	err = UUID_to_ClockIdentity(v1_pds->grandmasterCommunicationTechnology,
				    v1_pds->grandmasterUuid,
				    &v2_pds->grandmasterIdentity);
	if (err)
		return err;

	return sizeof(*v2_pds);
}

static int v1_port_data_set_to_v2(const struct ptp_context_v1 *v1_context,
				  const struct management_msg_v1 *v1_mgmt,
				  struct management_tlv *v2_mgmt)
{
	struct port_ds_v1 *v1_pds = (struct port_ds_v1 *) v1_mgmt->messageParameters;
	struct portDS *v2_pds = (struct portDS *) v2_mgmt->data;
	int err;

	if (htons(v1_mgmt->parameterLength) < sizeof(*v1_pds))
		return -EBADMSG;

	err = UUID_to_PortIdentity(v1_pds->portCommunicationTechnology,
				   v1_pds->portUuid,
				   v1_pds->portId,
				   &v2_pds->portIdentity);
	if (err)
		return err;

	v2_pds->portState = v1_pds->portState;
	v2_pds->versionNumber = PTP_V1_VERSION_PTP;

	return sizeof(*v2_pds);
}

static struct management_map_entry {
	Enumeration8 key;
	Enumeration8 action;
	Enumeration16 id;
	int (*v1_to_v2)(const struct ptp_context_v1 *v1_context,
			const struct management_msg_v1 *v1_mgmt,
			struct management_tlv *v2_mgmt);
	int (*v2_to_v1)(const struct ptp_context_v1 *v1_context,
			const struct management_tlv *v1_mgmt,
			struct management_msg_v1 *v2_mgmt);
} management_map[] = {
	{
		PTP_V1_MM_NULL,
		GET,
		MID_NULL_MANAGEMENT,
		v1_null_mgmt_to_v2,
		v2_null_mgmt_to_v1
	},
	{
		PTP_V1_MM_NULL,
		SET,
		MID_NULL_MANAGEMENT,
		v1_null_mgmt_to_v2,
		v2_null_mgmt_to_v1
	},
	{
		PTP_V1_MM_NULL,
		COMMAND,
		MID_NULL_MANAGEMENT,
		v1_null_mgmt_to_v2,
		v2_null_mgmt_to_v1
	},
	{
		PTP_V1_MM_GET_DEFAULT_DATA_SET,
		GET,
		MID_DEFAULT_DATA_SET,
		NULL,
		NULL,
	},
	{
		PTP_V1_MM_DEFAULT_DATA_SET,
		RESPONSE,
		MID_DEFAULT_DATA_SET,
		v1_default_data_set_to_v2,
		NULL,
	},
	{
		PTP_V1_MM_GET_PARENT_DATA_SET,
		GET,
		MID_PARENT_DATA_SET,
		NULL,
		NULL,
	},
	{
		PTP_V1_MM_PARENT_DATA_SET,
		RESPONSE,
		MID_PARENT_DATA_SET,
		v1_parent_data_set_to_v2,
		NULL,
	},
	{
		PTP_V1_MM_GET_CURRENT_DATA_SET,
		GET,
		MID_CURRENT_DATA_SET,
		NULL,
		NULL,
	},
	{
		PTP_V1_MM_CURRENT_DATA_SET,
		RESPONSE,
		MID_CURRENT_DATA_SET,
		v1_current_data_set_to_v2,
		NULL,
	},
	{
		PTP_V1_MM_GET_PORT_DATA_SET,
		GET,
		MID_PORT_DATA_SET,
		NULL,
		NULL,
	},
	{
		PTP_V1_MM_PORT_DATA_SET,
		RESPONSE,
		MID_PORT_DATA_SET,
		v1_port_data_set_to_v2,
		NULL,
	},
};

static int v1_management_to_v2(const struct ptp_context_v1 *v1_context,
			       const struct management_msg_v1 *v1_mgmt,
			       struct management_msg *v2_mgmt)
{
	int err;
	struct management_map_entry *entry = NULL;
	struct management_tlv *tlv;
	size_t i;
	int16_t startingBoundaryHops, boundaryHops;

	if (htons(v1_mgmt->parameterLength) > PTP_V1_MAX_MANAGEMENT_PAYLOAD_SIZE)
		return -EBADMSG;

	err = UUID_to_PortIdentity(v1_mgmt->targetCommunicationTechnology,
				   v1_mgmt->targetUuid,
				   v1_mgmt->targetPortId,
				   &v2_mgmt->targetPortIdentity);
	if (err)
		return err;

	/*
	 * TODO: Clause 6.2.2.1: if boundaryHops is negative, transmit only if
	 * port is not in INITIALIZING state.
	 */

	startingBoundaryHops = ntohs(v1_mgmt->startingBoundaryHops);
	if (startingBoundaryHops == 0x7FFF)
		v2_mgmt->startingBoundaryHops = 0x7F;
	else if (abs(startingBoundaryHops) > UINT8_MAX)
		return -EBADMSG;

	boundaryHops = ntohs(v1_mgmt->boundaryHops);
	if (abs(boundaryHops) > UINT8_MAX)
		return -EBADMSG;

	v2_mgmt->startingBoundaryHops = htons(startingBoundaryHops) & 0xFF;
	v2_mgmt->boundaryHops = htons(boundaryHops) & 0xFF;

	tlv = (struct management_tlv *) v2_mgmt->suffix;
	tlv->type = TLV_MANAGEMENT;

	for (i = 0; i < ARRAY_SIZE(management_map); i++) {
		if (v1_mgmt->managementMessageKey == management_map[i].key) {
			entry = &management_map[i];
			break;
		}
	}

	if (entry == NULL || entry->v1_to_v2 == NULL)
		return -EPROTO;

	v2_mgmt->flags = entry->action;

	err = entry->v1_to_v2(v1_context, v1_mgmt, tlv);
	if (err < 0)
		return err;

	tlv->id = htons(entry->id);
	tlv->length = ntohs(2 + err); /* includes size of id */

	v2_mgmt->hdr.messageLength =
		htons(sizeof(struct management_msg) + sizeof(struct management_tlv) + err);

	return 0;
}

static int append_v2_mgmt_error(struct ptp_message *msg, uint16_t error_id)
{
	struct management_error_status *mes;
	struct management_tlv *tlv;
	struct tlv_extra *extra;

	tlv = (struct management_tlv *) msg->management.suffix;

	extra = msg_tlv_append(msg, sizeof(*msg));
	if (extra == NULL)
		return -ENOMEM;

	mes = (struct management_error_status *) extra->tlv;
	mes->type = TLV_MANAGEMENT_ERROR_STATUS;
	mes->length = 8;
	mes->error = error_id;
	mes->id = tlv->id;

	return 0;
}

static int v2_management_to_v1(const struct ptp_context_v1 *v1_context,
			       const struct management_msg *v2_mgmt,
			       struct management_msg_v1 *v1_mgmt)
{
	struct management_map_entry *entry = NULL;
	struct management_tlv *tlv;
	struct PortIdentity wildcard = {
		.clockIdentity = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		.portNumber = 0xFFFF
	};
	struct PortIdentity parentPortIdentity = clock_parent_identity(v1_context->clock);
	struct PortIdentity *targetPortIdentity =
		(struct PortIdentity *)&v2_mgmt->targetPortIdentity;
	UInteger16 targetPortId;
	size_t i;
	int err;

	/*
	 * PTPv1 doesn't support wildcard port identities. If we receive a PTPv2 for the
	 * wildcard port identity, map it to the parent port identity.
	 */

	if (pid_eq(targetPortIdentity, &wildcard)) {
		err = PortIdentity_to_UUID(&parentPortIdentity,
					   &v1_mgmt->targetCommunicationTechnology,
					   v1_mgmt->targetUuid,
					   &targetPortId);
	} else {
		err = PortIdentity_to_UUID(&v2_mgmt->targetPortIdentity,
					   &v1_mgmt->targetCommunicationTechnology,
					   v1_mgmt->targetUuid,
					   &targetPortId);
	}
	if (err)
		return err;

	v1_mgmt->targetPortId = targetPortId;
	v1_mgmt->startingBoundaryHops = v1_mgmt->startingBoundaryHops;
	v1_mgmt->boundaryHops = v1_mgmt->boundaryHops;

	tlv = (struct management_tlv *) v2_mgmt->suffix;
	if (ntohs(tlv->type) != TLV_MANAGEMENT ||
	    ntohs(tlv->length) < sizeof(tlv->id)) {
		pr_err("PTPv1 received invalid management TLV");
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(management_map); i++) {
		if ((v2_mgmt->flags & 0xf) == management_map[i].action &&
		    ntohs(tlv->id) == management_map[i].id) {
			entry = &management_map[i];
			break;
		}
	}

	if (entry == NULL) {
		pr_warning("no PTPv1 mapping for management ID %d", ntohs(tlv->id));
		return -EPROTO;
	}

	v1_mgmt->managementMessageKey = entry->key;

	if (entry->v2_to_v1) {
		err = entry->v2_to_v1(v1_context, tlv, v1_mgmt);
		if (ntohs(v1_mgmt->parameterLength) > PTP_V1_MAX_MANAGEMENT_PAYLOAD_SIZE)
			return -ERANGE;
	} else if (entry->action == GET || entry->action == COMMAND) {
		err = 0;
		v1_mgmt->parameterLength = 0;
	} else {
		err = -EPROTO;
	}

	if (err)
		return err;

	return 0;
}
