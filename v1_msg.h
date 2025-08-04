/**
 * @file v1_msg.h
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2024 PADL Software Pty Ltd, Luke Howard <lukeh@padl.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_V1_MSG_H
#define HAVE_V1_MSG_H

#define PTP_V1_VERSION_PTP			1
#define PTP_V1_VERSION_NETWORK			1

#define PTP_V1_UUID_LENGTH			6
#define PTP_V1_CODE_STRING_LENGTH		4
#define PTP_V1_SUBDOMAIN_NAME_LENGTH		16
#define PTP_V1_MAX_MANAGEMENT_PAYLOAD_SIZE	90
#define PTP_V1_DELAY_REQ_INTERVAL		30
#define PTP_V1_FOREIGN_MASTER_THRESHOLD		2
#define PTP_V1_RANDOMIZING_SLOTS		18
#define PTP_V1_LOG_VARIANCE_THRESHOLD		(1 << 8)
#define PTP_V1_LOG_VARIANCE_HYSTERESIS		(1 << 7)

#define PTP_V1_MESSAGE_TYPE_EVENT		0x01
#define PTP_V1_MESSAGE_TYPE_GENERAL		0x02

#define PTP_V1_MESSAGE_SYNC			0x00
#define PTP_V1_MESSAGE_DELAY_REQ		0x01
#define PTP_V1_MESSAGE_FOLLOW_UP		0x02
#define PTP_V1_MESSAGE_DELAY_RESP		0x03
#define PTP_V1_MESSAGE_MANAGEMENT		0x04

#define PTP_V1_CLOSED				0x00
#define PTP_V1_ETHER				0x01
#define PTP_V1_DEFAULT				0xff

#define PTP_V1_IDENTIFIER_ATOM			"ATOM"
#define PTP_V1_IDENTIFIER_GPS			"GPS\0"
#define PTP_V1_IDENTIFIER_NTP			"NTP\0"
#define PTP_V1_IDENTIFIER_HAND			"HAND"
#define PTP_V1_IDENTIFIER_INIT			"INIT"
#define PTP_V1_IDENTIFIER_DFLT			"DFLT"

#define PTP_V1_SUBDOMAIN_DFLT			"_DFLT\0\0\0\0\0\0\0\0\0\0\0"
#define PTP_V1_SUBDOMAIN_ALT1			"_ALT1\0\0\0\0\0\0\0\0\0\0\0"
#define PTP_V1_SUBDOMAIN_ALT2			"_ALT2\0\0\0\0\0\0\0\0\0\0\0"
#define PTP_V1_SUBDOMAIN_ALT3			"_ALT3\0\0\0\0\0\0\0\0\0\0\0"

#define PTP_V1_LI_61				0x01
#define PTP_V1_LI_59				0x02
#define PTP_V1_BOUNDARY_CLOCK			0x04
#define PTP_V1_ASSIST				0x08
#define PTP_V1_EXT_SYNC				0x10
#define PTP_V1_PARENT_STATS			0x20
#define PTP_V1_SYNC_BURST			0x40

/* Table 25: ManagementMessage enumeration */
#define PTP_V1_MM_NULL					0
#define PTP_V1_MM_OBTAIN_IDENTITY			1
#define PTP_V1_MM_CLOCK_IDENTITY			2
#define PTP_V1_MM_INITIALIZE_CLOCK			3
#define PTP_V1_MM_SET_SUBDOMAIN				4
#define PTP_V1_MM_CLEAR_DESIGNATED_PREFERRED_MASTER	5
#define PTP_V1_MM_SET_DESIGNATED_PREFERRED_MASTER	6
#define PTP_V1_MM_GET_DEFAULT_DATA_SET			7
#define PTP_V1_MM_DEFAULT_DATA_SET			8
#define PTP_V1_MM_UPDATE_DEFAULT_DATA_SET		9
#define PTP_V1_MM_GET_CURRENT_DATA_SET			10
#define PTP_V1_MM_CURRENT_DATA_SET			11
#define PTP_V1_MM_GET_PARENT_DATA_SET			12
#define PTP_V1_MM_PARENT_DATA_SET			13
#define PTP_V1_MM_GET_PORT_DATA_SET			14
#define PTP_V1_MM_PORT_DATA_SET				15
#define PTP_V1_MM_GET_GLOBAL_TIME_DATA_SET		16
#define PTP_V1_MM_GLOBAL_TIME_DATA_SET			17
#define PTP_V1_MM_UPDATE_GLOBAL_TIME_PROPERTIES		18
#define PTP_V1_MM_GOTO_FAULTY_STATE			19
#define PTP_V1_MM_GET_FOREIGN_DATA			20
#define PTP_V1_MM_FOREIGN_DATA				21
#define PTP_V1_MM_SET_SYNC_INTERVAL			22
#define PTP_V1_MM_DISABLE_PORT				23
#define PTP_V1_MM_ENABLE_PORT				24
#define PTP_V1_MM_DISABLE_BURST				25
#define PTP_V1_MM_ENABLE_BURST				26
#define PTP_V1_MM_SET_TIME				27

struct ptp_v1_domain_map_entry {
	STAILQ_ENTRY(ptp_v1_domain_map_entry)		entries;
	UInteger8					domainNumber;
	Octet						subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH];
};

struct ptp_v1_clockClass_map_entry {
	STAILQ_ENTRY(ptp_v1_clockClass_map_entry)	entries;
	UInteger8					clockClass_min;
	UInteger8					clockClass_max;
	UInteger8					stratum;
};

#define PTP_V1_PRIORITY_MAP_GM_PREFERRED		0x1
#define PTP_V1_PRIORITY_MAP_HAS_STRATUM			0x2 /* else use clockClass map */

struct ptp_v1_priority1_map_entry {
	STAILQ_ENTRY(ptp_v1_priority1_map_entry)	entries;
	uint8_t						flags;
	UInteger8					priority1_min;
	UInteger8					priority1_max;
	UInteger8					stratum;
};

struct ptp_v1_priority2_map_entry {
	STAILQ_ENTRY(ptp_v1_priority2_map_entry)	entries;
	UInteger8					priority2_min;
	UInteger8					priority2_max;
	UInteger8					grandmasterIsBoundaryClock;
};

/* last announce was generated locally */
#define PTP_V1_CONTEXT_FLAG_LAST_ANNO_LOCAL		0x01
/* handling PTPv1 SYNC as PTPv2 ANNOUNCE */
#define PTP_V1_CONTEXT_FLAG_SYNC_AS_ANNO		0x02

struct ptp_context_v1 {
	uint8_t							flags;
	uint8_t							domain_number;
	uint8_t							ts;
	uint8_t							reserved;
	uint16_t						epoch_number_rx;

	STAILQ_HEAD(domain, ptp_v1_domain_map_entry)		domain_map;
	STAILQ_HEAD(clock_class, ptp_v1_clockClass_map_entry)	clock_class_map;
	STAILQ_HEAD(priority1, ptp_v1_priority1_map_entry)	priority1_map;
	STAILQ_HEAD(priority2, ptp_v1_priority2_map_entry)	priority2_map;

	struct ptp_message					last_announce_tx;
	struct ptp_message					last_announce_rx;

	struct clock						*clock;
};

struct TimeRepresentation {
	UInteger32	seconds;
	Integer32	nanoseconds;
} PACKED;

struct ptp_header_v1 {
	UInteger16	versionPTP;
	UInteger16	versionNetwork;
	Octet		subdomain[PTP_V1_SUBDOMAIN_NAME_LENGTH];
	UInteger8	messageType;
	Enumeration8	sourceCommunicationTechnology;
	Octet		sourceUuid[PTP_V1_UUID_LENGTH];
	UInteger16	sourcePortId;
	UInteger16	sequenceId;
	Enumeration8	control;
	UInteger8	reserved1;
	Octet		flags[2];
	Octet		reserved2[4];
} PACKED;

struct sync_delay_req_msg_v1 {
	struct ptp_header_v1		hdr;
	struct TimeRepresentation	originTimestamp;
	UInteger16			epochNumber;
	Integer16			currentUTCOffset;
	UInteger8			reserved1;
	Enumeration8			grandmasterCommunicationTechnology;
	Octet				grandmasterClockUuid[PTP_V1_UUID_LENGTH];
	UInteger16			grandmasterPortId;
	UInteger16			grandmasterSequenceId;
	Octet				reserved2[3];
	UInteger8			grandmasterClockStratum;
	Octet				grandmasterClockIdentifier[PTP_V1_CODE_STRING_LENGTH];
	Octet				reserved3[2];
	Integer16			grandmasterClockVariance;
	Octet				reserved4;
	UInteger8			grandmasterPreferred;
	Octet				reserved5;
	UInteger8			grandmasterIsBoundaryClock;
	Octet				reserved6[3];
	Integer8			syncInterval;
	Octet				reserved7[2];
	Integer16			localClockVariance;
	Octet				reserved8[2];
	UInteger16			localStepsRemoved;
	Octet				reserved9[3];
	UInteger8			localClockStratum;
	Octet				localClockIdentifier[PTP_V1_CODE_STRING_LENGTH];
	Octet				reserved10;
	Enumeration8			parentCommunicationTechnology;
	Octet				parentUuid[PTP_V1_UUID_LENGTH];
	Octet				reserved11[2];
	UInteger16			parentPortId;
	Octet				reserved12[2];
	Integer16			estimatedMasterVariance;
	Integer32			estimatedMasterDrift;
	Octet				reserved13[3];
	UInteger8			utcReasonable; /* should be Boolean */
} PACKED;

struct follow_up_msg_v1 {
	struct ptp_header_v1		hdr;
	UInteger16			reserved;
	UInteger16			associatedSequenceId;
	struct TimeRepresentation	preciseOriginTimestamp;
} PACKED;

struct delay_resp_msg_v1 {
	struct ptp_header_v1		hdr;
	struct TimeRepresentation	delayReceiptTimestamp;
	Octet				reserved;
	Enumeration8			requestingSourceCommunicationTechnology;
	Octet				requestingSourceUuid[PTP_V1_UUID_LENGTH];
	UInteger16			requestingSourcePortId;
	UInteger16			requestingSourceSequenceId;
} PACKED;

struct management_msg_v1 {
	struct ptp_header_v1		hdr;
	Octet				reserved1;
	Enumeration8			targetCommunicationTechnology;
	Octet				targetUuid[PTP_V1_UUID_LENGTH];
	UInteger16			targetPortId;
	Integer16			startingBoundaryHops;
	Integer16			boundaryHops;
	Octet				reserved2;
	Enumeration8			managementMessageKey;
	Octet				reserved3[2];
	UInteger16			parameterLength;
	Octet				messageParameters[0];
} PACKED;

struct ptp_message_v1 {
	union {
		struct ptp_header_v1		hdr;
		struct sync_delay_req_msg_v1	sync;
		struct sync_delay_req_msg_v1	delay_req;
		struct follow_up_msg_v1		follow_up;
		struct delay_resp_msg_v1	delay_resp;
		struct management_msg_v1	management;
		struct message_data		data;
	} PACKED;
	size_t length; /* length in host byte order */
};

struct ptp_message;

/*
 * Management messages that are encoded in messageParameters
 */

struct clock_identity_v1 {
	Octet				reserved1[3];
	UInteger8			clockCommunicationTechnology;
	Octet				clockUuidField[PTP_V1_UUID_LENGTH];
	Octet				reserved2[4];
	UInteger16			clockPort;
	Octet				manufacturerIdentity[48];
} PACKED;

struct initialize_clock_v1 {
	Octet				reserved[2];
	UInteger16			initializationKey;
} PACKED;

struct set_subdomain_v1 {
	Octet				subdomainName[PTP_V1_SUBDOMAIN_NAME_LENGTH];
} PACKED;

struct default_ds_v1 {
	Octet				reserved1[3];
	UInteger8			clockCommunicationTechnology;
	Octet				clockUuidField[PTP_V1_UUID_LENGTH];
	Octet				reserved2[4];
	UInteger16			clockPort;
	Octet				reserved3[3];
	UInteger8			clockStratum;
	Octet				clockIdentifier[PTP_V1_CODE_STRING_LENGTH];
	Octet				reserved4[2];
	Integer16			clockVariance;
	Octet				reserved5[3];
	UInteger8			clockFollowupCapable;
	Octet				reserved6[3];
	UInteger8			preferred;
	Octet				reserved7[3];
	UInteger8			initializable;
	Octet				reserved8[3];
	UInteger8			externalTiming;
	Octet				reserved9[3];
	UInteger8			isBoundaryClock;
	Octet				reserved10[3];
	Integer8			syncInterval;
	Octet				subdomainName[PTP_V1_SUBDOMAIN_NAME_LENGTH];
	Octet				reserved11[2];
	UInteger16			numberPorts;
	Octet				reserved12[2];
	UInteger16			numberForeignRecords;
} PACKED;

struct update_default_ds_v1 {
	Octet				reserved1[3];
	UInteger8			clockStratum;
	Octet				clockIdentifier[PTP_V1_CODE_STRING_LENGTH];
	Octet				reserved2[2];
	Integer16			clockVariance;
	Octet				reserved3[3];
	UInteger8			preferred;
	Octet				reserved4[3];
	Integer8			syncInterval;
	Octet				subdomainName[PTP_V1_SUBDOMAIN_NAME_LENGTH];
} PACKED;

struct current_ds_v1 {
	Octet				reserved1[2];
	UInteger16			stepsRemoved;
	struct TimeRepresentation	offsetFromMaster;
	struct TimeRepresentation	oneWayDelay;
} PACKED;

struct parent_ds_v1 {
	Octet				reserved1[3];
	Enumeration8			parentCommunicationTechnology;
	Octet				parentUuid[PTP_V1_UUID_LENGTH];
	Octet				reserved2[4];
	UInteger16			parentPortId;
	Octet				reserved3[2];
	UInteger16			parentLastSyncSequenceNumber;
	Octet				reserved4[3];
	UInteger8			parentFollowupCapable;
	Octet				reserved5[3];
	UInteger8			parentExternalTiming;
	Octet				reserved6[2];
	Integer16			parentVariance;
	Octet				reserved7[3];
	UInteger8			parentStats;
	Octet				reserved8[2];
	Integer16			observedVariance;
	Integer32			observedDrift;
	Octet				reserved9[3];
	UInteger8			utcReasonable;
	UInteger8			reserved10[3];
	Enumeration8			grandmasterCommunicationTechnology;
	Octet				grandmasterUuid[PTP_V1_UUID_LENGTH];
	Octet				reserved11[4];
	UInteger16			grandmasterPortId;
	Octet				reserved12[3];
	UInteger8			grandmasterStratum;
	Octet				grandmasterIdentifier[PTP_V1_CODE_STRING_LENGTH];
	Octet				reserved13[2];
	Integer16			grandmasterVariance;
	Octet				reserved14[3];
	UInteger8			grandmasterPreferred;
	Octet				reserved15[3];
	UInteger8			grandmasterIsBoundaryClock;
	Octet				reserved16[2];
	UInteger16			grandmasterSequenceNumber;
} PACKED;

struct port_ds_v1 {
	Octet				reserved1[2];
	UInteger16			returnedPortNumber;
	Octet				reserved2[3];
	UInteger8			portState;
	Octet				reserved3[2];
	UInteger16			lastSyncEventSequenceNumber;
	Octet				reserved4[2];
	UInteger16			lastGeneralEventSequenceNumber;
	Octet				reserved5[3];
	Enumeration8			portCommunicationTechnology;
	Octet				portUuid[PTP_V1_UUID_LENGTH];
	Octet				reserved6[4];
	UInteger16			portId;
	Octet				reserved7[3];
	UInteger8			burstEnabled;
	Octet				reserved8;
	UInteger8			subdomainAddressOctets;
	UInteger8			eventPortAddressOctets;
	UInteger8			generalPortAddressOctets;
	Octet				subdomainAddress[4];
	Octet				reserved9[2];
	UInteger16			eventPortAddress;
	Octet				reserved10[2];
	UInteger16			generalPortAddress;
} PACKED;

struct global_time_properties_v1 {
	struct TimeRepresentation	localTime;
	Octet				reserved1[2];
	Integer16			currentUtcOffset;
	Octet				reserved2[3];
	UInteger8			leap59;
	Octet				reserved3[3];
	UInteger8			leap61;
	Octet				reserved4[2];
	UInteger16			epochNumber;
} PACKED;

struct update_global_time_properties_v1 {
	Octet				reserved1[2];
	Integer16			currentUtcOffset;
	Octet				reserved2[3];
	UInteger8			leap59;
	Octet				reserved3[3];
	UInteger8			leap61;
	Octet				reserved4[2];
	UInteger16			epochNumber;
} PACKED;

struct set_sync_interval_v1 {
	Octet				reserved[2];
	Integer16			syncInterval;
} PACKED;

struct set_time_v1 {
	struct TimeRepresentation	localTime;
} PACKED;

/*
 * Translate a PTPv2 message to a PTPv1 message per Clause 18 of
 * IEEE 1588-2002.
 * @param context	PTPv1 translation context
 * @param v2_msg	Validated PTPv2 message to be translated
 * @param v1_msg	The translated PTPv1 message
 * @return		Zero on success, or negative error code on failure
 */
int v2_message_to_v1(const struct ptp_context_v1 *context,
		     const struct ptp_message *v2_msg,
		     struct ptp_message_v1 *v1_msg);

/*
 * Validate and translate a PTPv1 message to a PTPv2 message using the
 * mappings in Clause 18 of IEEE 1588-2002.
 * @param context	PTPv1 translation context
 * @param v1_msg	PTPv1 message to be translated
 * @param v2_msg	The translated PTPv2 message
 * @return		Zero on success, or negative error code on failure
 */
int v1_message_to_v2(const struct ptp_context_v1 *context,
		     const struct ptp_message_v1 *v1_msg,
		     struct ptp_message *v2_msg);

/*
 * Map a PTPv2 domain number to a handle (IEEE 1588-2002 Annex C).
 * @param context	PTPv1 translation context
 * @param domainNumber	PTPv2 domain number
 * @param handle	PTPv1 handle
 * @return		Zero on success, or negative error code on failure
 */
int domainNumber_to_handle(const struct ptp_context_v1 *context,
			   UInteger8 domainNumber,
			   int *handle);

#endif
