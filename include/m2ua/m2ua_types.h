#ifndef m2ua_types_h
#define m2ua_types_h

/**
 * Types found in the M2UA RFC 3331
 */

#include <stdint.h>

#define M2UA_VERSION	1
#define M2UA_SPARE	0

enum {
	M2UA_CLS_MGMT,		/* Management (MGMT) Message [IUA/M2UA/M3UA/SUA] */
	M2UA_CLS_TRANS,		/* Transfer Messages [M3UA] */
	M2UA_CLS_SSNM,		/* SS7 Signalling Network Management (SSNM) Messages [M3UA/SUA] */
	M2UA_CLS_ASPSM,		/* ASP State Maintenance (ASPSM) Messages [IUA/M2UA/M3UA/SUA] */
	M2UA_CLS_ASPTM,		/* ASP Traffic Maintenance (ASPTM) Messages [IUA/M2UA/M3UA/SUA] */
	M2UA_CLS_QPTM,		/* Q.921/Q.931 Boundary Primitives Transport (QPTM) */
	M2UA_CLS_MAUP,		/* MTP2 User Adaptation (MAUP) Messages [M2UA] */
	M2UA_CLS_SUA_LESS,	/* Connectionless Messages [SUA] */
	M2UA_CLS_SUA_CONN,	/* Connection-Oriented Messages [SUA] */
	M2UA_CLS_RKM,		/* Routing Key Management (RKM) Messages (M3UA) */
 	M2UA_CLS_IIM,		/* Interface Identifier Management (IIM) Messages (M2UA) */
};

/**
 * MTP2 User Adaption = MAUP messages
 */
enum {
	M2UA_MAUP_RESERVED,	/* Reserved */
	M2UA_MAUP_DATA,		/* Data */
	M2UA_MAUP_EST_REQ,	/* Establish Request */
	M2UA_MAUP_EST_CON,	/* Establish Confirm */
	M2UA_MAUP_REL_REQ,	/* Release Request */
	M2UA_MAUP_REL_CON,	/* Release Confirm */
	M2UA_MAUP_REL_IND,	/* Release Indication */
	M2UA_MAUP_STATE_REQ,	/* State Request */
	M2UA_MAUP_STATE_CON,	/* State Confirm */
	M2UA_MAUP_STATE_IND,	/* State Indication */
	M2UA_MAUP_RETR_REQ,	/* Data Retrieval Request */
	M2UA_MAUP_D_RETR_CON,	/* Data Retrieval Confirm */
	M2UA_MAUP_D_RETR_IND,	/* Data Retrieval Indication */
	M2UA_MAUP_D_RETR_COMPL,	/* Data Retrieval Complete Indication */
	M2UA_MAUP_CONG_IND,	/* Congestion Indication */
	M2UA_MAUP_DATA_ACK,	/* Data Acknowledge */
};

/**
 * Application Server Process State Maintaenance (ASPSM) messages
 */
enum {
	M2UA_ASPSM_RESERVED,	/* Reserved */
	M2UA_ASPSM_UP,		/* ASP Up (UP) */
	M2UA_ASPSM_DOWN,	/* ASP Down (DOWN) */
	M2UA_ASPSM_BEAT,	/* Heartbeat (BEAT) */
	M2UA_ASPSM_UP_ACK,	/* ASP Up Ack (UP ACK) */
	M2UA_ASPSM_DOWN_ACK,	/* ASP Down Ack (DOWN ACK) */
	M2UA_ASPSM_BEAT_ACK,	/* Heartbeat Ack (BEAT ACK) */
};

/**
 * Application Server Process Traffic Maintaenance (ASPTM) messages.
 */
enum {
	M2UA_ASPTM_RESERVED,	/* Reserved */
	M2UA_ASPTM_ACTIV,	/* ASP Active (ACTIVE) */
	M2UA_ASPTM_INACTIV,	/* ASP Inactive (INACTIVE) */
	M2UA_ASPTM_ACTIV_ACK,	/* ASP Active Ack (ACTIVE ACK) */
	M2uA_ASPTM_INACTIV_ACK,	/* ASP Inactive Ack (INACTIVE ACK) */
};

/**
 * Management (MGMT) messages
 */
enum {
	M2UA_MGMT_ERROR,	/* Error (ERR) */
	M2UA_MGMT_NTFY,		/* Notify (NTFY) */
};

/**
 * Interface Identifier Management (IIM) Messages
 */
enum {
	M2UA_IIM_RESERVED,	/* Reserved */
	M2UA_IIM_REG_REQ,	/* Registration Request (REG REQ) */
	M2UA_IIM_REG_RSP,	/* Registration Response (REG RSP) */
	M2UA_IIM_DEREG_REQ,	/* Deregistration Request (DEREG REQ) */
	M2UA_IIM_DEREG_RSP,	/* Deregistration Response (DEREG RSP) */
};

struct m2ua_common_hdr {
	uint8_t version;
	uint8_t spare;
	uint8_t msg_class;
	uint8_t msg_type;
	uint32_t msg_length;
	uint8_t data[0];
} __attribute__((packed));


/**
 * Common tag values used by all user adaption layers
 */
enum {
	MUA_TAG_RESERVED,	/* Reserved */
	MUA_TAG_IDENT_INT,	/* Interface Identifier (Integer) */
	MUA_TAG_UNUSED1,	/* Unused */
	MUA_TAG_IDENT_TEXT,	/* Interface Identifier (Text) */
	MUA_TAG_INFO,		/* Info String */
	MUA_TAG_UNUSED2,	/* Unused */
	MUA_TAG_UNUSED3,	/* Unused */
	MUA_TAG_DIAG_INF,	/* Diagnostic Information */
	MUA_TAG_IDENT_RANGE,	/* Interface Identifier (Integer Range) */
	MUA_TAG_BEAT_DATA,	/* Heartbeat Data */
	MUA_TAG_UNUSED4,	/* Unused */
	MUA_TAG_TRA_MODE,	/* Traffic Mode Type */
	MUA_TAG_ERR_CODE,	/* Error Code */
	MUA_TAG_STATUS,	/* Status Type/Information */
	MUA_TAG_UNUSED5,	/* Unused */
	MUA_TAG_UNUSED6,	/* Unused */
	MUA_TAG_UNUSED7,	/* Unused */
	MUA_TAG_ASP_IDENT,	/* ASP Identifier */
	MUA_TAG_UNUSED8,	/* Unused */
	MUA_TAG_CORREL_ID,	/* Correlation Id */
};

/**
 * Tag Values for M2UA
 */
enum {
	__m2ua_tag_start	= 767,

	M2UA_TAG_DATA,		/* Protocol Data 1 */
	M2UA_TAG_DATA_TTC,	/* Protocol Data 2 (TTC) */
	M2UA_TAG_STATE_REQ,	/* State Request */
	M2UA_TAG_STATE_EVENT,	/* State Event */
	M2UA_TAG_CONG_STATUS,	/* Congestion Status */
	M2UA_TAG_DISC_STATUS,	/* Discard Status */
	M2UA_TAG_ACTION,	/* Action */
	M2UA_TAG_SEQ_NO,	/* Sequence Number */
	M2UA_TAG_RETR_RES,	/* Retrieval Result */
	M2UA_TAG_LNK_KEY,	/* Link Key */
	M2UA_TAG_L_LNK_KEY_ID,	/* Local-LK-Identifier */
	M2UA_TAG_SDT,		/* Signalling Data Terminal (SDT) Identifier */
	M2UA_TAG_SDL,		/* Signalling Data Link (SDL) Identifier */
	M2UA_TAG_REG_RES,	/* Registration Result */
	M2UA_TAG_RES_STATUS,	/* Registration Status */
	M2UA_TAG_DEREG_RES,	/* De-Registration Result */
	M2UA_TAG_DEREG_STATIS,	/* De-Registration Status */
};

struct m2ua_parameter_hdr {
	uint16_t tag;
	uint16_t len;
	uint8_t data[0];
} __attribute__((packed));



#endif
