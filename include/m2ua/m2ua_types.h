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


/**
 * 3.3.1.5 State Request
 */
enum {
	M2UA_STATUS_LPO_SET,		/* Request local processor outage */
	M2UA_STATUS_LPO_CLEAR,		/* Request local processor outage recovered */
	M2UA_STATUS_EMER_SET,		/* Request emergency alignment */
	M2UA_STATUS_EMER_CLEAR, 	/* Request normal alignment (cancel emergency) */
	M2UA_STATUS_FLUSH_BUFFERS,	/* Flush or clear receive, transmit and retransmit queues */
	M2UA_STATUS_CONTINUE,		/* Continue or Resume */
	M2UA_STATUS_CLEAR_RTB,		/* Clear the retransmit queue */
	M2UA_STATUS_AUDIT,		/* Audit state of link */
	M2UA_STATUS_CONG_CLEAR,		/* Congestion cleared */
	M2UA_STATUS_CONG_ACCEPT,	/* Congestion accept */
	M2UA_STATUS_CONG_DISCARD,	/* Congestion discard */
};

/**
 * 3.3.1.7 State Indication
 */
enum {
	__m2ua_event_dummy,
	M2UA_EVENT_RPO_ENTER,		/* Remote entered processor outage */
	M2UA_EVENT_RPO_EXIT,		/* Remote exited processor outage */
	M2UA_EVENT_LPO_ENTER,		/* Link entered processor outage */
	M2UA_EVENT_LPO_EXIT,		/* Link exited processor outage */
};

/**
 * 3.3.1.8 Congestion Indication
 */
enum {
	M2UA_LEVEL_NONE,		/* No congestion */
	M2UA_LEVEL_1,			/* Congestion Level 1 */
	M2UA_LEVEL_2,			/* Congestion Level 2 */
	M2UA_LEVEL_3,			/* Congestion Level 3 */
};

/**
 * 3.3.1.9 Retrieval Request
 */
enum {
	M2UA_ACTION_RTRV_BSN,		/* Retrieve the backward sequence number */
	M2UA_ACTION_RTRV_MSGS,		/* Retrieve the PDUs from the transmit and retransmit queues. */
};

/**
 * 3.3.1.10 Retrieval Confirm
 */
enum {
	M2UA_RESULT_SUCCESS,		/* Action successful */
	M2UA_RESULT_FAILURE,		/* Action failed */
};

/**
 * 3.3.2.7 ASP Active (ASPAC)
 */
enum {
	M2UA_TRA_OVERRIDE	= 1,	/* Override */
	M2UA_TRA_LOAD_SHARE	= 2,	/* Load-share */
	M2UA_TRA_BROADCAST	= 3,	/* Broadcast */
};

/**
 * 3.3.3.1 Error (ERR)
 */
enum {
	__m2ua_err_unused,
	M2UA_ERR_INV_VER,		/* Invalid Version */
	M2UA_ERR_INV_INT_IDENT,		/* Invalid Interface Identifier */
	M2UA_ERR_UNS_MSG_CLASS,		/* Unsupported Message Class */
	M2UA_ERR_UNS_MSG_TYPE,		/* Unsupported Message Type */
	M2UA_ERR_UNS_TRA_MODE,		/* Unsupported Traffic Handling Mode */
	M2UA_ERR_UNE_MSG,		/* Unexpected Message */
	M2UA_ERR_PROTO_ERROR,		/* Protocol Error */
	M2UA_ERR_UNS_INT_IDENT_T,	/* Unsupported Interface Identifier Type */
	M2UA_ERR_INV_STR_IDENT,		/* Invalid Stream Identifier */
	M2UA_ERR_UNUSED1,		/* Unused in M2UA */
	M2UA_ERR_UNUSED2,		/* Unused in M2UA */
	M2UA_ERR_UNUSED3,		/* Unused in M2UA */
	M2UA_ERR_REFUSED,		/* Refused - Management Blocking */
	M2UA_ERR_ASP_IDENT_REQ,		/* ASP Identifier Required */
	M2UA_ERR_INV_ASP_IDENT,		/* Invalid ASP Identifier */
	M2UA_ERR_ASP_ACT_FOR_IDENT,	/* ASP Active for Interface Identifier(s) */
	M2UA_ERR_INV_PARAM_VAL,		/* Invalid Parameter Value */
	M2UA_ERR_PARAM_FIELD_ERR,	/* Parameter Field Error */
	M2UA_ERR_UNEXP_PARAM,		/* Unexpected Parameter */
	M2UA_ERR_UNUSED4,		/* Unused in M2UA */
	M2UA_ERR_UNUSED5,		/* Unused in M2UA */
	M2UA_ERR_MISSING_PARAM,		/* Missing Parameter */
};

/**
 * 3.3.3.2 Notify (NTFY)
 */
enum {
	M2UA_STP_AS_STATE_CHG 	= 1,	/* Application Server state change (AS_State_Change) */
	M2UA_STP_OTHER		= 2,	/* Other */
};

enum {
	/* this is for M2UA_STP_AS_STATE_CHG */
	M2UA_STP_AS_INACTIVE		= 2,	/* Application Server Inactive (AS_Inactive) */
	M2UA_STP_AS_ACTIVE		= 3,	/* Application Server Active (AS_Active) */
	M2UA_STP_AS_PENDING		= 4,	/* Application Server Pending (AS_Pending) */

	/* this is for the other */
	M2UA_STP_O_INSUFF_ASP_RES	= 1,	/* Insufficient ASP resources active in AS */
	M2UA_STP_O_ALT_ASP_ACTIVR	= 2,	/* Alternate ASP Active */
	M2UA_STP_O_ASP_FAILURE		= 3,	/* ASP Failure */
};

/**
 * 3.3.4.3 Registration Response (REG RSP)
 */
enum {
	M2UA_REG_SUCC,				/* Successfully Registered */
	M2UA_REG_ERR_UNK,			/* Error - Unknown */
	M2UA_REG_ERR_INV_SDLI,			/* Error - Invalid SDLI */
	M2UA_REG_ERR_INV_SDTI,			/* Error - Invalid SDTI */
	M2UA_REG_ERR_INV_LNK_KEY,		/* Error - Invalid Link Key */
	M2UA_REG_ERR_PERM_DENIED,		/* Error - Permission Denied */
	M2UA_REG_ERR_OVERLAP_KEY,		/* Error - Overlapping (Non-unique) Link Key */
	M2UA_REG_ERR_LNK_KEY_NOT_PROV,		/* Error - Link Key not Provisioned */
	M2UA_REG_ERR_INSUFF_RES,		/* Error - Insufficient Resources */
};

/**
 * 3.3.4.4 De-Registration Response (DEREG RSP)
 */
enum {
	M2UA_DEREG_SUCC,			/* Successfully De-registered */
	M2UA_DEREG_ERR_UNK,			/* Error - Unknown */
	M2UA_DEREG_ERR_INV_IDENT,		/* Error - Invalid Interface Identifier */
	M2UA_DEREG_ERR_PERM_DENIED,		/* Error - Permission Denied */
	M2UA_DEREG_ERR_NOT_REG,			/* Error - Not Registered */
};

#endif
