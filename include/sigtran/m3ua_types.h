#pragma once

/**
 * Types found in the M3UA RFC 4666
 */

#include <stdint.h>


#define M3UA_VERSION	1

enum {
	M3UA_CLS_MGMT,		/* Management (MGMT) Message [IUA/M2UA/M3UA/SUA] */
	M3UA_CLS_TRANS,		/* Transfer Messages [M3UA] */
	M3UA_CLS_SSNM,		/* SS7 Signalling Network Management (SSNM) Messages [M3UA/SUA] */
	M3UA_CLS_ASPSM,		/* ASP State Maintenance (ASPSM) Messages [IUA/M2UA/M3UA/SUA] */
	M3UA_CLS_ASPTM,		/* ASP Traffic Maintenance (ASPTM) Messages [IUA/M2UA/M3UA/SUA] */
	M3UA_CLS_RESERVED1,	/* Reserved for Other SIGTRAN Adaptation Layers */
	M3UA_CLS_RESERVED2,	/* Reserved for Other SIGTRAN Adaptation Layers */
	M3UA_CLS_RESERVED3,	/* Reserved for Other SIGTRAN Adaptation Layers */
	M3UA_CLS_RESERVED4,	/* Reserved for Other SIGTRAN Adaptation Layers */
	M3UA_CLS_RKM,		/* Routing Key Management (RKM) Messages (M3UA) */
};

/**
 * Management (MGMT) messages
 */
enum {
	M3UA_MGMT_ERROR,	/* Error (ERR) */
	M3UA_MGMT_NTFY,		/* Notify (NTFY) */
};

/**
 * Transfer Messages
 */
enum {
	M3UA_TRANS_RESERVED,	/* Reserved */
	M3UA_TRANS_DATA,	/* Payload Data (DATA) */
};

/**
 * SS7 Signalling Network Management (SSNM) Messages
 */
enum {
	M3UA_SSNM_RESERVED,	/* Reserved */
	M3UA_SSNM_DUNA,		/* Destination Unavailable (DUNA) */
	M3UA_SSNM_DAVA,		/* Destination Available (DAVA) */
	M3UA_SSNM_DAUD,		/* Destination State Audit (DAUD) */
	M3UA_SSNM_SCON,		/* Signalling Congestion (SCON) */
	M3UA_SSNM_DUPU,		/* Destination User Part Unavailable (DUPU) */
	M3UA_SSNM_DRST,		/* Destination Restricted (DRST) */
};

/**
 * Application Server Process State Maintaenance (ASPSM) messages
 */
enum {
	M3UA_ASPSM_RESERVED,	/* Reserved */
	M3UA_ASPSM_UP,		/* ASP Up (UP) */
	M3UA_ASPSM_DOWN,	/* ASP Down (DOWN) */
	M3UA_ASPSM_BEAT,	/* Heartbeat (BEAT) */
	M3UA_ASPSM_UP_ACK,	/* ASP Up Ack (UP ACK) */
	M3UA_ASPSM_DOWN_ACK,	/* ASP Down Ack (DOWN ACK) */
	M3UA_ASPSM_BEAT_ACK,	/* Heartbeat Ack (BEAT ACK) */
};

/**
 * Application Server Process Traffic Maintaenance (ASPTM) messages.
 */
enum {
	M3UA_ASPTM_RESERVED,	/* Reserved */
	M3UA_ASPTM_ACTIV,	/* ASP Active (ACTIVE) */
	M3UA_ASPTM_INACTIV,	/* ASP Inactive (INACTIVE) */
	M3UA_ASPTM_ACTIV_ACK,	/* ASP Active Ack (ACTIVE ACK) */
	M3UA_ASPTM_INACTIV_ACK,	/* ASP Inactive Ack (INACTIVE ACK) */
};

/**
 * Routing Key Management (RKM) Messages
 */
enum {
	M3UA_RKM_RESERVED,	/* Reserved */
	M3UA_RKM_REG_REQ,	/* Registration Request (REG REQ) */
	M3UA_RKM_REG_RSP,	/* Registration Response (REG RSP) */
	M3UA_RKM_DEREG_REQ,	/* Deregistration Request (DEREG REQ) */
	M3UA_RKM_DEREG_RSP,	/* Deregistration Response (DEREG RSP) */
};

/**
 * Tag Values for M3UA
 */
enum {
	M3UA_TAG_NET_APPEAR = 0x0200,	/* Network Appearance */
	M3UA_TAG_RESERVED1,		/* Reserved */
	M3UA_TAG_RESERVED2,		/* Reserved */
	M3UA_TAG_RESERVED3,		/* Reserved */
	M3UA_TAG_USER_CAUSE,		/* User/Cause */
	M3UA_TAG_CONGEST_IND,		/* Congestion Indications */
	M3UA_TAG_CONCERN_DEST,		/* Concerned Destination */
	M3UA_TAG_ROUTING_KEY,		/* Routing Key */
	M3UA_TAG_REG_RESULT,		/* Registration Result */
	M3UA_TAG_DEREG_RESULT,		/* Deregistration Result */
	M3UA_TAG_LOCAL_ROUT_KEY_IDENT,	/* Local Routing Key Identifier */
	M3UA_TAG_DEST_PC,		/* Destination Point Code */
	M3UA_TAG_SERV_IND,		/* Service Indicators */
	M3UA_TAG_RESERVED4,		/* Reserved */
	M3UA_TAG_ORIG_PC_LIST,		/* Originating Point Code List */
	M3UA_TAG_RESERVED5,		/* Reserved */
	M3UA_TAG_PROTO_DATA,		/* Protocol Data */
	M3UA_TAG_RESERVED6,		/* Reserved */
	M3UA_TAG_REG_STATUS,		/* Registration Status */
	M3UA_TAG_DEREG_STATUS,		/* Deregistration Status */
};


/**
 * Protocol data for transport messages. This is
 * replacing the MTP L3 header
 */
struct m3ua_protocol_data {
        uint32_t        opc;
        uint32_t        dpc;
        uint8_t         si;
        uint8_t         ni;
        uint8_t         mp;
        uint8_t         sls;
        uint8_t         data[0];
} __attribute__((packed));
