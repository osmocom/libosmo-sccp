#pragma once

#include <stdint.h>

/**
 * Common tag values used by all user adaption layers
 */
enum {
	MUA_TAG_RESERVED,	/* Reserved */
	MUA_TAG_IDENT_INT,	/* Interface Identifier (Integer) (M2UA) */
	MUA_TAG_UNUSED1,	/* Unused */
	MUA_TAG_IDENT_TEXT,	/* Interface Identifier (Text) (M2UA) */
	MUA_TAG_INFO,		/* Info String */
	MUA_TAG_UNUSED2,	/* Unused */
	MUA_TAG_ROUTING_CTX,	/* Routing Context (M3UA) */
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
	MUA_TAG_AFF_PC,		/* Affected Point Code (M3UA) */
	MUA_TAG_CORREL_ID,	/* Correlation Id */
};

struct xua_common_hdr {
	uint8_t version;
	uint8_t spare;
	uint8_t msg_class;
	uint8_t msg_type;
	uint32_t msg_length;
	uint8_t data[0];
} __attribute__((packed));


struct xua_parameter_hdr {
	uint16_t tag;
	uint16_t len;
	uint8_t data[0];
} __attribute__((packed));
