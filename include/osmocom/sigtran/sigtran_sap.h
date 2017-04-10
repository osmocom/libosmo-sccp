#pragma once
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/osmo_ss7.h>


enum osmo_sigtran_sap {
	SCCP_SAP_USER	= _SAP_SS7_BASE,
	/* xUA Layer Manager */
	XUA_SAP_LM,
	MTP_SAP_USER,
};

enum osmo_xlm_prim_type {
	OSMO_XLM_PRIM_M_SCTP_ESTABLISH,
	OSMO_XLM_PRIM_M_SCTP_RELEASE,
	OSMO_XLM_PRIM_M_SCTP_RESTART,
	OSMO_XLM_PRIM_M_SCTP_STATUS,
	OSMO_XLM_PRIM_M_ASP_STATUS,
	OSMO_XLM_PRIM_M_AS_STATUS,
	OSMO_XLM_PRIM_M_NOTIFY,
	OSMO_XLM_PRIM_M_ERROR,
	OSMO_XLM_PRIM_M_ASP_UP,
	OSMO_XLM_PRIM_M_ASP_DOWN,
	OSMO_XLM_PRIM_M_ASP_ACTIVE,
	OSMO_XLM_PRIM_M_ASP_INACTIVE,
	OSMO_XLM_PRIM_M_AS_ACTIVE,
	OSMO_XLM_PRIM_M_AS_INACTIVE,
	OSMO_XLM_PRIM_M_AS_DOWN,
	/* optional as per spec, not implemented yet */
	OSMO_XLM_PRIM_M_RK_REG,
	OSMO_XLM_PRIM_M_RK_DEREG,
};

#define NOTIFY_PAR_P_ASP_ID	(1 << 0)
#define NOTIFY_PAR_P_ROUTE_CTX	(1 << 1)

struct osmo_xlm_prim_notify {
	uint32_t presence;
	uint16_t status_type;
	uint16_t status_info;
	uint32_t asp_id;
	uint32_t route_ctx;
	char *info_string;
};

struct osmo_xlm_prim_error {
	uint32_t code;
};

struct osmo_xlm_prim_rk_reg {
	/* routing key */
	struct osmo_ss7_routing_key key;
	enum osmo_ss7_as_traffic_mode traf_mode;
};

struct osmo_xlm_prim_rk_dereg {
	uint32_t route_ctx;
};

struct osmo_xlm_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_xlm_prim_notify notify;
		struct osmo_xlm_prim_error error;
	} u;
};

#define msgb_xlm_prim(msg) ((struct osmo_xlm_prim *)(msg)->l1h)

char *osmo_xlm_prim_name(struct osmo_prim_hdr *oph);
