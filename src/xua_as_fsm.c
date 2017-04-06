/* SCCP M3UA / SUA AS osmo_fsm according to RFC3868 4.3.1 / RFC4666 4.3.2 */
/* (C) Copyright 2017 by Harald Welte <laforge@gnumonks.org>
 * 
 * All Rights reserved.
 *
 * Based on Erlang implementation xua_as_fsm.erl in osmo-ss7.git
 */

#include <string.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>
#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"
#include "xua_internal.h"

static struct msgb *encode_notify(const struct m3ua_notify_params *npar)
{
	struct xua_msg *xua = m3ua_encode_notify(npar);
	struct msgb *msg = xua_to_msg(M3UA_VERSION, xua);
	xua_msg_free(xua);
	return msg;
}

static int asp_notify_all_as(struct osmo_ss7_as *as, struct m3ua_notify_params *npar)
{
	struct msgb *msg;
	unsigned int i, sent = 0;

	/* iterate over all non-DOWN ASPs and send them the message */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];

		if (!asp)
			continue;

		if (!asp->fi || asp->fi->state == XUA_ASP_S_DOWN)
			continue;

		/* Optional: ASP Identifier (if sent in ASP-UP) */
		if (asp->asp_id_present) {
			npar->presence |= NOTIFY_PAR_P_ASP_ID;
			npar->asp_id = asp->asp_id;
		} else
			npar->presence &= ~NOTIFY_PAR_P_ASP_ID;

		/* TODO: Optional Routing Context */

		msg = encode_notify(npar);
		osmo_ss7_asp_send(asp, msg);
		sent++;
	}

	return sent;
}


/***********************************************************************
 * Actual FSM
 ***********************************************************************/

#define S(x)	(1 << (x))

enum xua_as_state {
	XUA_AS_S_DOWN,
	XUA_AS_S_INACTIVE,
	XUA_AS_S_ACTIVE,
	XUA_AS_S_PENDING,
};

static const struct value_string xua_as_event_names[] = {
	{ XUA_ASPAS_ASP_INACTIVE_IND, 	"ASPAS-ASP_INACTIVE.ind" },
	{ XUA_ASPAS_ASP_DOWN_IND,	"ASPAS-ASP_DOWN.ind" },
	{ XUA_ASPAS_ASP_ACTIVE_IND,	"ASPAS-ASP_ACTIVE.ind" },
	{ 0, NULL }
};

struct xua_as_fsm_priv {
	struct osmo_ss7_as *as;
};

/* is any other ASP in this AS in state != DOWN? */
static bool check_any_other_asp_not_down(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp_cmp)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;

		if (asp_cmp == asp)
			continue;

		if (asp->fi && asp->fi->state != XUA_ASP_S_DOWN)
			return true;
	}

	return false;
}

/* is any other ASP in this AS in state ACTIVE? */
static bool check_any_other_asp_in_active(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp_cmp)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;

		if (asp_cmp == asp)
			continue;

		if (asp->fi && asp->fi->state == XUA_ASP_S_ACTIVE)
			return true;
	}

	return false;
}


static void xua_as_fsm_down(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case XUA_ASPAS_ASP_INACTIVE_IND:
		/* one ASP transitions into ASP-INACTIVE */
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_INACTIVE, 0, 0);
		break;
	case XUA_ASPAS_ASP_DOWN_IND:
		/* ignore */
		break;
	}
}

/* onenter call-back responsible of transmitting NTFY to all ASPs in
 * case of AS state changes */
static void xua_as_fsm_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_as *as = xafp->as;
	struct m3ua_notify_params npar = {
		.status_type = M3UA_NOTIFY_T_STATCHG,
	};

	switch (fi->state) {
	case XUA_AS_S_INACTIVE:
		npar.status_info = M3UA_NOTIFY_I_AS_INACT;
		break;
	case XUA_AS_S_ACTIVE:
		npar.status_info = M3UA_NOTIFY_I_AS_ACT;
		break;
	case XUA_AS_S_PENDING:
		npar.status_info = M3UA_NOTIFY_I_AS_PEND;
		break;
	default:
		return;
	}

	/* Add the routing context, if it is configured */
	if (as->cfg.routing_key.context) {
		npar.presence |= NOTIFY_PAR_P_ROUTE_CTX;
		npar.route_ctx = as->cfg.routing_key.context;
	}

	/* TODO: ASP-Id of ASP triggering this state change */

	asp_notify_all_as(xafp->as, &npar);
};

static void xua_as_fsm_inactive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_asp *asp = data;

	switch (event) {
	case XUA_ASPAS_ASP_DOWN_IND:
		/* one ASP transitions into ASP-DOWN */
		if (check_any_other_asp_not_down(xafp->as, asp)) {
			/* ignore, we stay AS_INACTIVE */
		} else
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_DOWN, 0, 0);
		break;
	case XUA_ASPAS_ASP_ACTIVE_IND:
		/* one ASP transitions into ASP-ACTIVE */
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_ACTIVE, 0, 0);
		break;
	case XUA_ASPAS_ASP_INACTIVE_IND:
		/* ignore */
		break;
	}
}

static void xua_as_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_asp *asp = data;

	switch (event) {
	case XUA_ASPAS_ASP_DOWN_IND:
	case XUA_ASPAS_ASP_INACTIVE_IND:
		if (check_any_other_asp_in_active(xafp->as, asp)) {
			/* ignore, we stay AS_ACTIVE */
		} else {
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_PENDING, 0, 0);
			/* FIXME: Start T(r) */
			/* FIXME: Queue all signalling messages until
			 * recovery or T(r) expiry */
		}
		break;
	case XUA_ASPAS_ASP_ACTIVE_IND:
		/* ignore */
		break;
	}
}

static void xua_as_fsm_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case XUA_ASPAS_ASP_ACTIVE_IND:
		/* one ASP transitions into ASP-ACTIVE */
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_ACTIVE, 0, 0);
		break;
	case XUA_ASPAS_ASP_INACTIVE_IND:
		/* ignore */
		break;
	case XUA_ASPAS_ASP_DOWN_IND:
		/* ignore */
		break;
	}
}

static const struct osmo_fsm_state xua_as_fsm_states[] = {
	[XUA_AS_S_DOWN] = {
		.in_event_mask = S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_DOWN_IND),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE),
		.name = "AS_DOWN",
		.action = xua_as_fsm_down,
	},
	[XUA_AS_S_INACTIVE] = {
		.in_event_mask = S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND) |
				 S(XUA_ASPAS_ASP_INACTIVE_IND),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE) |
				  S(XUA_AS_S_ACTIVE),
		.name = "AS_INACTIVE",
		.action = xua_as_fsm_inactive,
		.onenter = xua_as_fsm_onenter,
	},
	[XUA_AS_S_ACTIVE] = {
		.in_event_mask = S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND),
		.out_state_mask = S(XUA_AS_S_ACTIVE) |
				  S(XUA_AS_S_PENDING),
		.name = "AS_ACTIVE",
		.action = xua_as_fsm_active,
		.onenter = xua_as_fsm_onenter,
	},
	[XUA_AS_S_PENDING] = {
		.in_event_mask = S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE) |
				  S(XUA_AS_S_ACTIVE) |
				  S(XUA_AS_S_PENDING),
		.name = "AS_PENDING",
		.action = xua_as_fsm_pending,
		.onenter = xua_as_fsm_onenter,
	},
};

struct osmo_fsm xua_as_fsm = {
	.name = "XUA_AS",
	.states = xua_as_fsm_states,
	.num_states = ARRAY_SIZE(xua_as_fsm_states),
	.log_subsys = DLSS7,
	.event_names = xua_as_event_names,
};

/*! \brief Start an AS FSM for a given Application Server
 *  \param[in] as Application Server for which to start the AS FSM
 *  \param[in] log_level Logging level for logging of this FSM
 *  \returns FSM instance in case of success; NULL in case of error */
struct osmo_fsm_inst *xua_as_fsm_start(struct osmo_ss7_as *as, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct xua_as_fsm_priv *xafp;

	fi = osmo_fsm_inst_alloc(&xua_as_fsm, as, NULL, log_level, as->cfg.name);

	xafp = talloc_zero(fi, struct xua_as_fsm_priv);
	if (!xafp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	xafp->as = as;

	fi->priv = xafp;

	return fi;
}
