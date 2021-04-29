/* SCCP M3UA / SUA AS osmo_fsm according to RFC3868 4.3.1 / RFC4666 4.3.2 */
/* (C) Copyright 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
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

static struct msgb *encode_notify(const struct osmo_xlm_prim_notify *npar)
{
	struct xua_msg *xua = m3ua_encode_notify(npar);
	struct msgb *msg = xua_to_msg(M3UA_VERSION, xua);
	xua_msg_free(xua);
	return msg;
}

static int as_notify_all_asp(struct osmo_ss7_as *as, struct osmo_xlm_prim_notify *npar)
{
	struct msgb *msg;
	unsigned int i, sent = 0;

	/* we don't send notify to IPA peers! */
	if (as->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
		return 0;

	/* iterate over all non-DOWN ASPs and send them the message */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];

		if (!asp)
			continue;

		/* NOTIFY are only sent by SG or IPSP role */
		if (asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP)
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

/* determine which role (SG/ASP/IPSP) we operate in */
static int get_local_role(struct osmo_ss7_as *as)
{
	unsigned int i;

	/* this is a bit tricky. "osmo_ss7_as" has no configuation of a role,
	 * only the ASPs have.  As they all must be of the same role, let's simply
	 * find the first one and return its role */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];

		if (!asp)
			continue;

		return asp->cfg.role;
	}
	/* we don't have any ASPs in this AS? Strange */
	return -1;
}

static struct osmo_ss7_asp *xua_as_select_asp_override(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	/* FIXME: proper selection of the ASP based on the SLS! */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp))
			break;
	}
	return asp;
}

static struct osmo_ss7_asp *xua_as_select_asp_roundrobin(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	unsigned int first_idx;

	first_idx = (as->cfg.last_asp_idx_sent + 1) % ARRAY_SIZE(as->cfg.asps);
	i = first_idx;
	do {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp))
			break;
		i = (i + 1) % ARRAY_SIZE(as->cfg.asps);
	} while (i != first_idx);
	as->cfg.last_asp_idx_sent = i;

	return asp;
}

int xua_as_transmit_msg_broadcast(struct osmo_ss7_as *as, struct msgb *msg)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	struct msgb *msg_cpy;
	bool sent = false;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp || !osmo_ss7_asp_active(asp))
			continue;
		msg_cpy = msgb_copy(msg, "xua_bcast_cpy");
		if (osmo_ss7_asp_send(asp, msg_cpy) == 0)
			sent = true;
	}

	msgb_free(msg);
	return sent ? 0 : -1;
}

/* actually transmit a message through this AS */
int xua_as_transmit_msg(struct osmo_ss7_as *as, struct msgb *msg)
{
	struct osmo_ss7_asp *asp = NULL;

	switch (as->cfg.mode) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
		asp = xua_as_select_asp_override(as);
		break;
	case OSMO_SS7_AS_TMOD_LOADSHARE:
	case OSMO_SS7_AS_TMOD_ROUNDROBIN:
		asp = xua_as_select_asp_roundrobin(as);
		break;
	case OSMO_SS7_AS_TMOD_BCAST:
		return xua_as_transmit_msg_broadcast(as, msg);
	case _NUM_OSMO_SS7_ASP_TMOD:
		OSMO_ASSERT(false);
	}

	if (!asp) {
		LOGPFSM(as->fi, "No ASP in AS, dropping message\n");
		msgb_free(msg);
		return -1;
	}

	return osmo_ss7_asp_send(asp, msg);
}


/***********************************************************************
 * Actual FSM
 ***********************************************************************/

#define S(x)	(1 << (x))

#define MSEC_TO_S_US(x)		(x/1000), ((x%1000)*10)

static const struct value_string xua_as_event_names[] = {
	{ XUA_ASPAS_ASP_INACTIVE_IND, 	"ASPAS-ASP_INACTIVE.ind" },
	{ XUA_ASPAS_ASP_DOWN_IND,	"ASPAS-ASP_DOWN.ind" },
	{ XUA_ASPAS_ASP_ACTIVE_IND,	"ASPAS-ASP_ACTIVE.ind" },
	{ XUA_AS_E_RECOVERY_EXPD,	"AS-T_REC_EXPD.ind" },
	{ XUA_AS_E_TRANSFER_REQ,	"AS-TRANSFER.req" },
	{ 0, NULL }
};

struct xua_as_fsm_priv {
	struct osmo_ss7_as *as;
	struct {
		struct osmo_timer_list t_r;
		struct llist_head queued_msgs;
	} recovery;
	bool ipa_route_created;
};

/* is the given AS one with a single ASP of IPA type? */
static bool is_single_ipa_asp(struct osmo_ss7_as *as)
{
	unsigned int asp_count = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;
		asp_count++;
		if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA)
			return false;
	}
	if (asp_count == 1)
		return true;
	return false;
}

static void ipa_add_route(struct osmo_fsm_inst *fi)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_as *as = xafp->as;
	struct osmo_ss7_instance *inst = as->inst;

	if (osmo_ss7_route_find_dpc_mask(inst->rtable_system, as->cfg.routing_key.pc, 0xffffff))
		return;

	/* As opposed to M3UA, there is no RKM and we have to implicitly
	 * automatically add a route once an IPA connection has come up */
	if (osmo_ss7_route_create(inst->rtable_system, as->cfg.routing_key.pc, 0xffffff, as->cfg.name))
		xafp->ipa_route_created = true;
}

static void ipa_del_route(struct osmo_fsm_inst *fi)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_as *as = xafp->as;
	struct osmo_ss7_instance *inst = as->inst;
	struct osmo_ss7_route *rt;

	/* don't delete a route if we added none */
	if (!xafp->ipa_route_created)
		return;

	/* find the route which we have created if we ever reached ipa_asp_fsm_wait_id_ack2 */
	rt = osmo_ss7_route_find_dpc_mask(inst->rtable_system, as->cfg.routing_key.pc, 0xffffff);
	/* no route found, bail out */
	if (!rt) {
		LOGPFSML(fi, LOGL_NOTICE, "Attempting to delete route for this IPA AS, but cannot "
			 "find route for DPC %s. Did you manually delete it?\n",
			 osmo_ss7_pointcode_print(inst, as->cfg.routing_key.pc));
		return;
	}

	/* route points to different AS, bail out */
	if (rt->dest.as != as) {
		LOGPFSML(fi, LOGL_NOTICE, "Attempting to delete route for this IPA ASP, but found "
			 "route for DPC %s points to different AS (%s)\n",
			 osmo_ss7_pointcode_print(inst, as->cfg.routing_key.pc), rt->dest.as->cfg.name);
		return;
	}

	osmo_ss7_route_destroy(rt);
	xafp->ipa_route_created = false;
}



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

/* Tell other previously-active ASPs that a new ASP has been activated and mark
   them as inactive. Used in override mode when an ASP becomes active. */
static void notify_any_other_active_asp_as_inactive(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp_cmp)
{
	unsigned int i;
	struct msgb *msg;
	struct osmo_xlm_prim_notify npar = {
		.status_type = M3UA_NOTIFY_T_OTHER,
		.status_info = M3UA_NOTIFY_I_OT_ALT_ASP_ACT,
	};

	if (asp_cmp->asp_id_present)
		npar.asp_id = asp_cmp->asp_id;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp || !osmo_ss7_asp_active(asp))
			continue;

		if (asp_cmp == asp)
			continue;

		if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
			msg = encode_notify(&npar);
			osmo_ss7_asp_send(asp, msg);
		}

		osmo_fsm_inst_state_chg(asp->fi, XUA_ASP_S_INACTIVE, 0, 0);
	}

	return;
}

static void t_r_callback(void *_fi)
{
	struct osmo_fsm_inst *fi = _fi;
	osmo_fsm_inst_dispatch(fi, XUA_AS_E_RECOVERY_EXPD, NULL);
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
	struct osmo_xlm_prim_notify npar = {
		.status_type = M3UA_NOTIFY_T_STATCHG,
	};

	switch (fi->state) {
	case XUA_AS_S_INACTIVE:
		npar.status_info = M3UA_NOTIFY_I_AS_INACT;
		break;
	case XUA_AS_S_ACTIVE:
		if (is_single_ipa_asp(as))
			ipa_add_route(fi);
		npar.status_info = M3UA_NOTIFY_I_AS_ACT;
		break;
	case XUA_AS_S_PENDING:
		npar.status_info = M3UA_NOTIFY_I_AS_PEND;
		break;
	case XUA_AS_S_DOWN:
		if (is_single_ipa_asp(as))
			ipa_del_route(fi);
		/* RFC4666 sec 4.3.2 AS States:
		   If we end up here, it means no ASP is ACTIVE or INACTIVE,
		   meaning no ASP can have already configured the traffic mode
		   in ASPAC or REG REQ. Hence, we can clear traffic mode defined
		   by peers and allow next first peer to request a new traffic
		   mode. */
		as->cfg.mode_set_by_peer = false;
		if (!as->cfg.mode_set_by_vty)
			as->cfg.mode = OSMO_SS7_AS_TMOD_OVERRIDE;
		return;
	default:
		return;
	}

	/* Add the routing context, if it is configured */
	if (as->cfg.routing_key.context) {
		npar.presence |= NOTIFY_PAR_P_ROUTE_CTX;
		npar.route_ctx = as->cfg.routing_key.context;
	}

	/* TODO: ASP-Id of ASP triggering this state change */

	as_notify_all_asp(xafp->as, &npar);

	/* only if we are the SG, we must start broadcasting availability information
	 * to everyone else */
	if (get_local_role(xafp->as) == OSMO_SS7_ASP_ROLE_SG) {
		/* advertise availability of the routing key to others */
		uint32_t aff_pc = htonl(as->cfg.routing_key.pc);
		if (old_state != XUA_AS_S_ACTIVE && fi->state == XUA_AS_S_ACTIVE)
			xua_snm_pc_available(as, &aff_pc, 1, NULL, true);
		else if (old_state == XUA_AS_S_ACTIVE && fi->state != XUA_AS_S_ACTIVE)
			xua_snm_pc_available(as, &aff_pc, 1, NULL, false);
	}
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
	struct osmo_ss7_asp *asp;
	struct msgb *msg;

	switch (event) {
	case XUA_ASPAS_ASP_DOWN_IND:
	case XUA_ASPAS_ASP_INACTIVE_IND:
		asp = data;
		if (check_any_other_asp_in_active(xafp->as, asp)) {
			/* ignore, we stay AS_ACTIVE */
		} else {
			uint32_t recovery_msec = xafp->as->cfg.recovery_timeout_msec;
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_PENDING, 0, 0);
			/* Start T(r) */
			osmo_timer_schedule(&xafp->recovery.t_r, MSEC_TO_S_US(recovery_msec));
			/* FIXME: Queue all signalling messages until
			 * recovery or T(r) expiry */
		}
		break;
	case XUA_ASPAS_ASP_ACTIVE_IND:
		asp = data;
		/* RFC466 sec 4.3.4.3 ASP Active Procedures*/
		if (xafp->as->cfg.mode == OSMO_SS7_AS_TMOD_OVERRIDE)
			notify_any_other_active_asp_as_inactive(xafp->as, asp);
		break;
	case XUA_AS_E_TRANSFER_REQ:
		/* message for transmission */
		msg = data;
		xua_as_transmit_msg(xafp->as, msg);
		break;
	}
}

static void xua_as_fsm_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct msgb *msg;

	switch (event) {
	case XUA_ASPAS_ASP_ACTIVE_IND:
		/* one ASP transitions into ASP-ACTIVE */
		osmo_timer_del(&xafp->recovery.t_r);
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_ACTIVE, 0, 0);
		/* push out any pending queued messages */
		while ((msg = msgb_dequeue(&xafp->recovery.queued_msgs)))
			xua_as_transmit_msg(xafp->as, msg);
		break;
	case XUA_ASPAS_ASP_INACTIVE_IND:
		/* ignore */
		break;
	case XUA_ASPAS_ASP_DOWN_IND:
		/* ignore */
		break;
	case XUA_AS_E_RECOVERY_EXPD:
		LOGPFSM(fi, "T(r) expired; dropping queued messages\n");
		while ((msg = msgb_dequeue(&xafp->recovery.queued_msgs)))
			talloc_free(msg);
		if (check_any_other_asp_not_down(xafp->as, NULL))
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_INACTIVE, 0, 0);
		else
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_DOWN, 0, 0);
		break;
	case XUA_AS_E_TRANSFER_REQ:
		/* enqueue the to-be-transferred message */
		msg = data;
		msgb_enqueue(&xafp->recovery.queued_msgs, msg);
		break;
	}
}

static void xua_as_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;

	osmo_timer_del(&xafp->recovery.t_r);
}

static const struct osmo_fsm_state xua_as_fsm_states[] = {
	[XUA_AS_S_DOWN] = {
		.in_event_mask = S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_DOWN_IND),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE),
		.name = "AS_DOWN",
		.action = xua_as_fsm_down,
		.onenter = xua_as_fsm_onenter,
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
				 S(XUA_ASPAS_ASP_ACTIVE_IND) |
				 S(XUA_AS_E_TRANSFER_REQ),
		.out_state_mask = S(XUA_AS_S_ACTIVE) |
				  S(XUA_AS_S_PENDING),
		.name = "AS_ACTIVE",
		.action = xua_as_fsm_active,
		.onenter = xua_as_fsm_onenter,
	},
	[XUA_AS_S_PENDING] = {
		.in_event_mask = S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND) |
				 S(XUA_AS_E_TRANSFER_REQ) |
				 S(XUA_AS_E_RECOVERY_EXPD),
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
	.cleanup = xua_as_fsm_cleanup,
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
	xafp->recovery.t_r.cb = t_r_callback;
	xafp->recovery.t_r.data = fi;
	INIT_LLIST_HEAD(&xafp->recovery.queued_msgs);

	fi->priv = xafp;

	return fi;
}
