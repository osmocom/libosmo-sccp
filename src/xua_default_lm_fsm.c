/* Default XUA Layer Manager */
/* (C) 2017-2021 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* The idea of this default Layer Manager is as follows:
 * - we wait until a SCTP connection is established
 * - we issue the ASP-UP request and wait for the ASP being in UP state
 * - we wait if we receive a M-NOTIFY indication about any AS in this ASP
 * - if that's not received, we use RKM to register a routing context
 *   for our locally configured ASP and expect a positive registration
 *   result as well as a NOTIFY indication about AS-ACTIVE afterwards.
 */

#include <errno.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_internal.h"
#include "xua_asp_fsm.h"

#define S(x)	(1 << (x))

enum lm_state {
	/* idle state, SCTP not connected */
	S_IDLE,
	/* we're waiting for the ASP-UP to be confirmed */
	S_WAIT_ASP_UP,
	/* we are waiting for any NOTIFY about an AS in this ASP */
	S_WAIT_NOTIFY,
	/* we've sent a RK REG REQ and wait for the result */
	S_RKM_REG,
	/* all systems up, we're communicating */
	S_ACTIVE,
};

enum lm_event {
	LM_E_SCTP_EST_IND,
	LM_E_ASP_UP_CONF,
	LM_E_NOTIFY_IND,
	LM_E_AS_INACTIVE_IND,
	LM_E_AS_ACTIVE_IND,
	LM_E_AS_STATUS_IND,
	LM_E_RKM_REG_CONF,
	LM_E_SCTP_DISC_IND,
};

static const struct value_string lm_event_names[] = {
	{ LM_E_SCTP_EST_IND,	"SCTP-ESTABLISH.ind" },
	{ LM_E_ASP_UP_CONF,	"ASP-UP.conf" },
	{ LM_E_NOTIFY_IND,	"NOTIFY.ind" },
	{ LM_E_AS_INACTIVE_IND,	"AS-INACTIVE.ind" },
	{ LM_E_AS_ACTIVE_IND,	"AS-ACTIVE.ind" },
	{ LM_E_AS_STATUS_IND,	"AS-STATUS.ind" },
	{ LM_E_RKM_REG_CONF,	"RKM_REG.conf" },
	{ LM_E_SCTP_DISC_IND,	"SCTP-RELEASE.ind" },
	{ 0, NULL }
};

enum lm_timer {
	T_WAIT_ASP_UP,
	T_WAIT_NOTIFY,
	T_WAIT_NOTIFY_RKM,
	T_WAIT_RK_REG_RESP,
};

struct lm_fsm_priv {
	struct osmo_ss7_asp *asp;
};

static struct osmo_ss7_as *find_first_as_in_asp(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as;

	llist_for_each_entry(as, &asp->inst->as_list, list) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
			if (as->cfg.asps[i] == asp)
				return as;
		}
	}

	return NULL;
}

/* handle an incoming RKM registration response */
static int handle_reg_conf(struct osmo_fsm_inst *fi, uint32_t l_rk_id, uint32_t rctx)
{
	struct lm_fsm_priv *lmp = fi->priv;
	struct osmo_ss7_asp *asp = lmp->asp;
	struct osmo_ss7_as *as;

	/* update the application server with the routing context as
	 * allocated/registered by the SG */
	as = osmo_ss7_as_find_by_l_rk_id(asp->inst, l_rk_id);
	if (!as) {
		LOGPFSM(fi, "RKM Result for unknown l_rk_id %u\n", l_rk_id);
		return -EINVAL;
	}
	as->cfg.routing_key.context = rctx;

	return 0;
}

static void restart_asp(struct osmo_fsm_inst *fi)
{
	struct lm_fsm_priv *lmp = fi->priv;
	struct osmo_ss7_asp *asp = lmp->asp;
	int log_level = fi->log_level;

	osmo_ss7_asp_restart(asp);
	osmo_ss7_asp_use_default_lm(asp, log_level);
}


static void lm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lm_fsm_priv *lmp = fi->priv;

	switch (event) {
	case LM_E_SCTP_EST_IND:
		/* Try to transition to ASP-UP, wait for 20s */
		osmo_fsm_inst_state_chg(fi, S_WAIT_ASP_UP, 20, T_WAIT_ASP_UP);
		osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
		break;
	}
}

static void lm_wait_asp_up(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case LM_E_ASP_UP_CONF:
		/* ASP is up, wait for some time if any NOTIFY
		 * indications about AS in this ASP are received */
		osmo_fsm_inst_state_chg(fi, S_WAIT_NOTIFY, 2, T_WAIT_NOTIFY);
		break;
	}
}


static int lm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct lm_fsm_priv *lmp = fi->priv;
	struct osmo_xlm_prim *prim;
	struct osmo_ss7_as *as;

	switch (fi->T) {
	case T_WAIT_ASP_UP:
		/* we have been waiting for the ASP to come up, but it
		 * failed to do so */
		LOGPFSML(fi, LOGL_NOTICE, "Peer didn't send any ASP_UP in time! Restarting ASP\n");
		restart_asp(fi);
		break;
	case T_WAIT_NOTIFY:
		if (lmp->asp->cfg.quirks & OSMO_SS7_ASP_QUIRK_NO_NOTIFY) {
			/* some implementations don't send the NOTIFY which they SHOULD
			 * according to RFC4666 (see OS#5145) */
			LOGPFSM(fi, "quirk no_notify active; locally emulate AS-INACTIVE.ind\n");
			osmo_fsm_inst_dispatch(fi, LM_E_AS_INACTIVE_IND, NULL);
			break;
		}
		/* No AS has reported via NOTIFY that is was
		 * (statically) configured at the SG for this ASP, so
		 * let's dynamically register */
		osmo_fsm_inst_state_chg(fi, S_RKM_REG, 10, T_WAIT_RK_REG_RESP);
		prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_REQUEST);
		OSMO_ASSERT(prim);
		as = find_first_as_in_asp(lmp->asp);
		if (!as) {
			LOGPFSML(fi, LOGL_ERROR, "Unable to find AS!\n");
			restart_asp(fi);
			return 0;
		}
		/* Fill in settings from first AS (TODO: multiple AS support) */
		prim->u.rk_reg.key = as->cfg.routing_key;
		prim->u.rk_reg.traf_mode = as->cfg.mode;
		osmo_xlm_sap_down(lmp->asp, &prim->oph);
		break;
	case T_WAIT_NOTIFY_RKM:
		/* No AS has reported via NOTIFY even after dynamic RKM
		 * configuration */
		restart_asp(fi);
		break;
	case T_WAIT_RK_REG_RESP:
		/* timeout of registration of routing key */
		restart_asp(fi);
		break;
	}
	return 0;
}

static void lm_wait_notify(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lm_fsm_priv *lmp = fi->priv;
	struct osmo_xlm_prim *oxp = data;

	switch (event) {
	case LM_E_NOTIFY_IND:
		OSMO_ASSERT(oxp->oph.primitive == OSMO_XLM_PRIM_M_NOTIFY);
		OSMO_ASSERT(oxp->oph.operation == PRIM_OP_INDICATION);
		if (oxp->u.notify.status_type == M3UA_NOTIFY_T_STATCHG &&
		    (oxp->u.notify.status_info == M3UA_NOTIFY_I_AS_INACT ||
		     oxp->u.notify.status_info == M3UA_NOTIFY_I_AS_PEND)) {
			osmo_fsm_inst_state_chg(fi, S_ACTIVE, 0, 0);
			osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		}
		break;
	case LM_E_AS_INACTIVE_IND:
		/* we now know that an AS is associated with this ASP at
		 * the SG, and that this AS is currently inactive */
		/* request the ASP to go into active state (which
		 * hopefully will bring the AS to active, too) */
		osmo_fsm_inst_state_chg(fi, S_ACTIVE, 0, 0);
		osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	}
};

static void lm_rkm_reg(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_xlm_prim *oxp;
	int rc;

	switch (event) {
	case LM_E_RKM_REG_CONF:
		oxp = data;
		if (oxp->u.rk_reg.status != M3UA_RKM_REG_SUCCESS) {
			LOGPFSML(fi, LOGL_NOTICE, "Received RKM_REG_RSP with negative result\n");
			restart_asp(fi);
		} else {
			rc = handle_reg_conf(fi, oxp->u.rk_reg.key.l_rk_id, oxp->u.rk_reg.key.context);
			if (rc < 0)
				restart_asp(fi);
			/* RKM registration was successful, we can
			 * transition to WAIT_NOTIFY state and assume
			 * that an NOTIFY/AS-INACTIVE arrives within 20
			 * seconds */
			osmo_fsm_inst_state_chg(fi, S_WAIT_NOTIFY, 20, T_WAIT_NOTIFY_RKM);
		}
		break;
	}
}

static void lm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lm_fsm_priv *lmp = fi->priv;
	struct osmo_xlm_prim *oxp;

	switch (event) {
	case LM_E_AS_INACTIVE_IND:
		/* request the ASP to go into active state */
		osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	case LM_E_NOTIFY_IND:
		oxp = data;
		OSMO_ASSERT(oxp->oph.primitive == OSMO_XLM_PRIM_M_NOTIFY);
		OSMO_ASSERT(oxp->oph.operation == PRIM_OP_INDICATION);
		if (oxp->u.notify.status_type == M3UA_NOTIFY_T_STATCHG &&
		    oxp->u.notify.status_info != M3UA_NOTIFY_I_AS_ACT)
			restart_asp(fi);
		break;
	}
}

static void lm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case LM_E_SCTP_DISC_IND:
		restart_asp(fi);
		break;
	}
}

static const struct osmo_fsm_state lm_states[] = {
	[S_IDLE] = {
		.in_event_mask = S(LM_E_SCTP_EST_IND),
		.out_state_mask = S(S_WAIT_ASP_UP),
		.name = "IDLE",
		.action = lm_idle,
	},
	[S_WAIT_ASP_UP] = {
		.in_event_mask = S(LM_E_ASP_UP_CONF),
		.out_state_mask = S(S_WAIT_NOTIFY),
		.name = "WAIT_ASP_UP",
		.action = lm_wait_asp_up,
	},
	[S_WAIT_NOTIFY] = {
		.in_event_mask = S(LM_E_AS_INACTIVE_IND) | S(LM_E_NOTIFY_IND),
		.out_state_mask = S(S_RKM_REG) | S(S_ACTIVE),
		.name = "WAIT_NOTIFY",
		.action = lm_wait_notify,
	},
	[S_RKM_REG] = {
		.in_event_mask = S(LM_E_RKM_REG_CONF),
		.out_state_mask = S(S_WAIT_NOTIFY),
		.name = "RKM_REG",
		.action = lm_rkm_reg,
	},
	[S_ACTIVE] = {
		.in_event_mask = S(LM_E_AS_INACTIVE_IND) | S(LM_E_NOTIFY_IND),
		.name = "ACTIVE",
		.action = lm_active,
	},
};

/* Map from incoming XLM SAP primitives towards FSM events */
static const struct osmo_prim_event_map lm_event_map[] = {
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION, LM_E_SCTP_EST_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION, LM_E_SCTP_DISC_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_CONFIRM, LM_E_ASP_UP_CONF },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_AS_STATUS, PRIM_OP_INDICATION, LM_E_AS_STATUS_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_NOTIFY, PRIM_OP_INDICATION, LM_E_NOTIFY_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_AS_INACTIVE, PRIM_OP_INDICATION, LM_E_AS_INACTIVE_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_AS_ACTIVE, PRIM_OP_INDICATION, LM_E_AS_ACTIVE_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_CONFIRM, LM_E_RKM_REG_CONF },
	{ 0, 0, 0, OSMO_NO_EVENT },
};


struct osmo_fsm xua_default_lm_fsm = {
	.name = "xua_default_lm",
	.states = lm_states,
	.num_states = ARRAY_SIZE(lm_states),
	.timer_cb = lm_timer_cb,
	.event_names = lm_event_names,
	.allstate_event_mask = S(LM_E_SCTP_DISC_IND),
	.allstate_action = lm_allstate,
	.log_subsys = DLSS7,
};


/* layer manager primitive call-back function, registered osmo_ss7 */
static int default_lm_prim_cb(struct osmo_prim_hdr *oph, void *_asp)
{
	struct osmo_ss7_asp *asp = _asp;
	struct osmo_fsm_inst *fi = asp->lm_priv;
	uint32_t event = osmo_event_for_prim(oph, lm_event_map);
	char *prim_name = osmo_xlm_prim_name(oph);

	LOGPFSM(fi, "Received primitive %s\n", prim_name);

	if (event == OSMO_NO_EVENT) {
		LOGPFSML(fi, LOGL_NOTICE, "Ignoring primitive %s\n", prim_name);
		return 0;
	}

	osmo_fsm_inst_dispatch(fi, event, oph);

	return 0;
}

static const struct osmo_xua_layer_manager default_layer_manager = {
	.prim_cb = default_lm_prim_cb,
};

int osmo_ss7_asp_use_default_lm(struct osmo_ss7_asp *asp, int log_level)
{
	struct lm_fsm_priv *lmp;
	struct osmo_fsm_inst *fi;

	if (asp->lm_priv) {
		osmo_fsm_inst_term(asp->lm_priv, OSMO_FSM_TERM_ERROR, NULL);
		asp->lm_priv = NULL;
	}

	fi = osmo_fsm_inst_alloc(&xua_default_lm_fsm, asp, NULL, log_level, asp->cfg.name);

	lmp = talloc_zero(fi, struct lm_fsm_priv);
	if (!lmp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return -ENOMEM;
	}
	lmp->asp = asp;
	fi->priv = lmp;

	asp->lm = &default_layer_manager;
	asp->lm_priv = fi;

	return 0;
}
