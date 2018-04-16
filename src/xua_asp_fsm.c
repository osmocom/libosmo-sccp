/* SCCP M3UA / SUA ASP osmo_fsm according to RFC3868 4.3.1 */
/* (C) Copyright 2017 by Harald Welte <laforge@gnumonks.org>
 * 
 * All Rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Based on my earlier Erlang implementation xua_asp_fsm.erl in
 * osmo-ss7.git
 */

#include <errno.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/ipa.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>
#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/protocol/sua.h>

#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"

#define S(x)	(1 << (x))

/* The general idea is:
 * * translate incoming SUA/M3UA msg_class/msg_type to xua_asp_event
 * * propagate state transitions to XUA_AS_FSM via _onenter functiosn
 * * notify the Layer Management of any relevant changes
 * * 
 */

/* According to RFC3868 Section 8 */
#define XUA_T_A_SEC	2
#define XUA_T_R_SEC	2
#define XUA_T_ACK_SEC	2
#define XUA_T_BEAT_SEC	30
#define SUA_T_IAS_SEC	(7*60)		/* SUA only */
#define SUA_T_IAR_SEC	(15*60)		/* SUA only */

static const struct value_string xua_asp_role_names[] = {
	{ XUA_ASPFSM_ROLE_ASP,	"ASP" },
	{ XUA_ASPFSM_ROLE_SG,	"SG" },
	{ XUA_ASPFSM_ROLE_IPSP,	"IPSP" },
	{ 0, NULL }
};

static const struct value_string xua_asp_event_names[] = {
	{ XUA_ASP_E_M_ASP_UP_REQ,	"M-ASP_UP.req" },
	{ XUA_ASP_E_M_ASP_ACTIVE_REQ,	"M-ASP_ACTIVE.req" },
	{ XUA_ASP_E_M_ASP_DOWN_REQ,	"M-ASP_DOWN.req" },
	{ XUA_ASP_E_M_ASP_INACTIVE_REQ,	"M-ASP_INACTIVE.req" },

	{ XUA_ASP_E_SCTP_COMM_DOWN_IND,	"SCTP-COMM_DOWN.ind" },
	{ XUA_ASP_E_SCTP_RESTART_IND,	"SCTP-RESTART.ind" },
	{ XUA_ASP_E_SCTP_EST_IND,	"SCTP-EST.ind" },

	{ XUA_ASP_E_ASPSM_ASPUP,	"ASPSM-ASP_UP" },
	{ XUA_ASP_E_ASPSM_ASPUP_ACK,	"ASPSM-ASP_UP_ACK" },
	{ XUA_ASP_E_ASPTM_ASPAC,	"ASPTM-ASP_AC" },
	{ XUA_ASP_E_ASPTM_ASPAC_ACK,	"ASPTM-ASP_AC_ACK" },
	{ XUA_ASP_E_ASPSM_ASPDN,	"ASPSM-ASP_DN" },
	{ XUA_ASP_E_ASPSM_ASPDN_ACK,	"ASPSM-ASP_DN_ACK" },
	{ XUA_ASP_E_ASPTM_ASPIA,	"ASPTM-ASP_IA" },
	{ XUA_ASP_E_ASPTM_ASPIA_ACK,	"ASPTM_ASP_IA_ACK" },

	{ XUA_ASP_E_ASPSM_BEAT,		"ASPSM_BEAT" },
	{ XUA_ASP_E_ASPSM_BEAT_ACK,	"ASPSM_BEAT_ACK" },

	{ IPA_ASP_E_ID_RESP,		"IPA_CCM_ID_RESP" },
	{ IPA_ASP_E_ID_GET,		"IPA_CCM_ID_GET" },
	{ IPA_ASP_E_ID_ACK,		"IPA_CCM_ID_ACK" },

	{ 0, NULL }
};

/* private data structure for each FSM instance */
struct xua_asp_fsm_priv {
	/* pointer back to ASP to which we belong */
	struct osmo_ss7_asp *asp;
	/* Role (ASP/SG/IPSP) */
	enum xua_asp_role role;

	/* routing context[s]: list of 32bit integers */
	/* ACTIVE: traffic mode type, tid label, drn label ? */

	struct {
		struct osmo_timer_list timer;
		int out_event;
	} t_ack;
};

struct osmo_xlm_prim *xua_xlm_prim_alloc(enum osmo_xlm_prim_type prim_type,
					 enum osmo_prim_operation op)
{
	struct osmo_xlm_prim *prim;
	struct msgb *msg = msgb_alloc_headroom(2048+128, 128, "xua_asp-xlm msgb");
	if (!msg)
		return NULL;

	prim = (struct osmo_xlm_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, XUA_SAP_LM, prim_type, op, msg);

	return prim;
}

/* Send a XUA LM Primitive to the XUA Layer Manager (LM) */
void xua_asp_send_xlm_prim(struct osmo_ss7_asp *asp, struct osmo_xlm_prim *prim)
{
	const struct osmo_xua_layer_manager *lm = asp->lm;

	if (lm && lm->prim_cb)
		lm->prim_cb(&prim->oph, asp);
	else {
		LOGPASP(asp, DLSS7, LOGL_DEBUG, "No Layer Manager, dropping %s\n",
			osmo_xlm_prim_name(&prim->oph));
	}

	msgb_free(prim->oph.msg);
}

/* wrapper around send_xlm_prim for primitives without data */
void xua_asp_send_xlm_prim_simple(struct osmo_ss7_asp *asp,
				enum osmo_xlm_prim_type prim_type,
				enum osmo_prim_operation op)
{
	struct osmo_xlm_prim *prim = xua_xlm_prim_alloc(prim_type, op);
	if (!prim)
		return;
	xua_asp_send_xlm_prim(asp, prim);
}

static void send_xlm_prim_simple(struct osmo_fsm_inst *fi,
				 enum osmo_xlm_prim_type prim_type,
				enum osmo_prim_operation op)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	xua_asp_send_xlm_prim_simple(asp, prim_type, op);
}

/* ask the xUA implementation to transmit a specific message */
static int peer_send(struct osmo_fsm_inst *fi, int out_event, struct xua_msg *in)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg *xua = xua_msg_alloc();
	struct msgb *msg;

	switch (out_event) {
	case XUA_ASP_E_ASPSM_ASPUP:
		/* RFC 3868 Ch. 3.5.1 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_UP);
		/* Optional: ASP ID */
		if (asp->asp_id_present)
			xua_msg_add_u32(xua, SUA_IEI_ASP_ID, asp->asp_id);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_ASPUP_ACK:
		/* RFC3868 Ch. 3.5.2 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_UP_ACK);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		/* RFC3868 Ch. 3.5.3 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_DOWN);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_ASPDN_ACK:
		/* RFC3868 Ch. 3.5.4 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_DOWN_ACK);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_BEAT:
		/* RFC3868 Ch. 3.5.5 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_BEAT);
		/* Optional: Heartbeat Data */
		break;
	case XUA_ASP_E_ASPSM_BEAT_ACK:
		/* RFC3868 Ch. 3.5.6 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_BEAT_ACK);
		/* Optional: Heartbeat Data */
		xua_msg_copy_part(xua, M3UA_IEI_HEARDBT_DATA, in, M3UA_IEI_HEARDBT_DATA);
		break;
	case XUA_ASP_E_ASPTM_ASPAC:
		/* RFC3868 Ch. 3.6.1 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_ACTIVE);
		/* Optional: Traffic Mode Type */
		/* Optional: Routing Context */
		/* Optional: TID Label */
		/* Optional: DRN Label */
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPTM_ASPAC_ACK:
		/* RFC3868 Ch. 3.6.2 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_ACTIVE_ACK);
		/* Optional: Traffic Mode Type */
		/* Mandatory: Routing Context */
		//FIXME xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPTM_ASPIA:
		/* RFC3868 Ch. 3.6.3 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_INACTIVE);
		/* Optional: Routing Context */
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPTM_ASPIA_ACK:
		/* RFC3868 Ch. 3.6.4 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_INACTIVE_ACK);
		/* Optional: Routing Context */
		/* Optional: Info String */
		break;
	}

	msg = xua_to_msg(SUA_VERSION, xua);
	xua_msg_free(xua);
	if (!msg)
		return -1;

	return osmo_ss7_asp_send(asp, msg);
}

static int peer_send_error(struct osmo_fsm_inst *fi, uint32_t err_code)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg *xua = xua_msg_alloc();
	struct msgb *msg;

	xua->hdr = XUA_HDR(SUA_MSGC_MGMT, SUA_MGMT_ERR);
	xua->hdr.version = SUA_VERSION;
	xua_msg_add_u32(xua, SUA_IEI_ERR_CODE, err_code);

	msg = xua_to_msg(SUA_VERSION, xua);
	xua_msg_free(xua);
	if (!msg)
		return -1;

	return osmo_ss7_asp_send(asp, msg);
}

static void xua_t_ack_cb(void *data)
{
	struct osmo_fsm_inst *fi = data;
	struct xua_asp_fsm_priv *xafp = fi->priv;

	LOGPFSML(fi, LOGL_INFO, "T(ack) callback: re-transmitting event %s\n",
		osmo_fsm_event_name(fi->fsm, xafp->t_ack.out_event));

	/* Re-transmit message */
	peer_send(fi, xafp->t_ack.out_event, NULL);

	/* Re-start the timer */
	osmo_timer_schedule(&xafp->t_ack.timer, XUA_T_ACK_SEC, 0);
}

static int peer_send_and_start_t_ack(struct osmo_fsm_inst *fi,
				     int out_event)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	int rc;

	rc = peer_send(fi, out_event, NULL);
	if (rc < 0)
		return rc;

	xafp->t_ack.out_event = out_event;
	xafp->t_ack.timer.cb = xua_t_ack_cb,
	xafp->t_ack.timer.data = fi;

	osmo_timer_schedule(&xafp->t_ack.timer, XUA_T_ACK_SEC, 0);

	return rc;
}

static const uint32_t evt_ack_map[_NUM_XUA_ASP_E] = {
	[XUA_ASP_E_ASPSM_ASPUP] = XUA_ASP_E_ASPSM_ASPUP_ACK,
	[XUA_ASP_E_ASPTM_ASPAC] = XUA_ASP_E_ASPTM_ASPAC_ACK,
	[XUA_ASP_E_ASPSM_ASPDN] = XUA_ASP_E_ASPSM_ASPDN_ACK,
	[XUA_ASP_E_ASPTM_ASPIA] = XUA_ASP_E_ASPTM_ASPIA_ACK,
	[XUA_ASP_E_ASPSM_BEAT] = XUA_ASP_E_ASPSM_BEAT_ACK,
};


/* check if expected message was received + stop t_ack */
static void check_stop_t_ack(struct osmo_fsm_inst *fi, uint32_t event)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	int exp_ack;

	if (event >= ARRAY_SIZE(evt_ack_map))
		return;

	exp_ack = evt_ack_map[xafp->t_ack.out_event];
	if (exp_ack && event == exp_ack) {
		LOGPFSML(fi, LOGL_DEBUG, "T(ack) stopped\n");
		osmo_timer_del(&xafp->t_ack.timer);
	}
}

#define ENSURE_ASP_OR_IPSP(fi, event) 					\
	do {								\
		struct xua_asp_fsm_priv *_xafp = fi->priv;		\
		if (_xafp->role != XUA_ASPFSM_ROLE_ASP &&		\
		    _xafp->role != XUA_ASPFSM_ROLE_IPSP) {		\
			LOGPFSML(fi, LOGL_ERROR, "event %s not permitted " \
				 "in role %s\n",			\
				 osmo_fsm_event_name(fi->fsm, event),	\
				 get_value_string(xua_asp_role_names, _xafp->role));\
			return;						\
		}							\
	} while(0)

#define ENSURE_SG_OR_IPSP(fi, event) 					\
	do {								\
		struct xua_asp_fsm_priv *_xafp = fi->priv;		\
		if (_xafp->role != XUA_ASPFSM_ROLE_SG &&		\
		    _xafp->role != XUA_ASPFSM_ROLE_IPSP) {		\
			LOGPFSML(fi, LOGL_ERROR, "event %s not permitted " \
				 "in role %s\n",			\
				 osmo_fsm_event_name(fi->fsm, event),	\
				 get_value_string(xua_asp_role_names, _xafp->role));\
			return;						\
		}							\
	} while(0)

static void xua_asp_fsm_down(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg_part *asp_id_ie;

	check_stop_t_ack(fi, event);

	switch (event) {
	case XUA_ASP_E_M_ASP_UP_REQ:
		/* only if role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		/* Send M3UA_MSGT_ASPSM_ASPUP and start t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPSM_ASPUP);
		break;
	case XUA_ASP_E_ASPSM_ASPUP_ACK:
		/* only if role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_CONFIRM);
		/* This hack should be in layer manager, but let's try
		 * to be smart in case there is no layer manager */
		if (!asp->lm)
			osmo_fsm_inst_dispatch(fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	case XUA_ASP_E_ASPSM_ASPUP:
		/* only if role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		asp_id_ie = xua_msg_find_tag(data, SUA_IEI_ASP_ID);
		/* Optional ASP Identifier: Store for NTFY */
		if (asp_id_ie) {
			asp->asp_id = xua_msg_part_get_u32(asp_id_ie);
			asp->asp_id_present = true;
		}
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_UP,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		/* only if role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* The SGP MUST send an ASP Down Ack message in response
		 * to a received ASP Down message from the ASP even if
		 * the ASP is already marked as ASP-DOWN at the SGP. */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPDN_ACK, NULL);
		break;
	case XUA_ASP_E_SCTP_EST_IND:
		break;
	}
}

/* Helper function to dispatch an ASP->AS event to all AS of which this
 * ASP is a memmber.  Ignores routing contexts for now. */
static void dispatch_to_all_as(struct osmo_fsm_inst *fi, uint32_t event)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct osmo_ss7_instance *inst = asp->inst;
	struct osmo_ss7_as *as;

	llist_for_each_entry(as, &inst->as_list, list) {
		if (!osmo_ss7_as_has_asp(as, asp))
			continue;
		osmo_fsm_inst_dispatch(as->fi, event, asp);
	}
}

static void xua_asp_fsm_down_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_DOWN_IND);
}

static void xua_asp_fsm_inactive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg *xua_in;
	uint32_t traf_mode;

	check_stop_t_ack(fi, event);
	switch (event) {
	case XUA_ASP_E_M_ASP_ACTIVE_REQ:
		/* send M3UA_MSGT_ASPTM_ASPAC and start t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPTM_ASPAC);
		break;
	case XUA_ASP_E_M_ASP_DOWN_REQ:
		/* send M3UA_MSGT_ASPSM_ASPDN and start t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPSM_ASPDN);
		break;
	case XUA_ASP_E_ASPTM_ASPAC_ACK:
		/* only in role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_ACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_ACTIVE,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPSM_ASPDN_ACK:
		/* only in role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPTM_ASPAC:
		xua_in = data;
		/* only in role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		if (xua_msg_find_tag(xua_in, M3UA_IEI_TRAF_MODE_TYP)) {
			traf_mode = xua_msg_get_u32(xua_in, M3UA_IEI_TRAF_MODE_TYP);
			if (traf_mode != M3UA_TMOD_OVERRIDE &&
			    traf_mode != M3UA_TMOD_LOADSHARE &&
			    traf_mode != M3UA_TMOD_BCAST) {
				peer_send_error(fi, M3UA_ERR_UNSUPP_TRAF_MOD_TYP);
				break;
			}
		}
		if (xua_msg_find_tag(xua_in, M3UA_IEI_ROUTE_CTX)) {
			uint32_t rctx = xua_msg_get_u32(xua_in, M3UA_IEI_ROUTE_CTX);
			if (!osmo_ss7_as_find_by_rctx(asp->inst, rctx)) {
				peer_send_error(fi, M3UA_ERR_INVAL_ROUT_CTX);
				break;
			}
		}
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPTM_ASPAC_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_ACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_ACTIVE,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		/* only in role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPDN_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPUP:
		/* only if role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* If an ASP Up message is received and internally the
		 * remote ASP is already in the ASP-INACTIVE state, an
		 * ASP Up Ack message is returned and no further action
		 * is taken. */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
		break;
	case XUA_ASP_E_ASPTM_ASPIA:
		/* only in role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		peer_send(fi, XUA_ASP_E_ASPTM_ASPIA_ACK, NULL);
		break;
	}
}

static void xua_asp_fsm_inactive_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_INACTIVE_IND);
}

static void xua_asp_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	check_stop_t_ack(fi, event);
	switch (event) {
	case XUA_ASP_E_ASPSM_ASPDN_ACK:
		/* only in role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPTM_ASPIA_ACK:
		/* only in role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_M_ASP_DOWN_REQ:
		/* only in role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		/* send M3UA_MSGT_ASPSM_ASPDN and star t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPSM_ASPDN);
		break;
	case XUA_ASP_E_M_ASP_INACTIVE_REQ:
		/* only in role ASP */
		ENSURE_ASP_OR_IPSP(fi, event);
		/* send M3UA_MSGT_ASPTM_ASPIA and star t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPTM_ASPIA);
		break;
	case XUA_ASP_E_ASPTM_ASPIA:
		/* only in role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPTM_ASPIA_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		/* only in role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPDN_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPUP:
		/* only if role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* an ASP Up Ack message is returned, as well as
		 * an Error message ("Unexpected Message), and the
		 * remote ASP state is changed to ASP-INACTIVE in all
		 * relevant Application Servers */
		peer_send_error(fi, M3UA_ERR_UNEXPECTED_MSG);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		peer_send(fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPTM_ASPAC:
		/* only in role SG */
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPTM_ASPAC_ACK, NULL);
		break;
	}
}

static void xua_asp_fsm_active_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_ACTIVE_IND);
}

static void xua_asp_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_msg *xua;

	switch (event) {
	case XUA_ASP_E_SCTP_COMM_DOWN_IND:
	case XUA_ASP_E_SCTP_RESTART_IND:
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_BEAT:
		xua = data;
		peer_send(fi, XUA_ASP_E_ASPSM_BEAT_ACK, xua);
		break;
	case XUA_ASP_E_ASPSM_BEAT_ACK:
		/* FIXME: stop timer, if any */
		break;
	default:
		break;
	}
}

static int xua_asp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	/* We don't use the fsm timer, so any calls to this are an error */
	OSMO_ASSERT(0);
	return 0;
}

static void xua_asp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;

	osmo_timer_del(&xafp->t_ack.timer);
}

static const struct osmo_fsm_state xua_asp_states[] = {
	[XUA_ASP_S_DOWN] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_UP_REQ) |
				 S(XUA_ASP_E_ASPSM_ASPUP) |
				 S(XUA_ASP_E_ASPSM_ASPUP_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPDN) |
				 S(XUA_ASP_E_SCTP_EST_IND),
		.out_state_mask = S(XUA_ASP_S_INACTIVE),
		.name = "ASP_DOWN",
		.action = xua_asp_fsm_down,
		.onenter = xua_asp_fsm_down_onenter,
	},
	[XUA_ASP_S_INACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_ACTIVE_REQ) |
				 S(XUA_ASP_E_M_ASP_DOWN_REQ) |
				 S(XUA_ASP_E_ASPTM_ASPAC) |
				 S(XUA_ASP_E_ASPTM_ASPAC_ACK) |
				 S(XUA_ASP_E_ASPTM_ASPIA) |
				 S(XUA_ASP_E_ASPSM_ASPDN) |
				 S(XUA_ASP_E_ASPSM_ASPDN_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPUP),
		.out_state_mask = S(XUA_ASP_S_DOWN) |
				  S(XUA_ASP_S_ACTIVE),
		.name = "ASP_INACTIVE",
		.action = xua_asp_fsm_inactive,
		.onenter = xua_asp_fsm_inactive_onenter,
	},
	[XUA_ASP_S_ACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_ASPSM_ASPDN) |
				 S(XUA_ASP_E_ASPSM_ASPDN_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPUP) |
				 S(XUA_ASP_E_ASPTM_ASPIA) |
				 S(XUA_ASP_E_ASPTM_ASPIA_ACK) |
				 S(XUA_ASP_E_ASPTM_ASPAC) |
				 S(XUA_ASP_E_M_ASP_DOWN_REQ) |
				 S(XUA_ASP_E_M_ASP_INACTIVE_REQ),
		.out_state_mask = S(XUA_ASP_S_INACTIVE) |
				  S(XUA_ASP_S_DOWN),
		.name = "ASP_ACTIVE",
		.action = xua_asp_fsm_active,
		.onenter = xua_asp_fsm_active_onenter,
	},
};


struct osmo_fsm xua_asp_fsm = {
	.name = "XUA_ASP",
	.states = xua_asp_states,
	.num_states = ARRAY_SIZE(xua_asp_states),
	.timer_cb = xua_asp_fsm_timer_cb,
	.log_subsys = DLSS7,
	.event_names = xua_asp_event_names,
	.allstate_event_mask = S(XUA_ASP_E_SCTP_COMM_DOWN_IND) |
			       S(XUA_ASP_E_SCTP_RESTART_IND) |
			       S(XUA_ASP_E_ASPSM_BEAT) |
			       S(XUA_ASP_E_ASPSM_BEAT_ACK),
	.allstate_action = xua_asp_allstate,
	.cleanup = xua_asp_fsm_cleanup,
};

static struct osmo_fsm_inst *ipa_asp_fsm_start(struct osmo_ss7_asp *asp,
					enum xua_asp_role role, int log_level);

/*! \brief Start a new ASP finite stae machine for given ASP
 *  \param[in] asp Application Server Process for which to start FSM
 *  \param[in] role Role (ASP, SG, IPSP) of this FSM
 *  \param[in] log_level Logging Level for ASP FSM logging
 *  \returns FSM instance on success; NULL on error */
struct osmo_fsm_inst *xua_asp_fsm_start(struct osmo_ss7_asp *asp,
					enum xua_asp_role role, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct xua_asp_fsm_priv *xafp;

	if (asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
		return ipa_asp_fsm_start(asp, role, log_level);

	/* allocate as child of AS? */
	fi = osmo_fsm_inst_alloc(&xua_asp_fsm, asp, NULL, log_level, asp->cfg.name);

	xafp = talloc_zero(fi, struct xua_asp_fsm_priv);
	if (!xafp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	xafp->role = role;
	xafp->asp = asp;

	fi->priv = xafp;

	return fi;
}





/***********************************************************************
 * IPA Compatibility FSM
 ***********************************************************************/

/* The idea here is to have a FSM that handles an IPA / SCCPlite link in
 * a way that the higher-layer code considers it the same like an M3UA
 * or SUA link.  We have a couple of different states and some
 * additional events. */

enum ipa_asp_state {
	IPA_ASP_S_DOWN = XUA_ASP_S_DOWN,
	IPA_ASP_S_ACTIVE = XUA_ASP_S_ACTIVE,
	IPA_ASP_S_WAIT_ID_RESP,		/* Waiting for ID_RESP from peer */
	IPA_ASP_S_WAIT_ID_GET,		/* Waiting for ID_GET from peer */
	IPA_ASP_S_WAIT_ID_ACK,		/* Waiting for ID_ACK from peer */
	IPA_ASP_S_WAIT_ID_ACK2,		/* Waiting for ID_ACK (of ACK) from peer */
};

/* private data structure for each FSM instance */
struct ipa_asp_fsm_priv {
	/* pointer back to ASP to which we belong */
	struct osmo_ss7_asp *asp;
	/* Role (ASP/SG/IPSP) */
	enum xua_asp_role role;

	/* Structure holding parsed data of the IPA CCM ID exchange */
	struct ipaccess_unit *ipa_unit;
	/* Timer for tracking if no PONG is received in response to PING */
	struct osmo_timer_list pong_timer;
};

enum ipa_asp_fsm_t {
	T_WAIT_ID_RESP	= 1,
	T_WAIT_ID_ACK,
	T_WAIT_ID_GET,
};

/* get the file descriptor related to a given ASP */
static int get_fd_from_iafp(struct ipa_asp_fsm_priv *iafp)
{
	struct osmo_ss7_asp *asp = iafp->asp;
	struct osmo_fd *ofd;

	if (asp->server)
		ofd = osmo_stream_srv_get_ofd(asp->server);
	else if (asp->client)
		ofd = osmo_stream_cli_get_ofd(asp->client);
	else
		return -1;

	return ofd->fd;
}

/* Server + Client: Initial State, wait for M-ASP-UP.req */
static void ipa_asp_fsm_down(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	int fd = get_fd_from_iafp(iafp);

	switch (event) {
	case XUA_ASP_E_M_ASP_UP_REQ:
	case XUA_ASP_E_SCTP_EST_IND:
		if (iafp->role == XUA_ASPFSM_ROLE_SG) {
			/* Server: Transmit IPA ID GET + Wait for Response */
			if (fd >= 0) {
				ipa_ccm_send_id_req(fd);
				osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_RESP, 10, T_WAIT_ID_RESP);
			}
		} else {
			/* Client: We simply wait for an ID GET */
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_GET, 10, T_WAIT_ID_GET);
		}
		break;
	}
}

/* Server: We're waiting for an ID RESP */
static void ipa_asp_fsm_wait_id_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	int fd = get_fd_from_iafp(iafp);
	struct osmo_ss7_as *as;
	struct tlv_parsed tp;
	struct msgb *msg;
	int rc;

	switch (event) {
	case IPA_ASP_E_ID_RESP:
		/* resolve the AS based on the identity provided by peer. */
		msg = data;
			rc = ipa_ccm_idtag_parse(&tp, msgb_l2(msg)+2, msgb_l2len(msg)-2);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "Error %d parsing ID_RESP TLV: %s\n", rc,
				 msgb_hexdump(msg));
			goto out_err;
		}
		rc = ipa_ccm_tlv_to_unitdata(iafp->ipa_unit, &tp);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "Error %d parsing ID_RESP: %s\n", rc, msgb_hexdump(msg));
			goto out_err;
		}
		if (!iafp->ipa_unit->unit_name) {
			LOGPFSML(fi, LOGL_NOTICE, "No Unit Name specified by client\n");
			goto out_err;
		}
		as = osmo_ss7_as_find_by_name(asp->inst, iafp->ipa_unit->unit_name);
		if (!as) {
			LOGPFSML(fi, LOGL_NOTICE, "Cannot find any definition for IPA Unit Name '%s'\n",
				iafp->ipa_unit->unit_name);
			goto out_err;
		}
		osmo_ss7_as_add_asp(as, asp->cfg.name);
		/* TODO: OAP Authentication? */
		/* Send ID_ACK */
		if (fd >= 0) {
			ipaccess_send_id_ack(fd);
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_ACK2, 10, T_WAIT_ID_ACK);
		}
		break;
	}
	return;
out_err:
	osmo_ss7_asp_disconnect(asp);
	return;
}

/* Server: We're waiting for an ID ACK */
static void ipa_asp_fsm_wait_id_ack2(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	struct osmo_ss7_instance *inst = asp->inst;
	struct osmo_ss7_as *as = osmo_ss7_as_find_by_rctx(inst, 0);

	OSMO_ASSERT(as);

	switch (event) {
	case IPA_ASP_E_ID_ACK:
		/* ACK received, we can go to active state now.  The
		 * ACTIVE onenter function will inform the AS */
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_ACTIVE, 0, 0);
		/* As opposed to M3UA, there is no RKM and we have to implicitly automatically add
		 * a route once an IPA connection has come up */
		osmo_ss7_route_create(inst->rtable_system, as->cfg.routing_key.pc, 0xffffff,
				      as->cfg.name);
		break;
	}
}

/* Client: We're waiting for an ID GET */
static void ipa_asp_fsm_wait_id_get(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	struct msgb *msg_get, *msg_resp;
	const uint8_t *req_data;
	int data_len;

	switch (event) {
	case IPA_ASP_E_ID_GET:
		msg_get = data;
		req_data = msgb_l2(msg_get)+1;
		data_len = msgb_l2len(msg_get)-1;
		LOGPFSM(fi, "Received IPA CCM IDENTITY REQUEST for IEs %s\n",
			osmo_hexdump(req_data, data_len));
		/* avoid possible unsigned integer underflow, as ipa_ccm_make_id_resp_from_req()
		 * expects an unsigned integer, and in case of a zero-length L2 message we might
		 * have data_len == -1 here */
		if (data_len < 0)
			data_len = 0;
		/* Send ID_RESP to server */
		msg_resp = ipa_ccm_make_id_resp_from_req(iafp->ipa_unit, req_data, data_len);
		if (!msg_resp) {
			LOGPFSML(fi, LOGL_ERROR, "Error building IPA CCM IDENTITY RESPONSE\n");
			break;
		}
		osmo_ss7_asp_send(asp, msg_resp);
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_ACK, 10, T_WAIT_ID_ACK);
		break;
	}
}

/* Client: We're waiting for an ID ACK */
static void ipa_asp_fsm_wait_id_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	int fd;

	switch (event) {
	case IPA_ASP_E_ID_ACK:
		/* Send ACK2 to server */
		fd = get_fd_from_iafp(iafp);
		if (fd >= 0) {
			ipaccess_send_id_ack(fd);
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_ACTIVE, 0, 0);
		}
		break;
	}
}


/* Server + Client: We're actively transmitting user data */
static void ipa_asp_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case XUA_ASP_E_M_ASP_DOWN_REQ:
	case XUA_ASP_E_M_ASP_INACTIVE_REQ:
		/* FIXME: kill ASP and (wait for) re-connect */
		break;
	}
}

static void ipa_asp_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	int fd;

	switch (event) {
	case XUA_ASP_E_SCTP_COMM_DOWN_IND:
	case XUA_ASP_E_SCTP_RESTART_IND:
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_BEAT:
		/* PING -> PONG */
		fd = get_fd_from_iafp(iafp);
		if (fd >= 0)
			ipaccess_send_pong(fd);
		break;
	case XUA_ASP_E_ASPSM_BEAT_ACK:
		/* stop timer, if any */
		osmo_timer_del(&iafp->pong_timer);
		break;
	default:
		break;
	}
}

static void ipa_asp_fsm_active_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_INACTIVE_IND);
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_ACTIVE_IND);
}

static void ipa_pong_timer_cb(void *_fi)
{
	struct osmo_fsm_inst *fi = _fi;
	struct ipa_asp_fsm_priv *iafp = fi->priv;

	LOGPFSML(fi, LOGL_NOTICE, "Peer didn't respond to PING? with PONG!\n");
	/* kill ASP and (wait for) re-connect */
	osmo_ss7_asp_disconnect(iafp->asp);
}

static int ipa_asp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;

	LOGPFSML(fi, LOGL_ERROR, "Timeout waiting for peer response\n");
	/* kill ASP and (wait for) re-connect */
	osmo_ss7_asp_disconnect(iafp->asp);
	return -1;
}

static const struct osmo_fsm_state ipa_asp_states[] = {
	[IPA_ASP_S_DOWN] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_UP_REQ) |
				 S(XUA_ASP_E_SCTP_EST_IND),
		.out_state_mask = S(IPA_ASP_S_WAIT_ID_GET) |
				  S(IPA_ASP_S_WAIT_ID_RESP),
		.name = "ASP_DOWN",
		.action = ipa_asp_fsm_down,
		.onenter = xua_asp_fsm_down_onenter,
	},
	/* Server Side */
	[IPA_ASP_S_WAIT_ID_RESP] = {
		.in_event_mask = S(IPA_ASP_E_ID_RESP),
		.out_state_mask = S(IPA_ASP_S_WAIT_ID_ACK2) |
				  S(IPA_ASP_S_DOWN),
		.name = "WAIT_ID_RESP",
		.action = ipa_asp_fsm_wait_id_resp,
	},
	/* Server Side */
	[IPA_ASP_S_WAIT_ID_ACK2] = {
		.in_event_mask = S(IPA_ASP_E_ID_ACK),
		.out_state_mask = S(IPA_ASP_S_ACTIVE) |
				  S(IPA_ASP_S_DOWN),
		.name = "WAIT_ID_ACK2",
		.action = ipa_asp_fsm_wait_id_ack2,
	},
	/* Client Side */
	[IPA_ASP_S_WAIT_ID_GET] = {
		.in_event_mask = S(IPA_ASP_E_ID_GET),
		.out_state_mask = S(IPA_ASP_S_WAIT_ID_ACK),
		.name = "WAIT_ID_GET",
		.action = ipa_asp_fsm_wait_id_get,
	},
	/* Client Side */
	[IPA_ASP_S_WAIT_ID_ACK] = {
		.in_event_mask = S(IPA_ASP_E_ID_ACK),
		.out_state_mask = S(IPA_ASP_S_ACTIVE) |
				  S(IPA_ASP_S_DOWN),
		.name = "WAIT_ID_ACK",
		.action = ipa_asp_fsm_wait_id_ack,
	},
	[IPA_ASP_S_ACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_DOWN_REQ) |
				 S(XUA_ASP_E_M_ASP_INACTIVE_REQ),
		.out_state_mask = S(XUA_ASP_S_INACTIVE) |
				  S(XUA_ASP_S_DOWN),
		.name = "ASP_ACTIVE",
		.action = ipa_asp_fsm_active,
		.onenter = ipa_asp_fsm_active_onenter,
	},
};

static void ipa_asp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	struct osmo_ss7_instance *inst = asp->inst;
	struct osmo_ss7_as *as = osmo_ss7_as_find_by_rctx(inst, 0);
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(as);

	/* find the route which we have created if we ever reached ipa_asp_fsm_wait_id_ack2 */
	rt = osmo_ss7_route_find_dpc_mask(inst->rtable_system, as->cfg.routing_key.pc, 0xffffff);
	/* no route found, bail out */
	if (!rt)
		return;
	/* route points to different AS, bail out */
	if (rt->dest.as != as)
		return;

	osmo_ss7_route_destroy(rt);
	osmo_timer_del(&iafp->pong_timer);
}

struct osmo_fsm ipa_asp_fsm = {
	.name = "IPA_ASP",
	.states = ipa_asp_states,
	.num_states = ARRAY_SIZE(ipa_asp_states),
	.timer_cb = ipa_asp_fsm_timer_cb,
	.log_subsys = DLSS7,
	.event_names = xua_asp_event_names,
	.allstate_event_mask = S(XUA_ASP_E_SCTP_COMM_DOWN_IND) |
			       S(XUA_ASP_E_SCTP_RESTART_IND) |
			       S(XUA_ASP_E_ASPSM_BEAT) |
			       S(XUA_ASP_E_ASPSM_BEAT_ACK),
	.allstate_action = ipa_asp_allstate,
	.cleanup = ipa_asp_fsm_cleanup,
};


/*! \brief Start a new ASP finite stae machine for given ASP
 *  \param[in] asp Application Server Process for which to start FSM
 *  \param[in] role Role (ASP, SG, IPSP) of this FSM
 *  \param[in] log_level Logging Level for ASP FSM logging
 *  \returns FSM instance on success; NULL on error */
static struct osmo_fsm_inst *ipa_asp_fsm_start(struct osmo_ss7_asp *asp,
					enum xua_asp_role role, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct ipa_asp_fsm_priv *iafp;

	/* allocate as child of AS? */
	fi = osmo_fsm_inst_alloc(&ipa_asp_fsm, asp, NULL, log_level, asp->cfg.name);

	iafp = talloc_zero(fi, struct ipa_asp_fsm_priv);
	if (!iafp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	iafp->role = role;
	iafp->asp = asp;
	iafp->ipa_unit = talloc_zero(iafp, struct ipaccess_unit);
	iafp->ipa_unit->unit_name = talloc_strdup(iafp->ipa_unit, asp->cfg.name);
	iafp->pong_timer.cb = ipa_pong_timer_cb;
	iafp->pong_timer.data = fi;

	fi->priv = iafp;

	if (role == XUA_ASPFSM_ROLE_ASP)
		osmo_fsm_inst_dispatch(fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);

	return fi;
}
