/* SCCP M3UA / SUA ASP osmo_fsm according to RFC3868 4.3.1 */
/* (C) Copyright 2017 by Harald Welte <laforge@gnumonks.org>
 * 
 * All Rights reserved.
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

	{ XUA_ASP_E_ASPSM_ASPUP,	"ASPSM-ASP_UP" },
	{ XUA_ASP_E_ASPSM_ASPUP_ACK,	"ASPSM-ASP_UP_ACK" },
	{ XUA_ASP_E_ASPTM_ASPAC,	"ASPTM-ASP_AC" },
	{ XUA_ASP_E_ASPTM_ASPAC_ACK,	"ASPTM-ASP_AC_ACK" },
	{ XUA_ASP_E_ASPSM_ASPDN,	"ASPSM-ASP_DN" },
	{ XUA_ASP_E_ASPSM_ASPDN_ACK,	"ASPSM-ASP_DN_ACK" },
	{ XUA_ASP_E_ASPTM_ASPIA,	"ASPTM-ASP_IA" },
	{ XUA_ASP_E_ASPTM_ASPIA_ACK,	"ASPTM_ASP_IA_ACK" },
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
	struct osmo_xua_layer_manager *lm = asp->lm;

	if (lm && lm->prim_cb)
		lm->prim_cb(&prim->oph, asp);

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
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_UP,
				     PRIM_OP_CONFIRM);
		/* FIXME: This hack should be in layer manager? */
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

	if (xafp->role != XUA_ASPFSM_ROLE_SG)
		return;

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
		/* FIXME: Send ERROR message */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_INDICATION);
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

static const struct osmo_fsm_state xua_asp_states[] = {
	[XUA_ASP_S_DOWN] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_UP_REQ) |
				 S(XUA_ASP_E_ASPSM_ASPUP) |
				 S(XUA_ASP_E_ASPSM_ASPUP_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPDN),
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
};


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
