/* xUA Routing Key Management (RKM) as per RFC 4666 */
/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>
#include <arpa/inet.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_internal.h"
#include "xua_as_fsm.h"
#include "xua_asp_fsm.h"

const struct value_string m3ua_rkm_reg_status_vals[] = {
	{ M3UA_RKM_REG_SUCCESS,			"SUCCESS" },
	{ M3UA_RKM_REG_ERR_UNKNOWN,		"Unknown Error" },
	{ M3UA_RKM_REG_ERR_INVAL_DPC,		"Invalid Destination Pointcode" },
	{ M3UA_RKM_REG_ERR_INVAL_NET_APPEAR,	"Invalid Network Appearance" },
	{ M3UA_RKM_REG_ERR_INVAL_RKEY,		"Invalid Routing Key" },
	{ M3UA_RKM_REG_ERR_PERM_DENIED,		"Permission Denied" },
	{ M3UA_RKM_REG_ERR_CANT_SUPP_UNQ_RT,	"Cannot Support Unique Routing" },
	{ M3UA_RKM_REG_ERR_RKEY_NOT_PROVD,	"Routing Key Not Provided" },
	{ M3UA_RKM_REG_ERR_INSUFF_RESRC,	"Insufficient Resources" },
	{ M3UA_RKM_REG_ERR_UNSUPP_RK_PARAM,	"Unsupported Routing Key Parameter" },
	{ M3UA_RKM_REG_ERR_UNSUPP_TRAF_MODE,	"Unsupported Traffic Mode Type" },
	{ M3UA_RKM_REG_ERR_RKEY_CHG_REFUSED,	"Routing Key Change Refused" },
	{ M3UA_RKM_REG_ERR_RKEY_ALRDY_REGD,	"Routing Key Already Registered" },
	{ 0, NULL }
};

const struct value_string m3ua_rkm_dereg_status_vals[] = {
	{ M3UA_RKM_DEREG_SUCCESS,		"SUCCSS" },
	{ M3UA_RKM_DEREG_ERR_UNKNOWN,		"Unknown Error" },
	{ M3UA_RKM_DEREG_ERR_INVAL_RCTX,	"Invalid Routing Context" },
	{ M3UA_RKM_DEREG_ERR_PERM_DENIED,	"Permission Denied" },
	{ M3UA_RKM_DEREG_ERR_NOT_REGD,		"Error: Not Registered" },
	{ M3UA_RKM_DEREG_ERR_ASP_ACTIVE,	"Error: ASP Active" },
	{ 0, NULL }
};

/* push a M3UA header to the front of the given message */
static void msgb_push_m3ua_hdr(struct msgb *msg, uint8_t msg_class, uint8_t msg_type)
{
	struct xua_common_hdr *hdr;

	msg->l2h = msgb_push(msg, sizeof(*hdr));
	hdr = (struct xua_common_hdr *) msg->l2h;

	hdr->version = M3UA_VERSION;
	hdr->spare = 0;
	hdr->msg_class = msg_class;
	hdr->msg_type = msg_type;
	hdr->msg_length = htonl(msgb_l2len(msg));
}

/* SG: append a single registration result to given msgb */
static int msgb_append_reg_res(struct msgb *msg, uint32_t local_rk_id,
				uint32_t status, uint32_t rctx)
{
	uint8_t *old_tail = msg->tail;

	/* One individual Registration Result according to Chapter 3.6.2 */
	msgb_put_u16(msg, M3UA_IEI_REG_RESULT); /* outer IEI */
	msgb_put_u16(msg, 24 + 4); /* outer length */
	/* nested IEIs */
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_LOC_RKEY_ID, local_rk_id);
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_REG_STATUS, status);
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_ROUTE_CTX, rctx);

	return msg->tail - old_tail;
}

/* SG: append a single de-registration result to given msgb */
static int msgb_append_dereg_res(struct msgb *msg,
				 uint32_t status, uint32_t rctx)
{
	uint8_t *old_tail = msg->tail;

	/* One individual De-Registration Result according to Chapter 3.6.4 */
	msgb_put_u16(msg, M3UA_IEI_DEREG_RESULT); /* outer IEI */
	msgb_put_u16(msg, 16 + 4); /* outer length */
	/* nested IEIs */
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_ROUTE_CTX, rctx);
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_DEREG_STATUS, status);

	return msg->tail - old_tail;
}

/* ASP: send a RKM Registration Request message for a single routing key */
static void xua_rkm_send_reg_req(struct osmo_ss7_asp *asp,
				 const struct osmo_ss7_routing_key *rkey,
				 enum osmo_ss7_as_traffic_mode traf_mode)
{
	struct msgb *msg = m3ua_msgb_alloc(__func__);
	int tmod = osmo_ss7_tmode_to_xua(traf_mode);

	/* One individual Registration Request according to Chapter 3.6.1 */
	msgb_put_u16(msg, M3UA_IEI_ROUT_KEY); /* outer IEI */
	msgb_put_u16(msg, 32 + 4); /* outer length */
	/* nested IEIs */
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_LOC_RKEY_ID, rkey->l_rk_id);
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_ROUTE_CTX, rkey->context);
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_TRAF_MODE_TYP, tmod);
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_DEST_PC, rkey->pc);

	msgb_push_m3ua_hdr(msg, M3UA_MSGC_RKM, M3UA_RKM_REG_REQ);

	osmo_ss7_asp_send(asp, msg);
}

/* ASP: send a RKM De-Registration Request message for a single routing context */
static void xua_rkm_send_dereg_req(struct osmo_ss7_asp *asp, uint32_t route_ctx)
{
	struct msgb *msg = m3ua_msgb_alloc(__func__);

	/* One individual De-Registration Request according to Chapter 3.6.3 */
	msgb_t16l16vp_put_u32(msg, M3UA_IEI_ROUTE_CTX, route_ctx);

	msgb_push_m3ua_hdr(msg, M3UA_MSGC_RKM, M3UA_RKM_DEREG_REQ);

	osmo_ss7_asp_send(asp, msg);
}

/* maximum number of newly-assigned Application Servers in one dynamic
 * RKM REG request */
#define MAX_NEW_AS 16

/* SG: handle a single registration request IE (nested IEs in 'innner' */
static int handle_rkey_reg(struct osmo_ss7_asp *asp, struct xua_msg *inner,
			   struct msgb *resp, struct osmo_ss7_as **newly_assigned_as,
			   unsigned int max_nas_idx, unsigned int *nas_idx)
{
	uint32_t rk_id, rctx, _tmode, dpc;
	enum osmo_ss7_as_traffic_mode tmode;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route *rt;
	char namebuf[32];

	/* mandatory local routing key ID */
	rk_id = xua_msg_get_u32(inner, M3UA_IEI_LOC_RKEY_ID);
	/* ASP may already include a routing context value here */
	rctx = xua_msg_get_u32(inner, M3UA_IEI_ROUTE_CTX);

	/* traffic mode type (0 = undefined) */
	_tmode = xua_msg_get_u32(inner, M3UA_IEI_TRAF_MODE_TYP);
	if (xua_msg_find_tag(inner, M3UA_IEI_TRAF_MODE_TYP) && _tmode != M3UA_TMOD_OVERRIDE &&
	    _tmode != M3UA_TMOD_LOADSHARE && _tmode != M3UA_TMOD_BCAST) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: Invalid Traffic Mode %u\n", _tmode);
		msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_UNSUPP_TRAF_MODE, 0);
		return -1;
	}

	/* destination point code (mandatory) */
	dpc = xua_msg_get_u32(inner, M3UA_IEI_DEST_PC);

	/* We don't support routing keys with the following criteria, so
	 * we have to reject those */
	/* TODO: network appearance (optional) */
	/* TODO: service indicators (optional) */
	/* TODO: originating point code list (optional) */
	if (xua_msg_find_tag(inner, M3UA_IEI_NET_APPEAR) ||
	    xua_msg_find_tag(inner, M3UA_IEI_SVC_IND) ||
	    xua_msg_find_tag(inner, M3UA_IEI_ORIG_PC)) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: Unsupported Routing Key\n");
		msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_UNSUPP_RK_PARAM, 0);
		return -1;
	}

	/* if the ASP did not include a routing context number, allocate
	 * one locally (will be part of response) */
	if (!rctx)
		rctx = osmo_ss7_find_free_rctx(asp->inst);

	LOGPASP(asp, DLSS7, LOGL_INFO, "RKM: Registering routing key %u for DPC %s\n",
		rctx, osmo_ss7_pointcode_print(asp->inst, dpc));

	/* We have two cases here:
	 * a) pre-configured routing context on both ASP and SG: We will
	 *    find the AS based on the RCTX send by the client, check if
	 *    the routing key matches, associated AS with ASP and return
	 *    success.
	 * b) no routing context set on ASP, no pre-existing AS
	 *    definition on SG.  We have to create the AS, set the RK,
	 *    allocate the RCTX and return that RCTX to the client. This
	 *    is a slightly non-standard interpretation of M3UA RKM
	 *    which requires the SG to not have a-priori-knowledge of
	 *    all AS/RK in situations where the ASP are trusted.
	 */

	/* check if there is already an AS for this routing key */
	as = osmo_ss7_as_find_by_rctx(asp->inst, rctx);
	if (as) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: Found existing AS for RCTX %u\n", rctx);
		if (as->cfg.routing_key.pc != dpc) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "RKM: DPC doesn't match, rejecting AS (%u != %u)\n",
				as->cfg.routing_key.pc, dpc);
			msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_INVAL_RKEY, 0);
			return -1;
		}
		if (_tmode) {  /* if the peer has specified a traffic mode at all */
			tmode = osmo_ss7_tmode_from_xua(_tmode);
			if (!as->cfg.mode_set_by_peer && !as->cfg.mode_set_by_vty) {
				as->cfg.mode = tmode;
				LOGPAS(as, DLSS7, LOGL_INFO,
					"RKM: Traffic mode set dynamically by peer to %s\n",
					osmo_ss7_as_traffic_mode_name(as->cfg.mode));
			/* verify if existing AS has same traffic-mode as new request (if any) */
			} else if (!osmo_ss7_as_tmode_compatible_xua(as, _tmode)) {
				LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: Non-matching Traffic Mode %s\n",
					osmo_ss7_as_traffic_mode_name(tmode));
				msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_UNSUPP_TRAF_MODE, 0);
				return -1;
			}
			as->cfg.mode_set_by_peer = true;
		}
	} else if (asp->inst->cfg.permit_dyn_rkm_alloc) {
		/* Create an AS for this routing key */
		snprintf(namebuf, sizeof(namebuf), "as-rkm-%u", rctx);
		as = osmo_ss7_as_find_or_create(asp->inst, namebuf, OSMO_SS7_ASP_PROT_M3UA);
		if (!as) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "RKM: Cannot create AS %s\n", namebuf);
			msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_INSUFF_RESRC, 0);
			return -1;
		}

		as->cfg.description = talloc_strdup(as, "Auto-generated by RKM");
		as->rkm_dyn_allocated = true;
		if (!as->cfg.mode_set_by_vty && _tmode) {
			as->cfg.mode = osmo_ss7_tmode_from_xua(_tmode);
			as->cfg.mode_set_by_peer = true;
		}
		/* fill routing key */
		as->cfg.routing_key.pc = dpc;
		as->cfg.routing_key.context = rctx;

		/* add route for that routing key */
		rt = osmo_ss7_route_create(as->inst->rtable_system, dpc, 0xFFFFFF, namebuf);
		if (!rt) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "RKM: Cannot insert route for DPC %s / as %s\n",
				osmo_ss7_pointcode_print(asp->inst, dpc), namebuf);
			osmo_ss7_as_destroy(as);
			msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_CANT_SUPP_UNQ_RT, 0);
			return -1;
		}

		/* append to list of newly assigned as */
		if (*nas_idx >= max_nas_idx) {
			osmo_ss7_route_destroy(rt);
			osmo_ss7_as_destroy(as);
			LOGPASP(asp, DLSS7, LOGL_ERROR, "RKM: not enough room for newly assigned AS (max %u AS)\n",
				max_nas_idx+1);
			msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_INSUFF_RESRC, 0);
			return -1;
		}
		newly_assigned_as[(*nas_idx)++] = as;
	} else {
		/* not permitted to create dynamic RKM entries */
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: RCTX %u not found in configuration, and "
			"dynamic RKM allocation not permitted; permission denied\n", rctx);
		msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_PERM_DENIED, 0);
		return -1;
	}

	/* Success: Add just-create AS to connected ASP + report success */
	osmo_ss7_as_add_asp(as, asp->cfg.name);
	msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_SUCCESS, rctx);
	return 0;
}

/* SG: receive a registration request from ASP */
static int m3ua_rx_rkm_reg_req(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *part;
	struct msgb *resp = m3ua_msgb_alloc(__func__);
	struct osmo_ss7_as *newly_assigned_as[MAX_NEW_AS];
	unsigned int i, nas_idx = 0;

	memset(newly_assigned_as, 0, sizeof(newly_assigned_as));

	/* iterate over all routing key IEs in message */
	llist_for_each_entry(part, &xua->headers, entry) {
		struct xua_msg *inner;

		if (part->tag != M3UA_IEI_ROUT_KEY)
			continue;

		inner = xua_from_nested(part);
		if (!inner) {
			LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: Unable to parse "
				"nested IE for Routing Key\n");
			continue;
		}
		/* handle single registration and append result to
		 * 'resp' */
		handle_rkey_reg(asp, inner, resp, newly_assigned_as,
				ARRAY_SIZE(newly_assigned_as), &nas_idx);

		xua_msg_free(inner);
	}
	/* now first send the RKM REG Response */
	msgb_push_m3ua_hdr(resp, M3UA_MSGC_RKM, M3UA_RKM_REG_RSP);
	osmo_ss7_asp_send(asp, resp);

	/* and *after* the RKM REG Response inform the newly assigned
	 * ASs about the fact that there's an INACTIVE ASP for them,
	 * which will cause them to send NOTIFY to the client */
	for (i = 0; i < ARRAY_SIZE(newly_assigned_as); i++) {
		struct osmo_ss7_as *as = newly_assigned_as[i];
		if (!as)
			continue;
		/* Notify AS that it has an INACTIVE ASP */
		osmo_fsm_inst_dispatch(as->fi, XUA_ASPAS_ASP_INACTIVE_IND, asp);
	}

	return 0;
}

/* SG: handle a single routing key de-registration IE */
static int handle_rkey_dereg(struct osmo_ss7_asp *asp, uint32_t rctx,
			     struct msgb *resp)
{
	struct osmo_ss7_instance *inst = asp->inst;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route *rt;

	as = osmo_ss7_as_find_by_rctx(inst, rctx);
	if (!as) {
		msgb_append_dereg_res(resp, M3UA_RKM_DEREG_ERR_INVAL_RCTX, 0);
		return -1;
	}

	/* Reject if ASP is not even part of AS */
	if (!osmo_ss7_as_has_asp(as, asp)) {
		msgb_append_dereg_res(resp, M3UA_RKM_DEREG_ERR_INVAL_RCTX, 0);
		return -1;
	}

	/* Reject if ASP is still active */
	if (asp->fi->state == XUA_ASP_S_ACTIVE) {
		msgb_append_dereg_res(resp, M3UA_RKM_DEREG_ERR_ASP_ACTIVE, 0);
		return -1;
	}

	rt = osmo_ss7_route_find_dpc(inst->rtable_system, as->cfg.routing_key.pc);
	if (!rt) {
		msgb_append_dereg_res(resp, M3UA_RKM_DEREG_ERR_UNKNOWN, 0);
		return -1;
	}

	LOGPASP(asp, DLSS7, LOGL_INFO, "RKM: De-Registering rctx %u for DPC %s\n",
		rctx, osmo_ss7_pointcode_print(inst, as->cfg.routing_key.pc));

	/* remove ASP from AS */
	osmo_ss7_as_del_asp(as, asp->cfg.name);
	/* FIXME: Rather than spoofing teh ASP-DOWN.ind to the AS here,
	 * we should refuse RKM DEREG if the ASP is still ACTIVE */
	osmo_fsm_inst_dispatch(as->fi, XUA_ASPAS_ASP_DOWN_IND, asp);

	/* if we were dynamically allocated, release the associated
	 * route and destroy the AS */
	if (as->rkm_dyn_allocated) {
		/* remove route + AS definition */
		osmo_ss7_route_destroy(rt);
		osmo_ss7_as_destroy(as);
	}
	/* report success */
	msgb_append_dereg_res(resp, M3UA_RKM_DEREG_SUCCESS, rctx);

	return 0;
}

/* SG: receive a De-Registration request from ASP */
static int m3ua_rx_rkm_dereg_req(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *part = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	struct msgb *resp = m3ua_msgb_alloc(__func__);
	uint32_t *rctx;

	if (!part)
		return -1;

	for (rctx = (uint32_t *)part->dat; (uint8_t *)rctx < part->dat + part->len; rctx++)
		handle_rkey_dereg(asp, ntohl(*rctx), resp);

	msgb_push_m3ua_hdr(resp, M3UA_MSGC_RKM, M3UA_RKM_DEREG_RSP);
	osmo_ss7_asp_send(asp, resp);

	return 0;
}

/* ASP: handle a single registration response IE (nested IEs in 'inner') */
static int handle_rkey_reg_resp(struct osmo_ss7_asp *asp, struct xua_msg *inner)
{
	struct osmo_xlm_prim *oxp;

	if (!xua_msg_find_tag(inner, M3UA_IEI_LOC_RKEY_ID) ||
	    !xua_msg_find_tag(inner, M3UA_IEI_REG_STATUS) ||
	    !xua_msg_find_tag(inner, M3UA_IEI_ROUTE_CTX)) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Missing Inner IE in REG RESP\n");
		/* FIXME: ERROR to peer */
		return -1;
	}

	oxp = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_CONFIRM);
	if (!oxp)
		return -1;

	oxp->u.rk_reg.key.l_rk_id = xua_msg_get_u32(inner, M3UA_IEI_LOC_RKEY_ID);
	oxp->u.rk_reg.key.context = xua_msg_get_u32(inner, M3UA_IEI_ROUTE_CTX);
	oxp->u.rk_reg.status = xua_msg_get_u32(inner, M3UA_IEI_REG_STATUS);

	LOGPASP(asp, DLSS7, LOGL_INFO, "Received RKM REG RES rctx=%u status=%s\n",
		oxp->u.rk_reg.key.context,
		get_value_string(m3ua_rkm_reg_status_vals, oxp->u.rk_reg.status));

	/* Send primitive to LM */
	xua_asp_send_xlm_prim(asp, oxp);

	return 0;
}

/* ASP: receive a registration response (ASP role) */
static int m3ua_rx_rkm_reg_rsp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *part;
	struct xua_msg *inner = NULL;

	llist_for_each_entry(part, &xua->headers, entry) {
		/* skip other IEs and/or short REG_RES IEs */
		if (part->tag != M3UA_IEI_REG_RESULT || part->len < 24)
			continue;

		/* we leave the above loop at the first valid
		 * registration result (we only support one AS per ASP
		 * for now) */
		inner = xua_from_nested(part);
		if (!inner)
			continue;

		handle_rkey_reg_resp(asp, inner);
		xua_msg_free(inner);
	}
	return 0;
}

/* ASP: handle a single De-Registration response IE (nested IEs in 'inner' */
static int handle_rkey_dereg_resp(struct osmo_ss7_asp *asp, struct xua_msg *inner)
{
	struct osmo_xlm_prim *oxp;

	if (!xua_msg_find_tag(inner, M3UA_IEI_DEREG_STATUS) ||
	    !xua_msg_find_tag(inner, M3UA_IEI_ROUTE_CTX)) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Missing Inner IE in DEREG RESP\n");
		/* FIXME: ERROR to peer */
		return -1;
	}

	oxp = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_DEREG, PRIM_OP_CONFIRM);
	if (!oxp)
		return -1;

	oxp->u.rk_dereg.route_ctx = xua_msg_get_u32(inner, M3UA_IEI_ROUTE_CTX);
	oxp->u.rk_dereg.status = xua_msg_get_u32(inner, M3UA_IEI_DEREG_STATUS);

	LOGPASP(asp, DLSS7, LOGL_INFO, "Received RKM DEREG RES rctx=%u status=%s\n",
		oxp->u.rk_reg.key.context,
		get_value_string(m3ua_rkm_dereg_status_vals, oxp->u.rk_dereg.status));

	/* Send primitive to LM */
	xua_asp_send_xlm_prim(asp, oxp);

	return 0;
}

/* ASP: receive a De-Registration response */
static int m3ua_rx_rkm_dereg_rsp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *part;
	struct xua_msg *inner = NULL;

	llist_for_each_entry(part, &xua->headers, entry) {
		/* skip other IEs and/or short REG_RES IEs */
		if (part->tag != M3UA_IEI_DEREG_RESULT || part->len < 16)
			continue;

		/* we leave the above loop at the first valid
		 * registration result (we only support one AS per ASP
		 * for now) */
		inner = xua_from_nested(part);
		if (!inner)
			continue;

		handle_rkey_dereg_resp(asp, inner);
		xua_msg_free(inner);
	}
	return 0;
}

/* process an incoming RKM message in xua format */
int m3ua_rx_rkm(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	int rc;

	switch (xua->hdr.msg_type) {
	/* SG Side */
	case M3UA_RKM_REG_REQ:
		/* TOOD: ensure we are role SG */
		rc = m3ua_rx_rkm_reg_req(asp, xua);
		break;
	case M3UA_RKM_DEREG_REQ:
		/* TOOD: ensure we are role SG */
		rc = m3ua_rx_rkm_dereg_req(asp, xua);
		break;
	/* ASP Side */
	case M3UA_RKM_REG_RSP:
		/* TOOD: ensure we are role ASP */
		rc = m3ua_rx_rkm_reg_rsp(asp, xua);
		break;
	case M3UA_RKM_DEREG_RSP:
		/* TOOD: ensure we are role ASP */
		rc = m3ua_rx_rkm_dereg_rsp(asp, xua);
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Received unknown RKM msg_type %u\n",
			xua->hdr.msg_type);
		rc = -1;
		break;
	}
	return rc;
}

/* process a primitive from the xUA Layer Manager (LM) */
int osmo_xlm_sap_down(struct osmo_ss7_asp *asp, struct osmo_prim_hdr *oph)
{
	struct osmo_xlm_prim *prim = (struct osmo_xlm_prim *) oph;

	LOGPASP(asp, DLSS7, LOGL_DEBUG, "Received XUA Layer Manager Primitive: %s)\n",
		osmo_xlm_prim_name(&prim->oph));

	switch (OSMO_PRIM_HDR(&prim->oph)) {
	case OSMO_PRIM(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_REQUEST):
		/* Layer Manager asks us to send a Routing Key Reg Request */
		xua_rkm_send_reg_req(asp, &prim->u.rk_reg.key, prim->u.rk_reg.traf_mode);
		break;
	case OSMO_PRIM(OSMO_XLM_PRIM_M_RK_DEREG, PRIM_OP_REQUEST):
		/* Layer Manager asks us to send a Routing Key De-Reg Request */
		xua_rkm_send_dereg_req(asp, prim->u.rk_dereg.route_ctx);
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Unknown XUA Layer Manager Primitive: %s\n",
			osmo_xlm_prim_name(&prim->oph));
		break;
	}

	msgb_free(prim->oph.msg);
	return 0;
}

/* clean-up any dynamically created ASs + routes */
void xua_rkm_cleanup_dyn_as_for_asp(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_instance *inst = asp->inst;
	struct osmo_ss7_as *as, *as2;

	llist_for_each_entry_safe(as, as2, &inst->as_list, list) {
		if (!osmo_ss7_as_has_asp(as, asp))
			continue;
		/* FIXME: check if there are no other ASPs! */
		if (!as->rkm_dyn_allocated)
			continue;

		osmo_ss7_as_destroy(as);
	}
}
