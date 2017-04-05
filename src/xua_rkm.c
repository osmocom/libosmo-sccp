/* xUA Routing Key Management (RKM) as per RFC 4666 */
/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
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

#include <arpa/inet.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_internal.h"

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

/* append a single registration result to given msgb */
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

/* append a single de-registration result to given msgb */
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

/* handle a single registration request IE (nested IEs in 'innner' */
static int handle_rkey_reg(struct osmo_ss7_asp *asp, struct xua_msg *inner,
			   struct msgb *resp)
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

	tmode = osmo_ss7_tmode_from_xua(_tmode);

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

	/* check if there is already an AS for this routing key */
	if (osmo_ss7_as_find_by_rctx(asp->inst, rctx)) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "RKM: RCTX %u already in use\n", rctx);
		msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_RKEY_ALRDY_REGD, 0);
		return -1;
	}

	/* Create an AS for this routing key */
	snprintf(namebuf, sizeof(namebuf), "as-rkm-%u", rctx);
	as = osmo_ss7_as_find_or_create(asp->inst, namebuf, OSMO_SS7_ASP_PROT_M3UA);
	if (!as) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "RKM: Cannot create AS %s\n", namebuf);
		msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_INSUFF_RESRC, 0);
		return -1;
	}

	as->cfg.description = talloc_strdup(as, "Auto-generated by RKM");
	as->cfg.mode = tmode;
	/* fill routing key */
	as->cfg.routing_key.context = rctx;
	as->cfg.routing_key.pc = dpc;

	/* add route for that routing key */
	rt = osmo_ss7_route_create(as->inst->rtable_system, dpc, 0xFFFFFF, namebuf);
	if (!rt) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "RKM: Cannot insert route for DPC %s / as %s\n",
			osmo_ss7_pointcode_print(asp->inst, dpc), namebuf);
		osmo_ss7_as_destroy(as);
		msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_ERR_CANT_SUPP_UNQ_RT, 0);
		return -1;
	}

	/* Success: Add just-create AS to connected ASP + report success */
	osmo_ss7_as_add_asp(as, asp->cfg.name);
	msgb_append_reg_res(resp, rk_id, M3UA_RKM_REG_SUCCESS, rctx);
	return 0;
}

/* receive a registration requuest (SG role) */
static int m3ua_rx_rkm_reg_req(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *part;
	struct msgb *resp = m3ua_msgb_alloc(__func__);

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
		handle_rkey_reg(asp, inner, resp);
	}
	msgb_push_m3ua_hdr(resp, M3UA_MSGC_RKM, M3UA_RKM_REG_RSP);
	osmo_ss7_asp_send(asp, resp);

	return 0;
}

/* receive a deregistration requuest (SG role) */
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

	/* FIXME Reject if any ASP stillactively using this RCTX */

	rt = osmo_ss7_route_find_dpc(inst->rtable_system, as->cfg.routing_key.pc);
	if (!rt) {
		msgb_append_dereg_res(resp, M3UA_RKM_DEREG_ERR_UNKNOWN, 0);
		return -1;
	}

	LOGPASP(asp, DLSS7, LOGL_INFO, "RKM: De-Registering rctx %u for DPC %s\n",
		rctx, osmo_ss7_pointcode_print(inst, as->cfg.routing_key.pc));

	/* remove route + AS definition */
	osmo_ss7_route_destroy(rt);
	osmo_ss7_as_destroy(as);
	/* report success */
	msgb_append_dereg_res(resp, M3UA_RKM_DEREG_SUCCESS, rctx);

	return 0;
}

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

/* receive a registration response (ASP role) */
static int m3ua_rx_rkm_reg_rsp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	/* TODO */
}

/* receive a deregistration response (ASP role) */
static int m3ua_rx_rkm_dereg_rsp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	/* TODO */
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
