/* SCCP Routing Control (SCRC) according to ITU-T Q.714 */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights reserved
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
 *
 */

#include <stdbool.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>

#include <sccp/sccp_types.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "sccp_internal.h"
#include "xua_internal.h"

/***********************************************************************
 * Helper Functions
 ***********************************************************************/

static bool sua_is_connectionless(struct xua_msg *xua)
{
	if (xua->hdr.msg_class == SUA_MSGC_CL)
		return true;
	else
		return false;
}

static bool sua_is_cr(struct xua_msg *xua)
{
	if (xua->hdr.msg_class == SUA_MSGC_CO &&
	    xua->hdr.msg_type == SUA_CO_CORE)
		return true;

	return false;
}

static bool dpc_accessible(struct osmo_sccp_instance *inst, uint32_t pc)
{
	/* TODO: implement this! */
	return true;
}

static bool sccp_available(struct osmo_sccp_instance *inst,
			   const struct osmo_sccp_addr *addr)
{
	/* TODO: implement this! */
	return true;
}

static int sua2sccp_tx_m3ua(struct osmo_sccp_instance *inst,
			    struct xua_msg *sua)
{
	struct msgb *msg;
	struct osmo_mtp_prim *omp;
	struct osmo_mtp_transfer_param *param;
	struct osmo_ss7_instance *s7i = inst->ss7;
	uint32_t remote_pc = sua->mtp.dpc;

	/* 1) encode the SUA in xua_msg to SCCP message */
	msg = osmo_sua_to_sccp(sua);
	if (!msg) {
		LOGP(DLSCCP, LOGL_ERROR, "Cannot encode SUA to SCCP\n");
		return -1;
	}

	/* 2) wrap into MTP-TRANSFER.req primtiive */
	msg->l2h = msg->data;
	omp = (struct osmo_mtp_prim *) msgb_push(msg, sizeof(*omp));
	osmo_prim_init(&omp->oph, MTP_SAP_USER,
			OSMO_MTP_PRIM_TRANSFER, PRIM_OP_REQUEST, msg);
	param = &omp->u.transfer;
	if (sua->mtp.opc)
		param->opc = sua->mtp.opc;
	else
		param->opc = s7i->cfg.primary_pc;
	param->dpc = remote_pc;
	param->sls = sua->mtp.sls;
	param->sio = MTP_SIO(MTP_SI_SCCP, s7i->cfg.network_indicator);

	/* 3) send via MTP-SAP (osmo_ss7_instance) */
	return osmo_ss7_user_mtp_xfer_req(s7i, omp);
}

/* Gererate MTP-TRANSFER.req from xUA message */
static int gen_mtp_transfer_req_xua(struct osmo_sccp_instance *inst,
				    struct xua_msg *xua,
				    const struct osmo_sccp_addr *called)
{
	struct osmo_ss7_route *rt;

	/* this is a bit fishy due to the different requirements of
	 * classic SSCP/MTP compared to various SIGTRAN stackings.
	 * Normally, we would expect a fully encoded SCCP message here,
	 * but then if the route points to a SUA link, we actually need
	 * the SUA version of the message.
	 *
	 * We need to differentiate the following cases:
	 * a) SUA: encode XUA to SUA and send via ASP
	 * b) M3UA: encode XUA to SCCP, create MTP-TRANSFER.req
	 *    primitive and send it via ASP
	 * c) M2UA/M2PA or CS7: encode XUA, create MTP-TRANSFER.req
	 *    primitive and send it via link
	 */

	if (called->presence & OSMO_SCCP_ADDR_T_PC)
		xua->mtp.dpc = called->pc;
	if (!xua->mtp.dpc) {
		LOGP(DLSCCP, LOGL_ERROR, "MTP-TRANSFER.req from SCCP "
			"without DPC?!?\n");
		return -1;
	}

	rt = osmo_ss7_route_lookup(inst->ss7, xua->mtp.dpc);
	if (!rt) {
		LOGP(DLSCCP, LOGL_ERROR, "MTP-TRANSFER.req from SCCP for "
			"DPC %u: no route!\n", xua->mtp.dpc);
		return -1;
	}

	if (rt->dest.as) {
		struct osmo_ss7_as *as = rt->dest.as;
		switch (as->cfg.proto) {
		case OSMO_SS7_ASP_PROT_SUA:
			return sua_tx_xua_as(as, xua);
		case OSMO_SS7_ASP_PROT_M3UA:
		case OSMO_SS7_ASP_PROT_IPA:
			return sua2sccp_tx_m3ua(inst, xua);
		default:
			LOGP(DLSCCP, LOGL_ERROR, "MTP-TRANSFER.req for "
				"unknown protocol %u\n", as->cfg.proto);
			break;
		}
	} else if (rt->dest.linkset) {
		LOGP(DLSCCP, LOGL_ERROR, "MTP-TRANSFER.req from SCCP for "
			"linkset %s unsupported\n", rt->dest.linkset->cfg.name);
	} else {
		OSMO_ASSERT(0);
	}
	return -1;
}

/***********************************************************************
 * Global Title Translation
 ***********************************************************************/

static int translate(struct osmo_sccp_instance *inst,
		     const struct osmo_sccp_addr *called,
		     struct osmo_sccp_addr *translated)
{
	/* TODO: implement this! */
	*translated = *called;
	return 0;
}


/***********************************************************************
 * Individual SCRC Nodes
 ***********************************************************************/

static int scrc_local_out_common(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua,
				 const struct osmo_sccp_addr *called);

static int scrc_node_12(struct osmo_sccp_instance *inst, struct xua_msg *xua,
			const struct osmo_sccp_addr *called)
{
	/* TODO: Determine restriction */
	/* TODO: Treat Calling Party Addr */
	/* TODO: Hop counter */
	/* MTP-TRANSFER.req to MTP */
	return gen_mtp_transfer_req_xua(inst, xua, called);
}

static int scrc_node_2(struct osmo_sccp_instance *inst, struct xua_msg *xua,
			const struct osmo_sccp_addr *called)
{
	/* Node 2 on Sheet 5, only CO */
	/* Is DPC accessible? */
	if (!dpc_accessible(inst, called->pc)) {
		/* Error: MTP Failure */
		/* Routing Failure SCRC -> SCOC */
		sccp_scoc_rx_scrc_rout_fail(inst, xua,
				SCCP_RETURN_CAUSE_MTP_FAILURE);
		return 0;
	}
	/* Is SCCP available? */
	if (!sccp_available(inst, called)) {
		/* Error: SCCP Failure */
		/* Routing Failure SCRC -> SCOC */
		sccp_scoc_rx_scrc_rout_fail(inst, xua,
				SCCP_RETURN_CAUSE_SCCP_FAILURE);
		return 0;
	}
	return scrc_node_12(inst, xua, called);
}

static int scrc_node_7(struct osmo_sccp_instance *inst,
			struct xua_msg *xua,
			const struct osmo_sccp_addr *called)
{
	/* Connection Oriented? */
	if (sua_is_connectionless(xua)) {
		/* TODO: Perform Capability Test */
		/* TODO: Canges Needed? */
		if (0) {
			/* Changes Needed -> SCLC */
			return 0;
		}
	} else {
		/* TODO: Coupling Required? */
		if (0) {
			/* Node 13 (Sheet 5) */
		}
	}
	return scrc_node_12(inst, xua, called);
}

/* Node 4 (Sheet 3) */
static int scrc_node_4(struct osmo_sccp_instance *inst,
		       struct xua_msg *xua, uint32_t return_cause)
{
	/* TODO: Routing Failure SCRC -> OMAP */
	if (sua_is_connectionless(xua)) {
		/* Routing Failure SCRC -> SCLC */
		sccp_sclc_rx_scrc_rout_fail(inst, xua, return_cause);
	} else {
		/* Routing Failure SCRC -> SCOC */
		sccp_scoc_rx_scrc_rout_fail(inst, xua, return_cause);
	}
	return 0;
}

static int scrc_translate_node_9(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua,
				 const struct osmo_sccp_addr *called)
{
	struct osmo_sccp_addr translated;
	int rc;

	/* Translate */
	rc = translate(inst, called, &translated);
	/* Node 9 (Sheet 3) */
	if (rc < 0) {
		/* Node 4 (Sheet 3) */
		return scrc_node_4(inst, xua,
				   SCCP_RETURN_CAUSE_NO_TRANSLATION);
	}
	/* Route on SSN? */
	if (translated.ri != OSMO_SCCP_RI_SSN_PC &&
	    translated.ri != OSMO_SCCP_RI_SSN_IP) {
		/* TODO: GT Routing */
		LOGP(DLSCCP, LOGL_NOTICE, "GT Routing not implemented yet\n");
		/* Node 7 (Sheet 5) */
		return scrc_node_7(inst, xua, called);
	}

	/* Check DPC resultant from GT translation */
	if (osmo_ss7_pc_is_local(inst->ss7, translated.pc)) {
		if (sua_is_connectionless(xua)) {
			/* CL_MSG -> SCLC */
			sccp_sclc_rx_from_scrc(inst, xua);
		} else {
			/* Node 1 (Sheet 3) */
			/* CO_MSG -> SCOC */
			sccp_scoc_rx_from_scrc(inst, xua);
		}
		return 0;
	} else {
		/* Availability already checked */
		/* Node 7 (Sheet 5) */
		return scrc_node_7(inst, xua, called);
	}
}

/* Node 6 (Sheet 3) */
static int scrc_node_6(struct osmo_sccp_instance *inst,
		       struct xua_msg *xua,
		       const struct osmo_sccp_addr *called)
{
	struct osmo_sccp_user *scu;
	/* it is not really clear that called->pc will be set to
	 * anything here, in the case of a SSN-only CalledAddr */
	scu = sccp_user_find(inst, called->ssn, called->pc);

	/* Is subsystem equipped? */
	if (!scu) {
		/* Error: unequipped user */
		return scrc_node_4(inst, xua,
				   SCCP_RETURN_CAUSE_UNEQUIPPED_USER);
	}
	/* Is subsystem available? */
	if (0 /* !subsys_available(scu) */) {
		/* Error: subsystem failure */
		/* TODO: SCRC -> SSPC */
		if (sua_is_connectionless(xua)) {
			/* Routing Failure SCRC -> SCLC */
			sccp_sclc_rx_scrc_rout_fail(inst, xua,
				SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE);
		} else {
			/* Routing Failure SCRC -> SCOC */
			sccp_scoc_rx_scrc_rout_fail(inst, xua,
				SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE);
		}
		return 0;
	}
	if (sua_is_connectionless(xua)) {
		/* CL_MSG -> SCLC */
		sccp_sclc_rx_from_scrc(inst, xua);
	} else {
		/* Node 1 (Sheet 3) */
		/* CO_MSG -> SCOC */
		sccp_scoc_rx_from_scrc(inst, xua);
	}
	return 0;
}

static int scrc_local_out_common(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua,
				 const struct osmo_sccp_addr *called)
{
	struct osmo_ss7_instance *s7i = inst->ss7;

	/* Called address includes DPC? */
	if (called->presence & OSMO_SCCP_ADDR_T_PC) {
		if (!osmo_ss7_pc_is_local(s7i, called->pc)) {
			/* Node 7 of sheet 5 */
			/* Coupling required: no */
			return scrc_node_12(inst, xua, called);
		}
		/* Called address includes SSN? */
		if (called->presence & OSMO_SCCP_ADDR_T_SSN) {
			if (translate &&
			    (called->presence & OSMO_SCCP_ADDR_T_GT))
				return scrc_translate_node_9(inst, xua, called);
			else
				return scrc_node_6(inst, xua, called);
		}
	}
	/* No SSN in CalledAddr or no DPC included */
	if (!(called->presence & OSMO_SCCP_ADDR_T_GT)) {
		/* Error reason: Unqualified */
		/* TODO: Routing Failure SCRC -> OMAP */
		/* Node 4 (Sheet 3) */
		return scrc_node_4(inst, xua,
				   SCCP_RETURN_CAUSE_UNQUALIFIED);
	} else
		return scrc_translate_node_9(inst, xua, called);
}

/***********************************************************************
 * Entrance points from MTP, SCLC, SCOC, ...
 ***********************************************************************/

/* Figure C.1/Q.714 - SCCP Routing control procedures (SCRC) */

/* Connection oriented message SCOC -> SCRC */
int sccp_scrc_rx_scoc_conn_msg(struct osmo_sccp_instance *inst,
				struct xua_msg *xua)
{
	struct osmo_sccp_addr called;

	LOGP(DLSS7, LOGL_DEBUG, "%s: %s\n", __func__, xua_msg_dump(xua, &xua_dialect_sua));

	sua_addr_parse(&called, xua, SUA_IEI_DEST_ADDR);

	/* Is this a CR message ? */
	if (xua->hdr.msg_type != SUA_CO_CORE)
		return scrc_node_2(inst, xua, &called);

	/* TOOD: Coupling performed (not supported) */
	if (0) {
		return scrc_node_2(inst, xua, &called);
	}

	return scrc_local_out_common(inst, xua, &called);
}

/* Connectionless Message SCLC -> SCRC */
int sccp_scrc_rx_sclc_msg(struct osmo_sccp_instance *inst,
			  struct xua_msg *xua)
{
	struct osmo_sccp_addr called;

	LOGP(DLSS7, LOGL_DEBUG, "%s: %s\n", __func__, xua_msg_dump(xua, &xua_dialect_sua));

	sua_addr_parse(&called, xua, SUA_IEI_DEST_ADDR);

	/* Message Type */
	if (xua->hdr.msg_type == SUA_CL_CLDR) {
		/* UDTS, XUDTS or LUDTS */
		if (called.ri != OSMO_SCCP_RI_GT)
			return scrc_node_7(inst, xua, &called);
		/* Fall-through */
	} else {
		if (0 /* TODO: translation already performed */) {
			/* Node 12 (Sheet 5) */
			return scrc_node_12(inst, xua, &called);
		}
	}

	return scrc_local_out_common(inst, xua, &called);
}

/* Figure C.1/Q.714 Sheet 1 of 12, after we converted the
 * MTP-TRANSFER.ind to SUA */
int scrc_rx_mtp_xfer_ind_xua(struct osmo_sccp_instance *inst,
			     struct xua_msg *xua)
{
	struct osmo_sccp_addr called;
	uint32_t proto_class;
	struct xua_msg_part *hop_ctr_part;

	LOGP(DLSS7, LOGL_DEBUG, "%s: %s\n", __func__, xua_msg_dump(xua, &xua_dialect_sua));
	/* TODO: SCCP or nodal congestion? */

	/* CR or CL message? */
	if (!sua_is_connectionless(xua) && !sua_is_cr(xua)) {
		/* Node 1 (Sheet 3) */
		/* deliver to SCOC */
		sccp_scoc_rx_from_scrc(inst, xua);
		return 0;
	}
	/* We only treat connectionless and CR below */

	sua_addr_parse(&called, xua, SUA_IEI_DEST_ADDR);

	/* Route on GT? */
	if (called.ri != OSMO_SCCP_RI_GT) {
		/* Node 6 (Sheet 3) */
		return scrc_node_6(inst, xua, &called);
	}
	/* Message with hop-counter? */
	hop_ctr_part = xua_msg_find_tag(xua, SUA_IEI_S7_HOP_CTR);
	if (hop_ctr_part) {
		uint32_t hop_counter = xua_msg_part_get_u32(hop_ctr_part);
		if (hop_counter <= 1) {
			/* Error: hop-counter violation */
			/* node 4 */
			return scrc_node_4(inst, xua, SCCP_RETURN_CAUSE_HOP_COUNTER_VIOLATION);
		}
		/* Decrement hop-counter */
		hop_counter--;
		*(uint32_t *)hop_ctr_part->dat = htonl(hop_counter);
	}

	/* node 3 (Sheet 2) */
	/* Protocol class 0? */
	proto_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	switch (proto_class) {
	case 0:
		/* TODO: Assign SLS */
		break;
	case 1:
		/* TODO: Map incoming SLS to outgoing SLS */
		break;
	default:
		break;
	}
	return scrc_translate_node_9(inst, xua, &called);
}
