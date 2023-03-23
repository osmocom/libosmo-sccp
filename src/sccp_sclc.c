/* SCCP Connectionless Control (SCLC) according to ITU-T Q.713/Q.714 */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights reserved
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
 *
 */

/* This code is a bit of a hybrid between the ITU-T Q.71x specifications
 * for SCCP (particularly its connection-oriented part), and the IETF
 * RFC 3868 (SUA).  The idea here is to have one shared code base of the
 * state machines for SCCP Connection Oriented, and use those both from
 * SCCP and SUA.
 *
 * To do so, all SCCP messages are translated to SUA messages in the
 * input side, and all generated SUA messages are translated to SCCP on
 * the output side.
 *
 * The Choice of going for SUA messages as the "native" format was based
 * on their easier parseability, and the fact that there are features in
 * SUA which classic SCCP cannot handle (like IP addresses in GT).
 * However, all SCCP features can be expressed in SUA.
 *
 * The code only supports Class 2.  No support for Class 3 is intended,
 * but patches are of course always welcome.
 *
 * Missing other features:
 *  * Segmentation/Reassembly support
 *  * T(guard) after (re)start
 *  * freezing of local references
 *  * parsing/encoding of IPv4/IPv6 addresses
 *  * use of multiple Routing Contexts in SUA case
 */

#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sccp/sccp_types.h>

#include "xua_internal.h"
#include "sccp_internal.h"

/* generate a 'struct xua_msg' of requested type from primitive data */
static struct xua_msg *xua_gen_msg_cl(uint32_t event,
				      struct osmo_scu_prim *prim, int msg_type)
{
	struct xua_msg *xua = xua_msg_alloc();
	struct osmo_scu_unitdata_param *udpar = &prim->u.unitdata;

	if (!xua)
		return NULL;

	switch (msg_type) {
	case SUA_CL_CLDT:
		xua->hdr = XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0); /* FIXME */
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, 0);
		xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &udpar->calling_addr);
		xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &udpar->called_addr);
		xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, udpar->in_sequence_control);
		/* optional: importance, ... correlation id? */
		if (!prim)
			goto prim_needed;
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));
		break;
	default:
		LOGP(DLSCCP, LOGL_ERROR, "Unknown msg_type %u\n", msg_type);
		xua_msg_free(xua);
		return NULL;
	}
	return xua;

prim_needed:
	xua_msg_free(xua);
	LOGP(DLSCCP, LOGL_ERROR, "%s must be called with valid 'prim' "
	     "pointer for msg_type=%u\n", __func__, msg_type);
	return NULL;
}

/* generate xua_msg, encode it and send it to SCRC */
static int xua_gen_encode_and_send(struct osmo_sccp_user *scu, uint32_t event,
				   struct osmo_scu_prim *prim, int msg_type)
{
	struct xua_msg *xua;
	int rc;

	xua = xua_gen_msg_cl(event, prim, msg_type);
	if (!xua)
		return -1;

	rc = sccp_scrc_rx_sclc_msg(scu->inst, xua);
	xua_msg_free(xua);
	return rc;
}

/*! Main entrance function for primitives from SCCP User.
 * The caller is required to free oph->msg, otherwise the same as sccp_sclc_user_sap_down().
 *  \param[in] scu SCCP User who is sending the primitive
 *  \param[on] oph Osmocom primitive header of the primitive
 *  \returns 0 on success; negative in case of error */
int sccp_sclc_user_sap_down_nofree(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;

	/* we get called from osmo_sccp_user_sap_down() which already
	 * has debug-logged the primitive */

	switch (OSMO_PRIM_HDR(&prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST):
		/* Connectionless by-passes this altogether */
		rate_ctr_inc2(scu->ctrg, SCU_CTR_CLDT_OUT_COUNT);
		rate_ctr_add2(scu->ctrg, SCU_CTR_CLDT_OUT_BYTES, msgb_l2len(prim->oph.msg));
		return xua_gen_encode_and_send(scu, -1, prim, SUA_CL_CLDT);
	default:
		LOGP(DLSCCP, LOGL_ERROR, "Received unknown SCCP User "
		     "primitive %s from user\n",
		     osmo_scu_prim_name(&prim->oph));
		return -1;
	}
}

/*! Main entrance function for primitives from SCCP User.
 * Implies a msgb_free(oph->msg), otherwise the same as sccp_sclc_user_sap_down_nofree().
 *  \param[in] scu SCCP User who is sending the primitive
 *  \param[on] oph Osmocom primitive header of the primitive
 *  \returns 0 on success; negative in case of error */
int sccp_sclc_user_sap_down(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct msgb *msg = prim->oph.msg;
	int rc = sccp_sclc_user_sap_down_nofree(scu, oph);
	msgb_free(msg);
	return rc;
}

/* Process an incoming CLDT message (from a remote peer) */
static int sclc_rx_cldt(struct osmo_sccp_instance *inst, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct osmo_scu_unitdata_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg = sccp_msgb_alloc(__func__);
	struct osmo_sccp_user *scu;
	uint32_t protocol_class;

	if (!data_ie) {
		LOGP(DLSCCP, LOGL_ERROR, "SCCP/SUA CLDT without user data?!?\n");
		return -1;
	}

	/* fill primitive */
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.unitdata;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_UNITDATA,
			PRIM_OP_INDICATION, upmsg);
	sua_addr_parse(&param->called_addr, xua, SUA_IEI_DEST_ADDR);
	sua_addr_parse(&param->calling_addr, xua, SUA_IEI_SRC_ADDR);
	param->in_sequence_control = xua_msg_get_u32(xua, SUA_IEI_SEQ_CTRL);
	protocol_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	param->return_option = protocol_class & 0x80;
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

	scu = sccp_user_find(inst, param->called_addr.ssn,
			     param->called_addr.pc);

	if (!scu) {
		/* FIXME: Send destination unreachable? */
		LOGP(DLSUA, LOGL_NOTICE, "Received SUA message for unequipped SSN %u\n",
			param->called_addr.ssn);
		msgb_free(upmsg);
		return 0;
	}

	rate_ctr_inc2(scu->ctrg, SCU_CTR_CLDT_IN_COUNT);
	rate_ctr_add2(scu->ctrg, SCU_CTR_CLDT_IN_BYTES, data_ie->len);

	/* copy data */
	upmsg->l2h = msgb_put(upmsg, data_ie->len);
	memcpy(upmsg->l2h, data_ie->dat, data_ie->len);

	/* send to user SAP */
	sccp_user_prim_up(scu, prim);

	/* xua_msg is free'd by our caller */
	return 0;
}

static int sclc_rx_cldr(struct osmo_sccp_instance *inst, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct osmo_scu_notice_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg = sccp_msgb_alloc(__func__);
	struct osmo_sccp_user *scu;

	if (!data_ie) {
		LOGP(DLSCCP, LOGL_ERROR, "SCCP/SUA CLDR without user data?!?\n");
		return -1;
	}

	/* fill primitive */
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.notice;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_NOTICE,
			PRIM_OP_INDICATION, upmsg);

	sua_addr_parse(&param->called_addr, xua, SUA_IEI_DEST_ADDR);
	sua_addr_parse(&param->calling_addr, xua, SUA_IEI_SRC_ADDR);
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
	param->cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE);

	scu = sccp_user_find(inst, param->called_addr.ssn,
			     param->called_addr.pc);
	if (!scu) {
		/* FIXME: Send destination unreachable? */
		LOGP(DLSUA, LOGL_NOTICE, "Received CLDR for unequipped SSN %u\n",
			param->called_addr.ssn);
		msgb_free(upmsg);
		return 0;
	}

	/* copy data */
	upmsg->l2h = msgb_put(upmsg, data_ie->len);
	memcpy(upmsg->l2h, data_ie->dat, data_ie->len);

	/* send to user SAP */
	sccp_user_prim_up(scu, prim);

	/* xua_msg is free'd by our caller */
	return 0;
}

/*! \brief SCRC -> SCLC (connectionless message)
 *  \param[in] inst SCCP Instance in which we operate
 *  \param[in] xua SUA connectionless message
 *  \returns 0 on success; negative on error */
int sccp_sclc_rx_from_scrc(struct osmo_sccp_instance *inst,
			   struct xua_msg *xua)
{
	int rc = -1;

	OSMO_ASSERT(xua->hdr.msg_class == SUA_MSGC_CL);

	switch (xua->hdr.msg_type) {
	case SUA_CL_CLDT:
		rc = sclc_rx_cldt(inst, xua);
		break;
	case SUA_CL_CLDR:
		rc = sclc_rx_cldr(inst, xua);
		break;
	default:
		LOGP(DLSUA, LOGL_NOTICE, "Received unknown/unsupported "
		     "message %s\n", xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}

	return rc;
}

/* generate a return/refusal message (SUA CLDR == SCCP UDTS) based on
 * the incoming message.  We need to flip all identities between sender
 * and receiver */
static struct xua_msg *gen_ret_msg(struct osmo_sccp_instance *inst,
				   const struct xua_msg *xua_in,
				   uint32_t ret_cause)
{
	struct xua_msg *xua_out = xua_msg_alloc();
	struct osmo_sccp_addr called;

	xua_out->hdr = XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDR);
	xua_msg_add_u32(xua_out, SUA_IEI_ROUTE_CTX, inst->route_ctx);
	xua_msg_add_u32(xua_out, SUA_IEI_CAUSE,
			SUA_CAUSE_T_RETURN | ret_cause);
	/* Swap Calling and Called Party */
	xua_msg_copy_part(xua_out, SUA_IEI_SRC_ADDR, xua_in, SUA_IEI_DEST_ADDR);
	xua_msg_copy_part(xua_out, SUA_IEI_DEST_ADDR, xua_in, SUA_IEI_SRC_ADDR);
	/* TODO: Optional: Hop Count */
	/* Optional: Importance */
	xua_msg_copy_part(xua_out, SUA_IEI_IMPORTANCE,
			  xua_in, SUA_IEI_IMPORTANCE);
	/* Optional: Message Priority */
	xua_msg_copy_part(xua_out, SUA_IEI_MSG_PRIO, xua_in, SUA_IEI_MSG_PRIO);
	/* Optional: Correlation ID */
	xua_msg_copy_part(xua_out, SUA_IEI_CORR_ID, xua_in, SUA_IEI_CORR_ID);
	/* Optional: Segmentation */
	xua_msg_copy_part(xua_out, SUA_IEI_SEGMENTATION,
			  xua_in, SUA_IEI_SEGMENTATION);
	/* Optional: Data */
	xua_msg_copy_part(xua_out, SUA_IEI_DATA, xua_in, SUA_IEI_DATA);

	sua_addr_parse(&called, xua_out, SUA_IEI_DEST_ADDR);
	/* Route on PC + SSN ? */
	if (called.ri == OSMO_SCCP_RI_SSN_PC) {
		/* if no PC, copy OPC into called addr */
		if (!(called.presence & OSMO_SCCP_ADDR_T_PC)) {
			struct osmo_sccp_addr calling;
			sua_addr_parse(&calling, xua_out, SUA_IEI_SRC_ADDR);
			called.presence |= OSMO_SCCP_ADDR_T_PC;
			called.pc = calling.pc;
			/* Re-encode / replace called address */
			xua_msg_free_tag(xua_out, SUA_IEI_DEST_ADDR);
			xua_msg_add_sccp_addr(xua_out, SUA_IEI_DEST_ADDR,
					      &called);
		}
	}
	return xua_out;
}

/*! \brief SCRC -> SCLC (Routing Failure
 *  \param[in] inst SCCP Instance in which we operate
 *  \param[in] xua_in Message that failed to be routed
 *  \param[in] cause SCCP Return Cause */
void sccp_sclc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua_in, uint32_t cause)
{
	struct xua_msg *xua_out;

	/* Figure C.12/Q.714 (Sheet 8) Node 9 */
	switch (xua_in->hdr.msg_type) {
	case SUA_CL_CLDT:
		xua_out = gen_ret_msg(inst, xua_in, cause);
		/* TODO: Message Return Option? */
		if (!osmo_ss7_pc_is_local(inst->ss7, xua_in->mtp.opc)) {
			/* non-local originator: send UDTS */
			/* TODO: Assign SLS */
			sccp_scrc_rx_sclc_msg(inst, xua_out);
		} else {
			/* local originator: send N-NOTICE to user */
			/* TODO: N-NOTICE.ind SCLC -> SCU */
			sclc_rx_cldr(inst, xua_out);
		}
		xua_msg_free(xua_out);
		break;
	case SUA_CL_CLDR:
		/* do nothing */
		break;
	}
}
