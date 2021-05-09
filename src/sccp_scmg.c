/* SCCP Management (SCMG) according to ITU-T Q.713/Q.714 */

/* (C) 2021 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/sccp_scmg.h>
#include <osmocom/sccp/sccp_types.h>

#include "xua_internal.h"
#include "sccp_internal.h"

/* ITU-T Q.714 5.3.3 Subsystem allowed */
void sccp_scmg_rx_ssn_allowed(struct osmo_sccp_instance *inst, uint32_t dpc, uint32_t ssn, uint32_t smi)
{
	struct osmo_scu_state_param state;
	/* 1) Instruct the translation function to update the translation tables */
	/* 2) Mark as "allowed" the status of that subsystem. */
	/* 3) Initiate a local broadcast of "User-in-service" information for the allowed subsystem */
	state = (struct osmo_scu_state_param) {
		.affected_pc = dpc,
		.affected_ssn = ssn,
		.user_in_service = true,
		.ssn_multiplicity_ind = smi,
	};
	sccp_lbcs_local_bcast_state(inst, &state);
	/* 4) Discontinue the subsystem status test if such a test was in progress */
	/* 5) Initiate a broadcast of Subsystem-Allowed messages to concerned signalling points. */
}

/* ITU-T Q.714 5.3.2 Subsystem prohibited */
void sccp_scmg_rx_ssn_prohibited(struct osmo_sccp_instance *inst, uint32_t dpc, uint32_t ssn, uint32_t smi)
{
	struct osmo_scu_state_param state;
	/* 1) instruct the translation function to update the translation tables */
	/* 2) mark as "prohibited" the status of that subsystem */
	/* 3) initiate a local broadcast of "User-out-of-service" information */
	state = (struct osmo_scu_state_param) {
		.affected_pc = dpc,
		.affected_ssn = ssn,
		.user_in_service = false,
		.ssn_multiplicity_ind = smi,
	};
	sccp_lbcs_local_bcast_state(inst, &state);

	/* 4) initiate the subsystem status test procedure if the prohibited subsystem is not local */
	/* 5) initiate a broadcast of Subsystem-Prohibited messages to concerned SP */
	/* 6) cancel "ignore subsystem status test" and the associated timer if in progress and if
	 *    the newly prohibited subsystem resides at the local node. */
}

/*! brief MTP -> SNM (MTP-PAUSE.ind) - inability to providing MTP service Q.714 5.2.2 */
void sccp_scmg_rx_mtp_pause(struct osmo_sccp_instance *inst, uint32_t dpc)
{
	struct osmo_scu_pcstate_param pcstate;
	/* 1) Informs the translation function to update the translation tables. */
	/* 2) SCCP management marks as "prohibited" the status of the remote signalling point, the
	   remote SCCP and each subsystem at the remote signalling point. */
	/* 3) Discontinues all subsystem status tests (including SSN = 1) */

	/* 4) local broadcast of "user-out-of-service" for each SSN at that dest
	 * [this would require us to track SSNs at each PC, which we don't] */

	/* 5) local broadcast of "signaling point inaccessible" */
	/* 6) local broadcast of "remote SCCP unavailable" */
	pcstate = (struct osmo_scu_pcstate_param) {
		.affected_pc = dpc,
		.restricted_importance_level = 0,
		.sp_status = OSMO_SCCP_SP_S_INACCESSIBLE,
		.remote_sccp_status = OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN,
	};
	sccp_lbcs_local_bcast_pcstate(inst, &pcstate);
}

/*! brief MTP -> SNM (MTP-RESUME.ind) - ability of providing the MTP service Q.714 5.2.3 */
void sccp_scmg_rx_mtp_resume(struct osmo_sccp_instance *inst, uint32_t dpc)
{
	struct osmo_scu_pcstate_param pcstate;
	/* 1) Sets the congestion state of that signalling point */
	/* 2) Instructs the translation function to update the translation tables. */
	/* 3) Marks as "allowed" the status of that destination, and the SCCP */
	/* 4) - not applicable */
	/* 5) Marks as "allowed" the status of remote subsystems */

	/* 6) local broadcast of "signalling point accessible" */
	/* 7) local broadcast of "remote SCCP accessible" */
	pcstate = (struct osmo_scu_pcstate_param) {
		.affected_pc = dpc,
		.restricted_importance_level = 0,
		.sp_status = OSMO_SCCP_SP_S_ACCESSIBLE,
		.remote_sccp_status = OSMO_SCCP_REM_SCCP_S_AVAILABLE,
	};
	sccp_lbcs_local_bcast_pcstate(inst, &pcstate);

	/* 8) local broadcast of "user-in-service"
	 * [this would require us to track SSNs at each PC, which we don't] */
}

void sccp_scmg_rx_mtp_status(struct osmo_sccp_instance *inst, uint32_t dpc, enum mtp_unavail_cause cause)
{
	struct osmo_scu_pcstate_param pcstate;
	/* 1) Informs the translation function to update the translation tables. */
	/* 2) In the case where the SCCP has received an MTP-STATUS indication primitive relating to
	      Mark the status of the SCCP and each SSN for the relevant destination to "prohibited"
	      and initiates a subsystem status test with SSN = 1. If the cause in the MTP-STATUS
	      indication primitive indicates "unequipped user", then no subsystem status test is
	      initiated. */
	/* 3) Discontinues all subsystem status tests (including SSN = 1) if an MTP-STATUS
	      indication primitive is received with a cause of "unequipped SCCP". The SCCP
	      discontinues all subsystem status tests, except for SSN = 1, if an MTP-STATUS
	      indication primitive is received with a cause of either "unknown" or "inaccessible" */
	switch (cause) {
	case MTP_UNAVAIL_C_UNKNOWN:
	case MTP_UNAVAIL_C_UNEQUIP_REM_USER:
	case MTP_UNAVAIL_C_INACC_REM_USER:
		break;
	}

	/* 4) local broadcast of "user-out-of-service" for each SSN at that dest
	 * [this would require us to track SSNs at each PC, which we don't] */

	/* 6) local broadcast of "remote SCCP unavailable" */
	pcstate = (struct osmo_scu_pcstate_param) {
		.affected_pc = dpc,
		.restricted_importance_level = 0,
		.sp_status = OSMO_SCCP_SP_S_ACCESSIBLE,
		.remote_sccp_status = OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN,
	};
	sccp_lbcs_local_bcast_pcstate(inst, &pcstate);
}

const struct value_string sccp_scmg_msgt_names[] = {
	{ SCCP_SCMG_MSGT_SSA, "SSA (Subsystem Allowed)" },
	{ SCCP_SCMG_MSGT_SSP, "SSP (Subsystem Prohibited)" },
	{ SCCP_SCMG_MSGT_SST, "SST (Subsystem Status Test)" },
	{ SCCP_SCMG_MSGT_SOR, "SOR (Subsystem Out-of-service Request)" },
	{ SCCP_SCMG_MSGT_SOG, "SOG (Subsystem Out-of-service Grant)" },
	{ SCCP_SCMG_MSGT_SSC, "SSC (Subsystem Congested)" },
	{ 0, NULL }
};

static int sccp_scmg_tx(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *calling_addr,
			const struct osmo_sccp_addr *called_addr,
			uint8_t msg_type, uint8_t ssn, uint16_t pc, uint8_t smi, uint8_t *ssc_cong_lvl)
{
	struct msgb *msg = sccp_msgb_alloc(__func__);
	struct osmo_scu_prim *prim;
	struct osmo_scu_unitdata_param *param;
	struct sccp_scmg_msg *scmg;

	/* fill primitive header */
	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	param = &prim->u.unitdata;
	memcpy(&param->calling_addr, calling_addr, sizeof(*calling_addr));
	memcpy(&param->called_addr, called_addr, sizeof(*called_addr));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST, msg);

	/* Fill the actual SCMG message */
	msg->l2h = msgb_put(msg, sizeof(*scmg));
	scmg = (struct sccp_scmg_msg *) msg->l2h;
	scmg->msg_type = msg_type;
	scmg->affected_ssn = ssn;
	scmg->affected_pc = pc;
	scmg->smi = smi;

	/* add congestion level in case of SSC message */
	if (msg_type == SCCP_SCMG_MSGT_SSC) {
		msgb_put(msg, 1);
		OSMO_ASSERT(ssc_cong_lvl);
		scmg->ssc_congestion_lvl[1] = *ssc_cong_lvl;
	}

	return osmo_sccp_user_sap_down(scu, &prim->oph);
}


/* Subsystem Allowed received */
static int scmg_rx_ssa(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *calling_addr,
			const struct osmo_sccp_addr *called_addr, const struct sccp_scmg_msg *ssa)
{
	/* Q.714 5.3.3 */
	if (ssa->affected_ssn == SCCP_SSN_MANAGEMENT)
		return 0;

	/* if the SSN is not marked as prohibited, ignore */

	/* Q.714 5.3.2.2 a) */
	sccp_scmg_rx_ssn_allowed(scu->inst, ssa->affected_pc, ssa->affected_ssn, ssa->smi);

	/* If the remote SCCP, at which the subsystem reported in the SSA message resides, is marked
	 * inaccessible, then the message is treated as an implicit indication of SCCP restart */
	return 0;
}

/* Subsystem Prohibited received */
static int scmg_rx_ssp(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *calling_addr,
			const struct osmo_sccp_addr *called_addr, const struct sccp_scmg_msg *ssp)
{
	/* Q.714 5.3.2.2 a) */
	sccp_scmg_rx_ssn_prohibited(scu->inst, ssp->affected_pc, ssp->affected_ssn, ssp->smi);
	return 0;
}

/* Subsystem Test received */
static int scmg_rx_sst(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *calling_addr,
			const struct osmo_sccp_addr *called_addr, const struct sccp_scmg_msg *sst)
{
	/* Q.714 5.3.4.3 Actions at the receiving side (of SST) */

	/* check "ignore subsystem status test" and bail out */
	/* check if SSN in question is available. If yes, return SSA. If not, ignore */
	scu = sccp_user_find(scu->inst, sst->affected_ssn, sst->affected_pc);
	if (!scu)
		return 0;

	/* is subsystem available? */
	if (0 /* !subsys_available(scu) */)
		return 0;

	struct osmo_sccp_addr peer_addr = *calling_addr;
	peer_addr.pc = 7000;
	peer_addr.presence |= OSMO_SCCP_ADDR_T_PC;

	return sccp_scmg_tx(scu, called_addr, &peer_addr, SCCP_SCMG_MSGT_SSA,
			    sst->affected_ssn, sst->affected_pc, 0, NULL);
}

static int scmg_rx(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *calling_addr,
		   const struct osmo_sccp_addr *called_addr, const struct sccp_scmg_msg *scmg)
{
	switch (scmg->msg_type) {
	case SCCP_SCMG_MSGT_SSA:
		return scmg_rx_ssa(scu, calling_addr, called_addr, scmg);
	case SCCP_SCMG_MSGT_SSP:
		return scmg_rx_ssp(scu, calling_addr, called_addr, scmg);
	case SCCP_SCMG_MSGT_SST:
		return scmg_rx_sst(scu, calling_addr, called_addr, scmg);
	case SCCP_SCMG_MSGT_SOR:
	case SCCP_SCMG_MSGT_SOG:
	case SCCP_SCMG_MSGT_SSC:
	default:
		LOGP(DLSCCP, LOGL_NOTICE, "Rx unsupported SCCP SCMG %s, ignoring",
			sccp_scmg_msgt_name(scmg->msg_type));
		break;
	}
	return 0;
}

/* main entry point for SCCP user primitives from SCRC/SCOC */
static int scmg_prim_cb(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_scu_unitdata_param *param;
	struct sccp_scmg_msg *scmg;
	int rc = 0;

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		param = &prim->u.unitdata;
		scmg = msgb_l2(oph->msg);
		/* ensure minimum length based on message type */
		if (msgb_l2len(oph->msg) < sizeof(*scmg)) {
			rc = -1;
			break;
		}
		if (scmg->msg_type == SCCP_SCMG_MSGT_SSC && msgb_l2len(oph->msg) < sizeof(*scmg)+1) {
			rc = -1;
			break;
		}
		/* interestingly, PC is specified to be encoded in little endian ?!? */
		scmg->affected_pc = osmo_load16le(&scmg->affected_pc);
		rc = scmg_rx(scu, &param->calling_addr, &param->called_addr, scmg);
		break;
	default:
		LOGP(DLSCCP, LOGL_ERROR, "unsupported SCCP user primitive %s\n",
			osmo_scu_prim_name(oph));
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

/* register SCMG as SCCP user for SSN=1 */
int sccp_scmg_init(struct osmo_sccp_instance *inst)
{
	struct osmo_sccp_user *scu;
	scu = osmo_sccp_user_bind(inst, "SCCP Maangement", scmg_prim_cb, SCCP_SSN_MANAGEMENT);
	if (!scu)
		return -1;
	return 0;
}
