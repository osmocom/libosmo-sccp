/* Implementation of the ITU-T Q.703 (MTP2) Link State Control FSM as
 * described [primarily] in Figure 8/Q.703 */

#include <osmocom/core/fsm.h>

#include "mtp2_lsc_fsm.h"
#include "mtp2_iac_fsm.h"

enum mtp2_lsc_fsm_state {
	MTP2_LSC_S_POWER_OFF,
	MTP2_LSC_S_OUT_OF_SERVICE,
	MTP2_LSC_S_INITIAL_ALIGNMENT,
	MTP2_LSC_S_ALIGNED_READY,
	MTP2_LSC_S_ALIGNED_NOT_READY,
	MTP2_LSC_S_IN_SERVICE,
	MTP2_LSC_S_PROCESSOR_OUTAGE,
};

static const struct value_string mtp2_lsc_event_names[] = {
	{ MTP_LSC_E_POWER_ON,			"MGMT2LSC_POWER_ON" },
	{ MTP_LSC_E_START,			"L32LSC_START" },
	{ MTP_LSC_E_EMERGENCY,			"L32LSC_EMERGENCY" },
	{ MTP_LSC_E_EMERGENCY_CEASES,		"L32LSC_EMERGENCY_CEASES" },
	{ MTP_LSC_E_LOCAL_PROC_OUTAGE,		"MGMT2LSC_LOCAL_PROCESSOR_OUTAGE" },
	{ MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD,	"MGMT2LSC_LOCAL_PROCESSOR_OUTAGE_RECOVERED" },
	{ MTP_LSC_E_LEVEL3_FAILURE,		"MGMT2LSC_LEVEL3_FAILURE" },
	{ MTP_LSC_E_ALIGNMENT_COMPLETE,		"IAC2LSC_ALIGNMENT_COMPLETE" },
	{ MTP_LSC_E_STOP,			"L32LSC_STOP" },
	{ MTP_LSC_E_LINK_FAILURE,		"RC2LSC_LINK_FAILURE" },
	{ MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE,	"IAC2LSC_ALIGNMENT_NOT_POSSIBLE" },
	{ MTP_LSC_E_RX_SIO_SIOS,		"RC2LSC_SIO_SIOS" },
	{ MTP_LSC_E_RX_SIN_SIE,			"RC2LSC_SIN_SIE" },
	{ MTP_LSC_E_RX_SIPO,			"RC2LSC_SIPO" },
	{ MTP_LSC_E_RX_FISU_MSU,		"RC2LSC_FISU_MSU" },
	{ MTP_LSC_E_FLUSH_BUFFERS,		"L32LSC_FLUSH_BUFFERS" },
	{ MTP_LSC_E_CONTINUE,			"L32LSC_CONTINUE" },
	{ MTP_LSC_E_NO_PROC_OUTAGE,		"POC2LSC_NO_PROCESSOR_OUTAGE" },
	{ MTP_LSC_E_T1_EXP,			"T1_EXPIRED" },
	{ 0, NULL }
};

struct lsc_fsm_data {
	/*! Initial Alignment Control FSM */
	struct osmo_fsm_inst *iac_fi;

	bool local_proc_outage;

	bool l3_indication_received;
	bool processor_outage;	/* remote? */
};

/* Figure 8/Q.703 (sheet 1 of 14) */
static void mtp2_lsc_fsm_power_off(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;

	switch (event) {
	case MTP_LSC_E_POWER_ON:
		/* LSC -> TXC: Start */
		/* LSC -> TXC: Send SIOS */
		/* LSC -> AERM: Set Ti to Tin */
		/* Cancel local processor outage */
		lfd->local_proc_outage = false;
		/* Cancel emergency */
		lfd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 8/Q.703 (sheet 2+3 of 14) */
static void mtp2_lsc_fsm_out_of_service(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;

	switch (event) {
	case MTP_LSC_E_START:
		/* LSC -> RC: Start */
		/* LSC -> TXC: Start */
		if (ldf->emergency) {
			/* LSC -> IAC: Emergency */
			osmo_fsm_inst_dispatch(lfd->iac_fi, MTP2_IAC_E_EMERGENCY, NULL);
		}
		/* LSC -> IAC: Start */
		osmo_fsm_inst_dispatch(lfd->iac_fi, MTP2_IAC_E_START, NULL);
		/* LSC -> RC: Stop */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_INITIAL_ALIGNMENT, 0, 0);
		break;
	case MTP_LSC_E_EMERGENCY:
		lfd->emergency = true;
		break;
	case MTP_LSC_E_EMERGENCY_CEASES:
		lfd->emergency = false;
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE:
		lfd->local_proc_outage = true;
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD:
		lfd->local_proc_outage = false;
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 8/Q.703 (sheet 4+5 of 14) */
static void mtp2_lsc_fsm_initial_alignment(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;

	switch (event) {
	case MTP_LSC_E_LOCAL_PROC_OUTAGE:
		/* fall-through */
	case MTP_LSC_E_LEVEL3_FAILURE:
		lfd->local_proc_outage = true;
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD:
		lfd->local_proc_outage = false;
		break;
	case MTP_LSC_E_EMERGENCY:
		lfd->emergency = true;
		/* LSC -> IAC: Emergency */
		osmo_fsm_inst_dispatch(lfd->iac_fi, MTP2_IAC_E_EMERGENCY, NULL);
		break;
	case MTP_LSC_E_ALIGNMENT_COMPLETE:
		/* LSC -> SUERM: Start */
		/* Start T1 */
		if (lfd->local_proc_outage) {
			/* LSC -> POC: Local Processor Outage */
			/* LSC -> TXC: Send SIPO */
			/* LSC -> RC: Reject MSU/FISU */
			osmo_fsm_inst_state_chg_ms(fi, MTP3_LSC_S_ALIGNED_NOT_READY, MTP2_T1_64_MS, 1);
		} else {
			/* LSC -> TXC: Send FISU */
			/* LSC -> RC: Accept MSU/FISU */
			osmo_fsm_inst_state_chg_ms(fi, MTP2_LSC_S_ALIGNED_READY, MTP2_T1_64_MS, 1);
		}
		break;
	case MTP_LSC_E_LINK_FAILURE:
		/* LSC -> L3: Out of service */
		/* fall-through */
	case MTP_LSC_E_STOP:
		/* LSC -> IAC: Stop */
		osmo_fsm_inst_dispatch(lfd->iac_fi, MTP2_IAC_E_STOP, NULL);
		/* LSC -> RC: Stop */
		/* LSC -> TRX: Send SIOS */
		/* Cancel local processor outage */
		lfd->local_proc_outage = false;
		/* Cancel emergency */
		lfd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE:
		/* LSC -> L3: Out of service */
		/* LSC -> RC: Stop */
		/* LSC -> TRX: Send SIOS */
		/* Cancel local processor outage */
		lfd->local_proc_outage = false;
		/* Cancel emergency */
		lfd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 8/Q.703 (sheet 6+7 of 14) */
static void mtp2_lsc_fsm_aligned_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;
	switch (event) {
	case MTP_LSC_E_LINK_FAILURE:
		/* fall-through */
	case MTP_LSC_E_RX_SIO_SIOS:
	case MTP_LSC_E_T1_EXP:
		/* LSC -> L3: Out of service */
		/* fall-through */
	case MTP_LSC_E_STOP:
		/* Stop T1 */
		/* LSC -> RC: Stop */
		/* LSC -> SUERM: Stop */
		/* LSC -> TXC: Send SIOS */
		/* Cancel emergency */
		lfd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_RX_SIPO:
		/* Stop T1 */
		/* LSC -> L3: Remote processor outage */
		/* LSC -> POC: Remote processor outage */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_PROCESSOR_OUTAGE, 0, 0);
		break;
	case MTP_LSC_E_RX_FISU_MSU:
		/* LSC -> L3: In service */
		/* Stop T1 */
		/* LSC -> TXC: Send MSU */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_IN_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE:
		/* fall-through */
	case MTP_LSC_E_LEVEL3_FAILURE:
		/* LSC -> POC: Local Processor outage */
		/* LSC -> TXC: Send SIPO */
		/* LSC -> RC: Reject MSU/FISU */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_ALIGNED_NOT_READY, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 8/Q.703 (sheet 8+9 of 14) */
static void mtp2_lsc_fsm_aligned_not_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;
	switch (event) {
	case MTP_LSC_E_LINK_FAILURE:
		/* fall-through */
	case MTP_LSC_E_RX_SIO_SIOS:
	case MTP_LSC_E_T1_EXP:
		/* LSC -> L3: Out of service */
		/* fall-through */
	case MTP_LSC_E_STOP:
		/* Stop T1 */
		/* LSC -> RC: Stop */
		/* LSC -> SUERM: Stop */
		/* LSC -> TxC: Send SIOS */
		/* Cancel emergency and local processor outage */
		lfd->emergency = false;
		lfd->local_proc_outage = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD:
		/* LSC -> POC: Local processor recovered */
		/* Cancel local processor outage */
		lfd->local_proc_outage = false;
		/* LSC -> TXC: Send FISU */
		/* LSC -> RC: Accept MSU/FISU */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_ALIGNED_READY, 0, 0);
		break;
	case MTP_LSC_E_RX_FISU_MSU:
		/* LSC -> L3: In service */
		/* Stop T1 */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_PROCESSOR_OUTAGE, 0, 0);
		break;
	case MTP_LSC_E_RX_SIPO:
		/* LSC -> L3: Remote processor outage */
		/* LSC -> POC: Remote processor outage */
		/* Stop T1 */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_PROCESSOR_OUTAGE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);

	}
}

/* Figure 8/Q.703 (sheet 10+11 of 14) */
static void mtp2_lsc_fsm_in_service(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;
	switch (event) {
	case MTP_LSC_E_LINK_FAILURE:
		/* fall-through */
	case MTP_LSC_E_RX_SIO_SIOS:
		/* fall-through */
	case MTP_LSC_E_RX_SIN_SIE:
		/* LSC -> L3: Out of service */
		/* fall-through */
	case MTP_LSC_E_STOP:
		/* LSC -> SUERM: Stop */
		/* LSC -> RC: Stop */
		/* LSC -> TxC: Send SIOS */
		/* Cancel emergency */
		lfd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE:
		/* fall-through */
	case MTP_LSC_E_LEVEL3_FAILURE:
		/* LSC -> POC: Local Processor outage */
		/* LSC -> TXC: Send SIPO */
		/* LSC -> RC: Reject MSU/FISU */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_ALIGNED_NOT_READY, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* Figure 8/Q.703 (sheet 12-14 of 14) */
static void mtp2_lsc_fsm_processor_outage(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lsc_fsm_data *lfd = fi->priv;
	switch (event) {
	case MTP_LSC_E_RX_FISU_MSU:
		/* LSC -> POC: Remote processor recovered */
		/* LSC -> L3: Remote processor recovered */
		break;
	case MTP_LSC_E_LEVEL3_FAILURE:
		/* fall-through */
	case MTP_LSC_E_LOCAL_PROC_OUTAGE:
		/* LSC -> POC: Local processor outage */
		/* LSC -> TXC: Send SIPO */
		break;
	case MTP_LSC_E_RX_SIPO:
		/* LSC -> L3: Remote processor outage */
		/* LSC -> POC: Remote processor outage */
		break;
	case MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD:
		/* LSC -> POC: Local processor recovered */
		/* LSC -> RC: Retrieve FSNX */
		/* LSC -> TXC: Send FISU */
		break;
	case MTP_LSC_E_FLUSH_BUFFERS:
		/* LSC -> TXC: Flush buffers */
		/* fall-through */
	case MTP_LSC_E_CONTINUE:
		/* Mark L3 indication received */
		lfd->l3_indication_received = true;
		if (lfd->processor_outage)
			break;
		/* Cancel Level3 indication received */
		/* LSC -> TXC: Send MSU/FISU */
		/* Cancel local processor outage */
		/* LSC -> RC: Accept MSU/FISU */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_IN_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_NO_PROC_OUTAGE:
		/* Cancel processor outage */
		lfd->processor_outage = false;
		if (!lfd->l3_indication_received)
			break;
		/* Cancel Level3 indication received */
		/* LSC -> TXC: Send MSU/FISU */
		/* Cancel local processor outage */
		/* LSC -> RC: Accept MSU/FISU */
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_IN_SERVICE, 0, 0);
		break;
	case MTP_LSC_E_LINK_FAILURE:
	case MTP_LSC_E_RX_SIO_SIOS:
	case MTP_LSC_E_RX_SIN_SIE:
		/* LSC -> L3: Out of service */
		/* fall-through */
	case MTP_LSC_E_STOP:
		/* LSC -> SUERM: Stop */
		/* LSC -> RC: Stop */
		/* LSC -> POC: Stop */
		/* LSC -> TXC: Send SIOS */
		/* Cancel emergency and local processor outage */
		lfd->emergency = false;
		lfd->local_proc_outage = false;
		osmo_fsm_inst_state_chg(fi, MTP2_LSC_S_OUT_OF_SERVICE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}


static int mtp2_lsc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct lsc_fsm_data *lfd = fi->priv;

	switch (fi-T) {
	case 1:
		/* we handle the timer expiration in the action call-backs
		 * to better align with the SDL diagrams */
		osmo_fsm_inst_dispatch(fi, MTP_LSC_E_T1_EXP, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}


static const struct osmo_fsm_state mtp2_lsc_states[] = {
	[MTP2_LSC_S_POWER_OFF] = {
		.name = "POWER_OFF",
		.in_event_mask = S(MTP_LSC_E_POWER_ON),
		.out_state_mask = S(MTP2_LSC_S_OUT_OF_SERVICE),
		.action = mtp2_lsc_fsm_power_off,
	},
	[MTP2_LSC_S_OUT_OF_SERVICE] = {
		.name = "OUT_OF_SERVICE",
		.in_event_mask = S(MTP_LSC_E_START) |
				 S(MTP_LSC_E_EMERGENCY) |
				 S(MTP_LSC_E_EMERGENCY_CEASES) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD) |
				 S(MTP_LSC_E_LEVEL3_FAILURE),
		.out_state_mask = S(MTP2_LSC_S_OUT_OF_SERVICE) |
				  S(MTP2_LSC_S_INITIAL_ALIGNMENT),
		.action = mtp2_lsc_fsm_out_of_service,
	},
	[MTP2_LSC_S_INITIAL_ALIGNMENT] = {
		.name = "INITIAL_ALIGNMENT",
		.in_event_mask = S(MTP_LSC_E_EMERGENCY) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD) |
				 S(MTP_LSC_E_LEVEL3_FAILURE) |
				 S(MTP_LSC_E_ALIGNMENT_COMPLETE) |
				 S(MTP_LSC_E_STOP) |
				 S(MTP_LSC_E_LINK_FAILURE) |
				 S(MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE),
		.out_state_mask = S(MTP2_LSC_S_INITIAL_ALIGNMENT) |
				  S(MTP2_LSC_S_ALIGNED_NOT_READY) |
				  S(MTP2_LSC_S_OUT_OF_SERVICE),
		.action = mtp2_lsc_fsm_initial_alignment,
	},
	[MTP2_LSC_S_ALIGNED_READY] = {
		.name = "ALIGNED_READY",
		.in_event_mask = S(MTP_LSC_E_LINK_FAILURE) |
				 S(MTP_LSC_E_RX_SIO_SIOS) |
				 S(MTP_LSC_E_STOP) |
				 S(MTP_LSC_E_RX_SIPO) |
				 S(MTP_LSC_E_RX_FISU_MSU) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE) |
				 S(MTP_LSC_E_LEVEL3_FAILURE) |
				 S(MTP_LSC_E_T1_EXP),
		.out_state_mask = S(MTP2_LSC_S_OUT_OF_SERVICE) |
				  S(MTP2_LSC_S_PROCESSOR_OUTAGE) |
				  S(MTP2_LSC_S_IN_SERVICE) |
				  S(MTP2_LSC_S_ALIGNED_NOT_READY),
		.action = mtp2_lsc_fsm_aligned_ready,
	},
	[MTP2_LSC_S_ALIGNED_NOT_READY] = {
		.name = "ALIGNED_NOT_READY",
		.in_event_mask = S(MTP_LSC_E_LINK_FAILURE) |
				 S(MTP_LSC_E_RX_SIO_SIOS) |
				 S(MTP_LSC_E_STOP) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD) |
				 S(MTP_LSC_E_RX_FISU_MSU) |
				 S(MTP_LSC_E_RX_SIPO) |
				 S(MTP_LSC_E_T1_EXP),
		.out_state_mask = S(MTP2_LSC_S_OUT_OF_SERVICE) |
				  S(MTP2_LSC_S_ALIGNED_READY) |
				  S(MTP2_LSC_S_PROCESSOR_OUTAGE),
		.action = mtp2_lsc_fsm_aligned_not_ready,
	},
	[MTP2_LSC_S_IN_SERVICE] = {
		.name = "IN_SERVICE",
		.in_event_mask = S(MTP_LSC_E_LINK_FAILURE) |
				 S(MTP_LSC_E_RX_SIO_SIOS) |
				 S(MTP_LSC_E_RX_SIN_SIE) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE) |
				 S(MTP_LSC_E_LEVEL3_FAILURE) |
				 S(MTP_LSC_E_RX_SIPO),
		.out_state_mask = S(MTP2_LSC_S_OUT_OF_SERVICE) |
				  S(MTP2_LSC_S_PROCESSOR_OUTAGE),
		.action = mtp2_lsc_fsm_in_service,
	},
	[MTP2_LSC_S_PROCESSOR_OUTAGE] = {
		.name = "PROCESSOR_OUTAGE",
		.in_event_mask = S(MTP_LSC_E_RX_FISU_MSU) |
				 S(MTP_LSC_E_LEVEL3_FAILURE) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE) |
				 S(MTP_LSC_E_RX_SIPO) |
				 S(MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD) |
				 S(MTP_LSC_E_FLUSH_BUFFERS) |
				 S(MTP_LSC_E_NO_PROC_OUTAGE) |
				 S(MTP_LSC_E_LINK_FAILURE) |
				 S(MTP_LSC_E_RX_SIO_SIOS) |
				 S(MTP_LSC_E_RX_SIN_SIE) |
				 S(MTP_LSC_E_STOP),
		.out_state_mask = S(MTP2_LSC_S_PROCESSOR_OUTAGE) |
				  S(MTP2_LSC_S_IN_SERVICE) |
				  S(MTP2_LSC_S_OUT_OF_SERVICE),
		.action = mtp2_lsc_fsm_processor_outage,
	},
};


struct osmo_fsm mtp2_lsc_fsm = {
	.name = "MTP2_LSC",
	.states = mtp2_lsc_states,
	.num_states = ARRAY_SIZE(mtp2_lsc_states),
	.timer_cb = mtp2_lsc_fsm_timer_cb,
	.log_subsys = DLMTP2,
	.event_names = mtp2_lsc_event_names,
	.allstate_event_mask = ,
	.allstate_action = mtp2_lsc_allstate,
};

struct osmo_fsm_inst *mtp2_lxc_fsm_alloc(struct osmo_ss7_link *s7l, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct mtp2_lsc_fsm_priv *lfp;

	fi = osmo_fsm_inst_alloc(&mtp2_lsc_fsm, s7l, NULL, log_level, s7l->name);

	lfp = talloc_zero(fi, struct mtp2_lxc_fsm_priv);
	if (!lfp) {
		osmo_fsm_inst_term(fi, OSM_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	/* Initial Alignment Control FSM instance */
	lfp->iac_fi = mtp2_iac_fsm_alloc(fi);

	lfp->local_proc_outage = false;
	lfp->l3_indication_received = false;
	lfp->processor_outage = false;

	fi->priv = lfp;

	return fi;
}
