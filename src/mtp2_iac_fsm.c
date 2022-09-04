
#include <osmocom/core/fsm.h>
#include "mtp2_iac_fsm.h"

/* Implementation of the ITU-T Q.703 (MTP@) Initial alignment control FSM as
 * described [primarily] in Figure 9/Q.703 */

enum mtp2_iac_fsm_state {
	MTP2_IAC_S_IDLE,
	MTP2_IAC_S_NOT_ALIGNED,
	MTP2_IAC_S_ALIGNED,
	MTP2_IAC_S_PROVING,
};

static const struct value_string mtp2_iac_event_names[] = {
	{ MTP2_IAC_E_EMERGENCY, 	"LSC2IAC_EMERGENCY" },
	{ MTP2_IAC_E_START, 		"LSC2IAC_START" },
	{ MTP2_IAC_E_STOP,		"LSC2IAC_STOP" },
	{ MTP2_IAC_E_RX_SIO,		"RC2IAC_RX_SIO" },
	{ MTP2_IAC_E_RX_SIOS,		"RC2IAC_RX_SIOS" },
	{ MTP2_IAC_E_RX_SIN,		"RC2IAC_RX_SIN" },
	{ MTP2_IAC_E_RX_SIE,		"RC2IAC_RX_SIE" },
	{ MTP2_IAC_E_CORRECT_SU,	"DAEDR2IAC_CORRECT_SU" },
	{ MTP2_IAC_E_ABORT_PROVING,	"AERM2IAC_ABORT_PROVING" },
	{ 0, NULL }
};

/* Section 12.3/Q.703 */
#define MTP2_T1_64_MS		45000
#define MTP2_T2_MS		60000
#define MTP2_T3_MS		1500
#define MTP2_T4e_64_MS		500
#define MTP2_T4n_64_MS		8200
#define MTP2_T5_MS		100
#define MTP2_T6_64_MS		5000
#define MTP2_T7_64_MS		1000

struct iac_fsm_data {
	bool emergency;
	bool further_proving;
	uint32_t t4_ms;
};

static void mtp2_iac_fsm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)

	struct iac_fsm_data *ifd = fi->priv;

	switch (event) {
	case MTP2_IAC_E_EMERGENCY:
		/* Mark emergency */
		ifd->emergency = true;
		return;
	case MTP2_IAC_E_START:
		/* IAC -> TXC: Send SIO */
		/* Start T2 */
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_NOT_ALIGNED, 0, 2);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void mtp2_iac_fsm_not_aligned(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct iac_fsm_data *ifd = fi->priv;

	switch (event) {
	case MTP2_IAC_E_STOP:
		/* Stop T2 (implicit below) */
		/* Cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
	case MTP2_IAC_E_RX_SIO:
	case MTP2_IAC_E_RX_SIN:
		/* Stop T2 (implicit below) */
		if (emergency) {
			/* Set T4 to Pe */
			ifd->t4_ms = MTP2_T4e_64_MS;
			/* IAC -> TXC: Send SIE */
		} else {
			/* Set T4 to Pn */
			ifd->t4_ms = MTP2_T4n_64_MS;
			/* IAC -> TXC: Send SIN */
		}
		/* Start T3 */
		osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_ALIGNED, MTP2_T3_MS, 3);
		break;
	case MTP2_IAC_E_RX_SIE:
		/* Stop T2 (implicit below) */
		if (emergency) {
			/* Set T4 to Pe */
			ifd->t4_ms = MTP2_T4e_64_MS;
			/* IAC -> TXC: Send SIE */
		} else {
			/* Set T4 to Pe */
			ifd->t4_ms = MTP2_T4e_64_MS;
			/* IAC -> TXC: Send SIN */
		}
		/* Start T3 */
		osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_ALIGNED, MTP2_T3_MS, 3);
		break;
	case MTP2_IAC_E_EMERGENCY:
		ifd->emergency = true;
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void mtp2_iac_fsm_aligned(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct iac_fsm_data *ifd = fi->priv;
	struct osmo_fsm_inst *lsc_fi = fi->proc.parent;

	switch (event) {
	case MTP2_IAC_E_RX_SIE:
		/* Set T4 to Pe */
		ifd->t4_ms = MTP2_T4e_64_MS;
		/* fall-through */
	case MTP2_IAC_E_RX_SIN:
		/* Stop T3 (implicit below) */
		if (t4 == Pe) {
			/* IAC -> AERM: set i to ie */
		}
		/* IAC -> AERM: Start */
		/* Start T4 (implicit below) */
		/* Cp := 0 */
		/* cancel further proving */
		ifd->further_proving = false;
		osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_PROVING, ifd->t4_ms, 4);
		break;
	case MTP2_IAC_E_EMERGENCY:
		/* IAC -> TXC: Send SIE */
		/* Set T4 to Pe */
		ifd->t4_ms = MTP2_T4e_64_MS;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_ALIGNED, 0, 0);
		break;
	case MTP2_IAC_E_STOP:
		/* Stop T3 (implicit below) */
		/* Cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		break;
	case MTP2_IAC_E_RX_SIOS:
		/* IAC -> LSC: Alignment not possible */
		osmo_fsm_inst_dispatch(lsc_fi, MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE, NULL);
		/* Stop T3 (implicit below) */
		/* Cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void mtp2_iac_fsm_proving(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct iac_fsm_data *ifd = fi->priv;
	struct osmo_fsm_inst *lsc_fi = fi->proc.parent;

	switch (event) {
	case MTP2_IAC_E_RX_SIO:
		/* Stop T4 (implicit below) */
		/* IAC -> AERM: Stop */
		/* Start T3 */
		osmo_fsm_inst_state_chg_ms(fi, MGP2_IAC_S_ALIGNED, MTP2_T3_MS, 3);
		break;
	case MTP2_IAC_E_CORRECT_SU:
		if (ifd->further_proving) {
			/* Stop T4 (implicit below) */
			/* 5 in-line below */
			/* IAC -> AERM: Start */
			/* Cancel further proving */
			ifd->further_proving = false;
			/* Start T4 */
			osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_PROVING, ifd->t4_ms, 4);
		} else {
			/* 6: empty */
		}
		break;
	case MTP2_IAC_E_RX_SIOS:
		/* Stop T4 (implicit below) */
		/* IAC -> LSC: Alignment not possible */
		osmo_fsm_inst_dispatch(lsc_fi, MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE, NULL);
		/* 4 in-line below */
		/* IAC -> AERM: Stop */
		/* cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		break;
	case MTP2_IAC_E_STOP:
		/* Stop T4 (implicit below) */
		/* 4 in-line below */
		/* IAC -> AERM: Stop */
		/* cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		break;
	case MTP2_IAC_E_ABORT_PROVING:
		/* Cp := Cp + 1 */
		if (id->cp == 5) {
			/* IAC -> LSC: Alignment not possible */
			osmo_fsm_inst_dispatch(lsc_fi, MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE, NULL);
			/* Stop T4 (implicit below) */
			/* IAC -> AERM: Stop */
			/* cancel emergency */
			ifd->emergency = false;
			osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		} else{
			/* Mark further proving */
			ifd->further_proving = true;
		}
		break;
	case MTP2_IAC_E_EMERGENCY:
		/* IAC -> TXC: Send SIE */
		/* Stop T4 (implicit below) */
		/* Set T4 to Pe */
		ifd->t4_ms = MTP2_T4e_64_MS;
		/* IAC -> AERM: Stop */
		/* Set Ti to Tie */
		/* IAC -> AERM: Start */
		/* Cancel further proving */
		ifd->further_proving = false;
		/* Start T4 */
		osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_PROVING, ifd->t4_ms, 4);
		break;
	case MTP2_IAC_E_RX_SIE:
		if (t4 == Pe)
			break;
		/* Stop T4 (implicit below) */
		/* Set T4 to Pe */
		ifd->t4_ms = MTP2_T4e_64_MS;
		/* IAC -> AERM: Stop */
		/* Set Ti to Tie */
		/* IAC -> AERM: Start */
		/* Cancel further proving */
		ifd->further_proving = false;
		/* Start T4 */
		osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_PROVING, ifd->t4_ms, 4);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static const struct osmo_fsm_state mtp2_iac_states[] = {
	[MTP2_IAC_S_IDLE] = {
		.name = "IDLE",
		.in_event_mask = S(MTP2_IAC_E_EMERGENCY) |
				 S(MTP2_IAC_E_START),
		.out_state_mask = S(MTP2_IAC_S_IDLE) |
				  S(MTP2_IAC_S_NOT_ALIGNED),
		.action = mtp2_iac_fsm_idle,
	},
	[MTP2_IAC_S_NOT_ALIGNED] = {
		.name = "NOT_ALIGNED",
		.in_event_mask = S(MTP2_IAC_E_STOP) |
				 S(MTP2_IAC_E_SIO) |
				 S(MTP2_IAC_E_SIN) |
				 S(MTP2_IAC_E_SIE) |
				 S(MTP2_IAC_E_EMERGENCY),
		.out_state_mask = S(MTP2_IAC_S_IDLE) |
				  S(MTP2_IAC_S_NOT_ALIGNED) |
				  S(MTP2_IAC_S_ALIGNED),
		.action = mtp2_iac_fsm_not_aligned,
	},
	[MTP2_IAC_S_ALIGNED] = {
		.name = "ALIGNED",
		.in_event_mask = S(MTP2_IAC_E_SIE) |
				 S(MTP2_IAC_E_SIN) |
				 S(MTP2_IAC_E_EMERGENCY) |
				 S(MTP2_IAC_E_STOP) |
				 S(MTP2_IAC_E_RX_SIOS),
		.out_state_mask = S(MTP2_IAC_S_ALIGNED) |
				  S(MTP2_IAC_S_PROVING) |
				  S(MTP2_IAC_S_IDLE),
		.action = mtp2_iac_fsm_aligned,
	},
	[MTP2_IAC_S_PROVING] = {
		.name = "PROVING",
		.in_event_mask = S(MTP2_IAC_E_RX_SIO) |
				 S(MTP2_IAC_E_CORRECT_SU) |
				 S(MTP2_IAC_E_RX_SIOS) |
				 S(MTP2_IAC_E_STOP) |
				 S(MTP2_IAC_E_ABORT_PROVING) |
				 S(MTP2_IAC_E_EMERGENCY) |
				 S(MTP2_IAC_E_RX_SIE),
		.out_state_mask = S(MTP2_IAC_S_ALIGNED) |
				  S(MTP2_IAC_S_IDLE) |
				  S(MTP2_IAC_S_PROVING),
		.action = mtp2_iac_fsm_proving,
	},
};

static int mtp2_iac_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct iac_fsm_data *ifd = fi->priv;
	struct osmo_fsm_inst *lsc_fi = fi->proc.parent;

	switch (fi->T) {
	case 2:
		/* Figure 9/Q.703 (sheet 1 of 6) */
		OSMO_ASSERT(fi->state == MTP2_IAC_S_NOT_ALIGNED);
		/* IAC -> LSC: Alignment not possible */
		osmo_fsm_inst_dispatch(lsc_fi, MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE, NULL);
		/* Cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		break;
	case 3:
		/* Figure 9/Q.703 (sheet 4 of 6) */
		OSMO_ASSERT(fi->state == MTP2_IAC_S_ALIGNED);
		/* IAC -> LSC: Alignment not possible */
		osmo_fsm_inst_dispatch(lsc_fi, MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE, NULL);
		/* Cancel emergency */
		ifd->emergency = false;
		osmo_fsm_inst_state_chg(fi, MTP2_IAC_S_IDLE, 0, 0);
		break;
	case 4:
		/* Figure 9/Q.703 (sheet 5 of 6) */
		OSMO_ASSERT(fi->state == MTP2_IAC_S_PROVING);
		if (ifd->further_proving) {
			/* 5 in-line below */
			/* IAC -> AERM: Start */
			/* Cancel further proving */
			ifd->further_proving = false;
			/* Start T4 */
			osmo_fsm_inst_state_chg_ms(fi, MTP2_IAC_S_PROVING, ifd->t4_ms, 4);
		} else {
			/* 6: empty */
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

struct osmo_fsm mtp2_iac_fsm = {
	.name = "MTP2_IAC",
	.states = mtp2_iac_states,
	.num_states = ARRAY_SIZE(mtp2_iac_states),
	.timer_cb = mtp2_iac_fsm_timer_cb,
	.log_subsys = DLMTP2,
	.event_names = mtp2_iac_event_names,
};

struct osmo_fsm_inst *mtp2_iac_fsm_alloc(struct osmo_fsm_inst *lsc_fsm)
{
	struct osmo_fsm_inst *fi;
	struct mtp2_iac_fsm_priv *ifp;

	fi = osmo_fsm_inst_alloc_child
}

