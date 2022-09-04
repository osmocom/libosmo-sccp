#include <osmocom/core/fsm.h>
#include "mtp2_txc_fsm.h"

struct txc_fsm_data {
	/* Link Status Control FSM Instance */
	struct osmo_fsm_inst *lsc_fi;
	/* back-pointer to SS7 Link */
	struct osmo_ss7_link *s7l;

	/* various fsm-private state */
	FIXME lssu_available;
	bool sib_received;
	bool rtb_full;
	bool msu_inhibited;

	uint32_t fnsl;
	uint32_t fnst;
	uint32_t fnsx;
	uint32_t fib;
	uint32_t bib;
	uint32_t fsnf;
	uint32_t cm;
};

static inline bool is_m2pa(const struct txc_fsm_data *tfd)
{
	return tfd->s7l->type == OSMO_SS7_LINK_TYPE_M2PA;
}

static void m2pa_txc_fsm_idle(struct osmo_fsm_inst *fi, uint32_t event ,void *data)
{
	struct txc_fsm_data *tfd = fi->priv;

	switch (event) {
	case MTP2_TXC_E_START:
		/* TXC -> DAEDT: Start */
		/* Cancel LSSU available */
		tfd->lssu_available = false;
		/* Cancel SIB received */
		tfd->sib_received = false;
		/* Cancel RTP full */
		tfd->rtb_full = false;
		/* Cancel MSU inhibited */
		tfd->msu_inhibited = false;
		/* initialize various variables */
		tfd->fsnl = 127;
		tfd->fsnt = 127;
		tfd->fsnx = 0;
		tfd->fib = tfd->bib = 1;
		tfd->fsnf = 0;
		tfd->cm = 0;
		osmo_fsm_inst_state_chg(fi, MTP2_TXC_S_IN_SERVICE, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void m2pa_txc_fsm_in_service(struct osmo_fsm_inst *fi, uint32_t event ,void *data)
{
	struct txc_fsm_data *tfd = fi->priv;
	struct osmo_m2pa_peer *m2p;

	if (is_m2pa(tfd))
		m2p = tfd->s7l->u.m2pa;
	else
		m2p = NULL;

	switch (event) {
	case MTP2_TXC_E_SEND_SIOS:
		/* Stop T7 */
		tfd->lssu_available = SIOS;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_OUT_OF_SERVICE);
		break;
	case MTP2_TXC_E_SEND_SIPO:
		/* Stop T7 */
		tfd->lssu_available = SIPO;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_PROCESSOR_OUTAGE);
		break;
	case MTP2_TXC_E_SEND_SIO:
		tfd->lssu_available = SIO;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_ALIGNMENT);
		break;
	case MTP2_TXC_E_SEND_SIN:
		tfd->lssu_available = SIN;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_PROVING_NORMAL);
		break;
	case MTP2_TXC_E_SEND_SIE:
		tfd->lssu_available = SIE;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_PROVING_EMERGENCY);
		break;
	case MTP2_TXC_E_SEND_SIB:
		tfd->lssu_available = SIB;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_BUSY);
		break;
	case MTP2_TXC_E_START:
		/* Cancel SIB received */
		tfd->sib_received = false;
		/* Cancel RTP full */
		tfd->rtb_full = false;
		/* Cancel MSU inhibited */
		tfd->msu_inhibited = false;
		/* initialize various variables */
		tfd->fsnl = 127;
		tfd->fsnt = 127;
		tfd->fsnx = 0;
		tfd->fib = tfd->bib = 1;
		tfd->fsnf = 0;
		tfd->cm = 0;
		osmo_fsm_inst_state_chg(fi, MTP2_TXC_S_IN_SERVICE, 0, 0);
		break;
	case MTP2_TXC_E_SEND_FISU:
		/* Stop T7 */
		/* Mark MSU inhibited */
		tfd->msu_inhibited = true;
		tfd->lssu_available = FISU;
		if (is_m2pa(tfd))
			osmo_m2pa_peer_send_link_status(m2p, M2PA_LSTS_READY);
		break;
	case MTP2_TXC_E_SEND_MSU:
		if (tfd->fsnl != tfd->fsnf - 1) {
			/* Start T7 */
		}
		/* Cancel MSU inhibited */
		tfd->msu_inhibited = false;
		tfd->lssu_available = NULL;
		break;
	case MTP2_TXC_E_NACK_TO_BE_SENT:
		ftd->bib = !ftd->bib;
		break;
	case MTP2_TXC_E_SIB_RECEIVED:
		if (!tfd->sib_received) {
			/* Start T6 */
			tfd->sib_received = true;
		}
		/* Start T7 */
		break;
	case MTP2_TXC_E_MSG_FOR_TX:
		/* Store MSU in TB */
		break;
	case MTP2_TSC_E_FLUSH_BUFFERS:
		/* Erase all MSUs in RTB and TB */
		/* Cancel RTB full */
		tfd->rtb_full = false;
		tfd->cm = 0;
		tfd->fsnf = tfd->bsnr + 1;
		tfd->fsnl = tfd->bsnr;
		tfd->fsnl = tfd->bsnr;
		break;
	default:
		OSMO_ASSERT(0);
	}
}


static const struct osmo_fsm_state m2pa_txc_fsm_states[] = {
	[MTP2_TXC_S_IDLE] = {
		.name = "IDLE",
		.action = m2pa_txc_fsm_idle,
		.in_event_mask = S(MTP2_TXC_E_START),
		.out_state_mask = S(MTP2_TXC_S_IDLE) |
				  S(MTP2_TXC_S_IN_SERVICE),
	},
	[MTP2_TXC_S_IN_SERVICE] = {
		.name = "IN_SERVICE",
		.action = m2pa_txc_fsm_in_service,
		.in_event_mask = S(MTP2_TXC_E_SEND_SIOS) |
				 S(MTP2_TXC_E_SEND_SIPO) |
				 S(MTP2_TXC_E_SEND_SIO) |
				 S(MTP2_TXC_E_SEND_SIN) |
				 S(MTP2_TXC_E_SEND_SIE) |
				 S(MTP2_TXC_E_SEND_SIB) |
				 S(MTP2_TXC_E_START) |
				 S(MTP2_TXC_E_SEND_FISU) |
				 S(MTP2_TXC_E_SEND_MSU) |
				 S(MTP2_TXC_E_NACK_TO_BE_SENT) |
				 S(MTP2_TXC_E_SIB_RECEIVED) |
				 S(MTP2_TXC_E_MSG_FOR_TX) |
				 S(MTP2_TSC_E_FLUSH_BUFFERS),
		.out_state_mask = S(MTP2_TXC_S_IN_SERVICE),
	},
};

struct osmo_fsm m2pa_txc_fsm = {
};
