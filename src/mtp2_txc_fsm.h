#pragma once
#include <osmocom/core/fsm.h>

enum mtp2_txc_event {
	MTP2_TXC_E_START,			/* LSC -> TXC: Start */
	MTP2_TXC_E_SEND_SIOS,			/* LSC -> TXC: Send SIOS */
	MTP2_TXC_E_SEND_SIPO,			/* LSC -> TXC: Send SIPO */
	MTP2_TXC_E_SEND_FISU,			/* LSC -> TXC: Send FISU */
	MTP2_TXC_E_SEND_MSU,			/* LSC -> TXC: Send MSU */
	MTP2_TXC_E_FLUSH_BUFFERS,		/* LSC -> TXC: Flush Buffers */
	MTP2_TXC_E_SEND_MSU,			/* LSC -> TXC: Send MSU/FISU */

	MTP2_TXC_E_SEND_SIO,			/* IAC -> TXC: Send SIO */
	MTP2_TXC_E_SEND_SIE,			/* IAC -> TXC: Send SIE */
	MTP2_TXC_E_SEND_SIN,			/* IAC -> TXC: Send SIN */

	MTP2_TXC_E_SEND_SIB,			/* CC -> TXC: Send SIB */

	MTP2_TXC_E_NACK_TO_BE_SENT,		/* RC -> TXC: NACK To be sent */
	MTP2_TXC_E_SIB_RECEIVED,		/* RC -> TXC: SIB Received */
	MTP2_TXC_E_MSG_FOR_TX,			/* L3 -> TXC: Message for transmission */
	//MTP2_TXC_E_BSNR_AND_BIBR,		/* RC -> TXC */
	//MTP2_TXC_E_FSNX_VALUE,		/* RC -> TXC */
	MTP2_TSC_E_FLUSH_BUFFERS,		/* LSC -> TXC: Flush buffers */
};

enum mtp2_txc_fsm_state {
	MTP2_TXC_S_IDLE,
	MTP2_TXC_S_IN_SERVICE,
};
