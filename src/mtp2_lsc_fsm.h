#pragma once
#include <osmocom/core/fsm.h>

enum mtp2_lsc_fsm_event {
	MTP_LSC_E_POWER_ON, 			/* MGMT -> LSC */
	MTP_LSC_E_START,			/* L3 -> LSC */
	MTP_LSC_E_EMERGENCY,			/* L3 -> LSC */
	MTP_LSC_E_EMERGENCY_CEASES,		/* L3 -> LSC */
	MTP_LSC_E_LOCAL_PROC_OUTAGE,		/* MGMT -> LSC */
	MTP_LSC_E_LOCAL_PROC_OUTAGE_RECOVD,	/* MGMT -> LSC */
	MTP_LSC_E_LEVEL3_FAILURE,		/* MGMT -> LSC */
	MTP_LSC_E_ALIGNMENT_COMPLETE,		/* IAC -> LSC */
	MTP_LSC_E_STOP,				/* L3 -> LSC */
	MTP_LSC_E_LINK_FAILURE,			/* RC -> LSC */
	MTP_LSC_E_ALIGNMENT_NOT_POSSIBLE,	/* IAC -> LSC */
	MTP_LSC_E_RX_SIO_SIOS,			/* RC -> LSC */
	MTP_LSC_E_RX_SIPO,			/* RC -> LSC */
	MTP_LSC_E_RX_FISU_MSU,			/* RC -> LSC */
	MTP_LSC_E_FLUSH_BUFFERS,		/* L3 -> LSC */
	MTP_LSC_E_CONTINUE,			/* L3 -> LSC */
	MTP_LSC_E_NO_PROC_OUTAGE,		/* POC -> LSC */
	MTP_LSC_E_T1_EXP,			/* LSC -> LSC */

};

extern struct osmo_fsm mtp2_lsc_fsm;
