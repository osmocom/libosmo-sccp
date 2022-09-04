#pragma once
#include <osmocom/core/fsm.h>

enum mtp2_iac_fsm_event {
	MTP2_IAC_E_EMERGENCY,
	MTP2_IAC_E_START,
	MTP2_IAC_E_STOP,
	MTP2_IAC_E_RX_SIO,
	MTP2_IAC_E_RX_SIOS,
	MTP2_IAC_E_RX_SIN,
	MTP2_IAC_E_RX_SIE,
	MTP2_IAC_E_CORRECT_SU,
	MTP2_IAC_E_ABORT_PROVING,
};

extern struct osmo_fsm mtp2_iac_fsm;
