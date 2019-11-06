#pragma once

struct osmo_ss7_as;

enum xua_as_state {
	XUA_AS_S_DOWN,
	XUA_AS_S_INACTIVE,
	XUA_AS_S_ACTIVE,
	XUA_AS_S_PENDING,
};

enum xua_as_event {
	XUA_ASPAS_ASP_INACTIVE_IND,
	XUA_ASPAS_ASP_DOWN_IND,
	XUA_ASPAS_ASP_ACTIVE_IND,
	XUA_AS_E_RECOVERY_EXPD,
	XUA_AS_E_TRANSFER_REQ,
};

extern struct osmo_fsm xua_as_fsm;

struct osmo_fsm_inst *xua_as_fsm_start(struct osmo_ss7_as *as, int log_level);
