#pragma once

enum xua_asp_state {
	XUA_ASP_S_DOWN,
	XUA_ASP_S_INACTIVE,
	XUA_ASP_S_ACTIVE,
};

enum xua_asp_event {
	XUA_ASP_E_M_ASP_UP_REQ,
	XUA_ASP_E_M_ASP_ACTIVE_REQ,
	XUA_ASP_E_M_ASP_DOWN_REQ,
	XUA_ASP_E_M_ASP_INACTIVE_REQ,

	XUA_ASP_E_SCTP_COMM_DOWN_IND,
	XUA_ASP_E_SCTP_RESTART_IND,
	XUA_ASP_E_SCTP_EST_IND,

	XUA_ASP_E_ASPSM_ASPUP,
	XUA_ASP_E_ASPSM_ASPUP_ACK,
	XUA_ASP_E_ASPTM_ASPAC,
	XUA_ASP_E_ASPTM_ASPAC_ACK,
	XUA_ASP_E_ASPSM_ASPDN,
	XUA_ASP_E_ASPSM_ASPDN_ACK,
	XUA_ASP_E_ASPTM_ASPIA,
	XUA_ASP_E_ASPTM_ASPIA_ACK,

	XUA_ASP_E_ASPSM_BEAT,
	XUA_ASP_E_ASPSM_BEAT_ACK,

	/* IPA specific */
	IPA_ASP_E_ID_RESP,
	IPA_ASP_E_ID_ACK,
	IPA_ASP_E_ID_GET,

	_NUM_XUA_ASP_E
};

extern struct osmo_fsm xua_asp_fsm;
extern struct osmo_fsm ipa_asp_fsm;

struct osmo_fsm_inst *xua_asp_fsm_start(struct osmo_ss7_asp *asp,
					enum osmo_ss7_asp_role role, int log_level);
