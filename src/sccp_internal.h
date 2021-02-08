#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>

#define SCCP_STR "Signalling Connection Control Part\n"

/* Appendix C.4 of Q.714 */
enum osmo_sccp_timer {
	OSMO_SCCP_TIMER_CONN_EST,
	OSMO_SCCP_TIMER_IAS,
	OSMO_SCCP_TIMER_IAR,
	OSMO_SCCP_TIMER_REL,
	OSMO_SCCP_TIMER_REPEAT_REL,
	OSMO_SCCP_TIMER_INT,
	OSMO_SCCP_TIMER_GUARD,
	OSMO_SCCP_TIMER_RESET,
	OSMO_SCCP_TIMER_REASSEMBLY,
	/* This must remain the last item: */
	OSMO_SCCP_TIMERS_COUNT
};

struct osmo_sccp_timer_val {
	uint32_t s;
	uint32_t us;
};

extern const struct osmo_sccp_timer_val osmo_sccp_timer_defaults[];

extern const struct value_string osmo_sccp_timer_names[];
static inline const char *osmo_sccp_timer_name(enum osmo_sccp_timer val)
{ return get_value_string(osmo_sccp_timer_names, val); }

extern const struct value_string osmo_sccp_timer_descriptions[];
static inline const char *osmo_sccp_timer_description(enum osmo_sccp_timer val)
{ return get_value_string(osmo_sccp_timer_descriptions, val); }

/* an instance of the SCCP stack */
struct osmo_sccp_instance {
	/* entry in global list of ss7 instances */
	struct llist_head list;
	/* list of 'struct sccp_connection' in this instance */
	struct llist_head connections;
	/* list of SCCP users in this instance */
	struct llist_head users;
	/* routing context to be used in all outbound messages */
	uint32_t route_ctx;
	/* next connection ID to allocate */
	uint32_t next_id;
	struct osmo_ss7_instance *ss7;
	void *priv;

	struct osmo_ss7_user ss7_user;

	struct osmo_sccp_timer_val timers[OSMO_SCCP_TIMERS_COUNT];
};

struct osmo_sccp_user {
	/*! \brief entry in list of sccp users of \ref osmo_sccp_instance */
	struct llist_head list;
	/*! \brief pointer back to SCCP instance */
	struct osmo_sccp_instance *inst;
	/*! \brief human-readable name of this user */
	char *name;

	/*! \brief SSN and/or point code to which we are bound */
	uint16_t ssn;
	uint32_t pc;

	/* set if we are a server */
	struct llist_head links;

	/* user call-back function in case of incoming primitives */
	osmo_prim_cb prim_cb;
	void *priv;

	/* Application Server FSM Instance */
	struct osmo_fsm_inst *as_fi;
};

extern int DSCCP;

struct xua_msg;

struct osmo_sccp_user *
sccp_user_find(struct osmo_sccp_instance *inst, uint16_t ssn, uint32_t pc);

/* Message from SCOC -> SCRC */
int sccp_scrc_rx_scoc_conn_msg(struct osmo_sccp_instance *inst,
				struct xua_msg *xua);

/* Message from SCLC -> SCRC */
int sccp_scrc_rx_sclc_msg(struct osmo_sccp_instance *inst, struct xua_msg *xua);

/* Message from MTP (SUA) -> SCRC */
int scrc_rx_mtp_xfer_ind_xua(struct osmo_sccp_instance *inst,
			     struct xua_msg *xua);

/* Message from SCRC -> SCOC */
void sccp_scoc_rx_from_scrc(struct osmo_sccp_instance *inst,
			    struct xua_msg *xua);
void sccp_scoc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua, uint32_t cause);

void sccp_scoc_flush_connections(struct osmo_sccp_instance *inst);

/* Message from SCRC -> SCLC */
int sccp_sclc_rx_from_scrc(struct osmo_sccp_instance *inst,
			   struct xua_msg *xua);
void sccp_sclc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua, uint32_t cause);

int sccp_user_prim_up(struct osmo_sccp_user *scut, struct osmo_scu_prim *prim);

/* SCU -> SCLC */
int sccp_sclc_user_sap_down(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph);
int sccp_sclc_user_sap_down_nofree(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph);

struct msgb *sccp_msgb_alloc(const char *name);

extern struct osmo_fsm sccp_scoc_fsm;

void sccp_scoc_show_connections(struct vty *vty, struct osmo_sccp_instance *inst);

const struct osmo_sccp_timer_val *osmo_sccp_timer_get(const struct osmo_sccp_instance *inst,
						      enum osmo_sccp_timer timer,
						      bool default_if_unset);

void osmo_sccp_vty_write_cs7_node(struct vty *vty, const char *indent, struct osmo_sccp_instance *inst);

/* Local Broadcast (LBCS) */
void sccp_lbcs_local_bcast_pcstate(struct osmo_sccp_instance *inst,
				   const struct osmo_scu_pcstate_param *pcstate);
void sccp_lbcs_local_bcast_state(struct osmo_sccp_instance *inst,
				   const struct osmo_scu_state_param *state);

/* SCCP Management (SCMG) */
void sccp_scmg_rx_ssn_allowed(struct osmo_sccp_instance *inst, uint32_t dpc, uint32_t ssn, uint32_t smi);
void sccp_scmg_rx_ssn_prohibited(struct osmo_sccp_instance *inst, uint32_t dpc, uint32_t ssn, uint32_t smi);
void sccp_scmg_rx_mtp_pause(struct osmo_sccp_instance *inst, uint32_t dpc);
void sccp_scmg_rx_mtp_resume(struct osmo_sccp_instance *inst, uint32_t dpc);
int sccp_scmg_init(struct osmo_sccp_instance *inst);
