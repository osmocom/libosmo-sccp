/* SCCP Connection Oriented (SCOC) according to ITU-T Q.713/Q.714 */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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

/* This code is a bit of a hybrid between the ITU-T Q.71x specifications
 * for SCCP (particularly its connection-oriented part), and the IETF
 * RFC 3868 (SUA).  The idea here is to have one shared code base of the
 * state machines for SCCP Connection Oriented, and use those both from
 * SCCP and SUA.
 *
 * To do so, all SCCP messages are translated to SUA messages in the
 * input side, and all generated SUA messages are translated to SCCP on
 * the output side.
 *
 * The Choice of going for SUA messages as the "native" format was based
 * on their easier parseability, and the fact that there are features in
 * SUA which classic SCCP cannot handle (like IP addresses in GT).
 * However, all SCCP features can be expressed in SUA.
 *
 * The code only supports Class 2.  No support for Class 3 is intended,
 * but patches are of course always welcome.
 *
 * Missing other features:
 *  * Segmentation/Reassembly support
 *  * T(guard) after (re)start
 *  * freezing of local references
 *  * parsing/encoding of IPv4/IPv6 addresses
 *  * use of multiple Routing Contexts in SUA case
 */

#include <errno.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sccp/sccp_types.h>

#include "xua_internal.h"
#include "sccp_internal.h"

#define S(x)	(1 << (x))
#define SCU_MSGB_SIZE	1024

/***********************************************************************
 * SCCP connection table
 ***********************************************************************/

/* a logical connection within the SCCP instance */
struct sccp_connection {
	/* entry in (struct sccp_instance)->connections */
	struct rb_node node;
	/* which instance are we part of? */
	struct osmo_sccp_instance *inst;
	/* which user owns us? */
	struct osmo_sccp_user *user;

	/* remote point code */
	uint32_t remote_pc;

	/* local/remote addresses and identities */
	struct osmo_sccp_addr calling_addr;
	struct osmo_sccp_addr called_addr;
	/* SCCP connection identifier. Only relevant across the SCCP User SAP,
	 * i.e. between the local application using the SCCP stack provided by
	 * libosmo-sccp.  Never transmitted over the wire! */
	uint32_t conn_id;
	/* SCCP Remote Connection Reference.  Allocated by the remote
	 * SCCP stack to uniquely identify a SCCP connection on its end.
	 * We don't interpret it, but simply cache it here so we can use
	 * it whenever sending data to the peer. Only relevant over the
	 * wire, not to be used across the SCCP user SAP */
	uint32_t remote_ref;

	uint32_t importance;
	uint32_t sccp_class;
	uint32_t release_cause; /* WAIT_CONN_CONF */

	struct msgb *opt_data_cache;

	/* incoming (true) or outgoing (false) */
	bool incoming;

	/* Osmo FSM Instance of sccp_scoc_fsm */
	struct osmo_fsm_inst *fi;

	/* Connect timer */
	struct osmo_timer_list t_conn;

	/* inactivity timers */
	struct osmo_timer_list t_ias;
	struct osmo_timer_list t_iar;

	/* release timers */
	struct osmo_timer_list t_rel;
	struct osmo_timer_list t_int;
	struct osmo_timer_list t_rep_rel;
};

/***********************************************************************
 * various helper functions
 ***********************************************************************/

enum sccp_connection_state {
	S_IDLE,
	S_CONN_PEND_IN,
	S_CONN_PEND_OUT,
	S_ACTIVE,
	S_DISCONN_PEND,
	S_RESET_IN,
	S_RESET_OUT,
	S_BOTHWAY_RESET,
	S_WAIT_CONN_CONF,
};

/* Events that this FSM can process */
enum sccp_scoc_event {
	/* Primitives from SCCP-User */
	SCOC_E_SCU_N_CONN_REQ,
	SCOC_E_SCU_N_CONN_RESP,
	SCOC_E_SCU_N_DISC_REQ,
	SCOC_E_SCU_N_DATA_REQ,
	SCOC_E_SCU_N_EXP_DATA_REQ,

	/* Events from RCOC (Routing for Connection Oriented) */
	SCOC_E_RCOC_CONN_IND,
	SCOC_E_RCOC_ROUT_FAIL_IND,
	SCOC_E_RCOC_RLSD_IND,
	SCOC_E_RCOC_REL_COMPL_IND,
	SCOC_E_RCOC_CREF_IND,
	SCOC_E_RCOC_CC_IND,
	SCOC_E_RCOC_DT1_IND,
	SCOC_E_RCOC_DT2_IND,
	SCOC_E_RCOC_IT_IND,
	SCOC_E_RCOC_OTHER_NPDU,
	SCOC_E_RCOC_ERROR_IND,

	/* Timer Events */
	SCOC_E_T_IAR_EXP,
	SCOC_E_T_IAS_EXP,

	SCOC_E_CONN_TMR_EXP,

	SCOC_E_T_REL_EXP,
	SCOC_E_T_INT_EXP,
	SCOC_E_T_REP_REL_EXP,
};

static const struct value_string scoc_event_names[] = {
	/* Primitives from SCCP-User */
	{ SCOC_E_SCU_N_CONN_REQ,	"N-CONNECT.req" },
	{ SCOC_E_SCU_N_CONN_RESP,	"N-CONNECT.resp" },
	{ SCOC_E_SCU_N_DISC_REQ,	"N-DISCONNECT.req" },
	{ SCOC_E_SCU_N_DATA_REQ,	"N-DATA.req" },
	{ SCOC_E_SCU_N_EXP_DATA_REQ,	"N-EXPEDITED_DATA.req" },

	/* Events from RCOC (Routing for Connection Oriented) */
	{ SCOC_E_RCOC_CONN_IND,		"RCOC-CONNECT.ind" },
	{ SCOC_E_RCOC_ROUT_FAIL_IND,	"RCOC-ROUT_FAIL.ind" },
	{ SCOC_E_RCOC_RLSD_IND,		"RCOC-RELEASED.ind" },
	{ SCOC_E_RCOC_REL_COMPL_IND,	"RCOC-RELEASE_COMPLETE.ind" },
	{ SCOC_E_RCOC_CREF_IND,		"RCOC-CONNECT_REFUSED.ind" },
	{ SCOC_E_RCOC_CC_IND,		"RCOC-CONNECT_CONFIRM.ind" },
	{ SCOC_E_RCOC_DT1_IND,		"RCOC-DT1.ind" },
	{ SCOC_E_RCOC_DT2_IND,		"RCOC-DT2.ind" },
	{ SCOC_E_RCOC_IT_IND,		"RCOC-IT.ind" },
	{ SCOC_E_RCOC_OTHER_NPDU,	"RCOC-OTHER_NPDU.ind" },
	{ SCOC_E_RCOC_ERROR_IND,	"RCOC-ERROR.ind" },

	{ SCOC_E_T_IAR_EXP,		"T(iar)_expired" },
	{ SCOC_E_T_IAS_EXP,		"T(ias)_expired" },
	{ SCOC_E_CONN_TMR_EXP,		"T(conn)_expired" },
	{ SCOC_E_T_REL_EXP,		"T(rel)_expired" },
	{ SCOC_E_T_INT_EXP,		"T(int)_expired" },
	{ SCOC_E_T_REP_REL_EXP,		"T(rep_rel)_expired" },

	{ 0, NULL }
};

/* how to map a SCCP CO message to an event */
static const struct xua_msg_event_map sua_scoc_event_map[] = {
	{ SUA_MSGC_CO, SUA_CO_CORE, SCOC_E_RCOC_CONN_IND },
	{ SUA_MSGC_CO, SUA_CO_RELRE, SCOC_E_RCOC_RLSD_IND },
	{ SUA_MSGC_CO, SUA_CO_RELCO, SCOC_E_RCOC_REL_COMPL_IND },
	{ SUA_MSGC_CO, SUA_CO_COREF, SCOC_E_RCOC_CREF_IND },
	{ SUA_MSGC_CO, SUA_CO_COAK, SCOC_E_RCOC_CC_IND },
	{ SUA_MSGC_CO, SUA_CO_CODT, SCOC_E_RCOC_DT1_IND },
	{ SUA_MSGC_CO, SUA_CO_COIT, SCOC_E_RCOC_IT_IND },
	{ SUA_MSGC_CO, SUA_CO_COERR, SCOC_E_RCOC_ERROR_IND },
};


/* map from SCU-primitives to SCOC FSM events */
static const struct osmo_prim_event_map scu_scoc_event_map[] = {
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_CONN_REQ },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_RESPONSE,
		SCOC_E_SCU_N_CONN_RESP },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_DATA_REQ },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_DISC_REQ },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_EXPEDITED_DATA, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_EXP_DATA_REQ },
	{ 0, 0, 0, OSMO_NO_EVENT }
};

/***********************************************************************
 * Timer Handling
 ***********************************************************************/

/* Mostly pasted from Appendix C.4 of ITU-T Q.714 (05/2001) -- some of their descriptions are quite
 * unintelligible out of context, for which we have our own description here. */
const struct osmo_tdef osmo_sccp_timer_defaults[OSMO_SCCP_TIMERS_LEN] = {
	{ .T = OSMO_SCCP_TIMER_CONN_EST,	.default_val = 1*60,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for connection confirm message, 1 to 2 minutes" },
	{ .T = OSMO_SCCP_TIMER_IAS,		.default_val = 7*60,	.unit = OSMO_TDEF_S,
	  .desc = "Send keep-alive: on an idle connection, delay before sending an Idle Timer message, 5 to 10 minutes" }, /* RFC 3868 Ch. 8. */
	{ .T = OSMO_SCCP_TIMER_IAR,		.default_val = 15*60,	.unit = OSMO_TDEF_S,
	  .desc = "Receive keep-alive: on an idle connection, delay until considering a connection as stale, 11 to 21 minutes" }, /* RFC 3868 Ch. 8. */
	{ .T = OSMO_SCCP_TIMER_REL,		.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for release complete message, 10 to 20 seconds" },
	{ .T = OSMO_SCCP_TIMER_REPEAT_REL,	.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for release complete message; or to repeat sending released message after the initial expiry, 10 to 20 seconds" },
	{ .T = OSMO_SCCP_TIMER_INT,		.default_val = 1*60,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for release complete message; or to release connection resources, freeze the LRN and "
		  "alert a maintenance function after the initial expiry, extending to 1 minute" },
	{ .T = OSMO_SCCP_TIMER_GUARD,		.default_val = 23*60,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting to resume normal procedure for temporary connection sections during the restart procedure, 23 to 25 minutes" },
	{ .T = OSMO_SCCP_TIMER_RESET,		.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting to release temporary connection section or alert maintenance function after reset request message is sent, 10 to 20 seconds" },
	{ .T = OSMO_SCCP_TIMER_REASSEMBLY,	.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting to receive all the segments of the remaining segments, single segmented message after receiving the first segment, 10 to 20 seconds" },
	{}
};

/* Appendix C.4 of ITU-T Q.714 */
const struct value_string osmo_sccp_timer_names[] = {
	{ OSMO_SCCP_TIMER_CONN_EST, "conn_est" },
	{ OSMO_SCCP_TIMER_IAS, "ias" },
	{ OSMO_SCCP_TIMER_IAR, "iar" },
	{ OSMO_SCCP_TIMER_REL, "rel" },
	{ OSMO_SCCP_TIMER_REPEAT_REL, "repeat_rel" },
	{ OSMO_SCCP_TIMER_INT, "int" },
	{ OSMO_SCCP_TIMER_GUARD, "guard" },
	{ OSMO_SCCP_TIMER_RESET, "reset" },
	{ OSMO_SCCP_TIMER_REASSEMBLY, "reassembly" },
	{}
};

osmo_static_assert(ARRAY_SIZE(osmo_sccp_timer_defaults) == (OSMO_SCCP_TIMERS_LEN) &&
		   ARRAY_SIZE(osmo_sccp_timer_names) == (OSMO_SCCP_TIMERS_LEN),
		   assert_osmo_sccp_timers_count);

static void sccp_timer_schedule(const struct sccp_connection *conn,
				struct osmo_timer_list *timer,
				enum osmo_sccp_timer timer_name)
{
	const unsigned long val_sec = osmo_tdef_get(conn->inst->tdefs, timer_name, OSMO_TDEF_S, -1);
	osmo_timer_schedule(timer, val_sec, 0);
}

/* T(ias) has expired, send a COIT message to the peer */
static void tx_inact_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_IAS_EXP, NULL);
}

/* T(iar) has expired, notify the FSM about it */
static void rx_inact_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_IAR_EXP, NULL);
}

/* T(rel) has expired, notify the FSM about it */
static void rel_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_REL_EXP, NULL);
}

/* T(int) has expired, notify the FSM about it */
static void int_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_INT_EXP, NULL);
}

/* T(repeat_rel) has expired, notify the FSM about it */
static void rep_rel_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_REP_REL_EXP, NULL);
}

/* T(conn) has expired, notify the FSM about it */
static void conn_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_CONN_TMR_EXP, NULL);
}

/* Re-start the Tx inactivity timer */
static void conn_restart_tx_inact_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_ias, OSMO_SCCP_TIMER_IAS);
}

/* Re-start the Rx inactivity timer */
static void conn_restart_rx_inact_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_iar, OSMO_SCCP_TIMER_IAR);
}

/* Re-start both Rx and Tx inactivity timers */
static void conn_start_inact_timers(struct sccp_connection *conn)
{
	conn_restart_tx_inact_timer(conn);
	conn_restart_rx_inact_timer(conn);
}

/* Stop both Rx and Tx inactivity timers */
static void conn_stop_inact_timers(struct sccp_connection *conn)
{
	osmo_timer_del(&conn->t_ias);
	osmo_timer_del(&conn->t_iar);
}

/* Start release timer T(rel) */
static void conn_start_rel_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_rel, OSMO_SCCP_TIMER_REL);
}

/* Start repeat release timer T(rep_rel) */
static void conn_start_rep_rel_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_rep_rel, OSMO_SCCP_TIMER_REPEAT_REL);
}

/* Start interval timer T(int) */
static void conn_start_int_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_int, OSMO_SCCP_TIMER_INT);
}

/* Stop all release related timers: T(rel), T(int) and T(rep_rel) */
static void conn_stop_release_timers(struct sccp_connection *conn)
{
	osmo_timer_del(&conn->t_rel);
	osmo_timer_del(&conn->t_int);
	osmo_timer_del(&conn->t_rep_rel);
}

/* Start connect timer T(conn) */
static void conn_start_connect_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_conn, OSMO_SCCP_TIMER_CONN_EST);
}

/* Stop connect timer T(conn) */
static void conn_stop_connect_timer(struct sccp_connection *conn)
{
	osmo_timer_del(&conn->t_conn);
}


/***********************************************************************
 * SUA Instance and Connection handling
 ***********************************************************************/

static void conn_destroy(struct sccp_connection *conn);

static struct sccp_connection *conn_find_by_id(const struct osmo_sccp_instance *inst, uint32_t id)
{
	struct sccp_connection *conn;
	const struct rb_node *node = inst->connections.rb_node;

	while (node) {
		conn = container_of(node, struct sccp_connection, node);
		if (id < conn->conn_id)
			node = node->rb_left;
		else if (id > conn->conn_id)
			node = node->rb_right;
		else
			return conn;
	}
	return NULL;
}

static int conn_add_node(struct osmo_sccp_instance *inst, struct sccp_connection *conn)
{
	struct rb_node **n = &(inst->connections.rb_node);
	struct rb_node *parent = NULL;

	while (*n) {
		struct sccp_connection *it;

		it = container_of(*n, struct sccp_connection, node);

		parent = *n;
		if (conn->conn_id < it->conn_id) {
			n = &((*n)->rb_left);
		} else if (conn->conn_id > it->conn_id) {
			n = &((*n)->rb_right);
		} else {
			LOGP(DLSCCP, LOGL_ERROR,
			     "Trying to reserve already reserved conn_id %u\n", conn->conn_id);
			return -EEXIST;
		}
	}

	rb_link_node(&conn->node, parent, n);
	rb_insert_color(&conn->node, &inst->connections);
	return 0;
}

bool osmo_sccp_conn_id_exists(const struct osmo_sccp_instance *inst, uint32_t id)
{
	return conn_find_by_id(inst, id) ? true : false;
}

#define INIT_TIMER(x, fn, priv)		do { (x)->cb = fn; (x)->data = priv; } while (0)

/* allocate + init a SCCP Connection with given ID */
static struct sccp_connection *conn_create_id(struct osmo_sccp_user *user, uint32_t conn_id)
{
	struct sccp_connection *conn = talloc_zero(user->inst, struct sccp_connection);
	char name[16];

	conn->conn_id = conn_id;
	conn->inst = user->inst;
	conn->user = user;

	if (conn_add_node(user->inst, conn) < 0) {
		talloc_free(conn);
		return NULL;
	}

	INIT_TIMER(&conn->t_conn, conn_tmr_cb, conn);
	INIT_TIMER(&conn->t_ias, tx_inact_tmr_cb, conn);
	INIT_TIMER(&conn->t_iar, rx_inact_tmr_cb, conn);
	INIT_TIMER(&conn->t_rel, rel_tmr_cb, conn);
	INIT_TIMER(&conn->t_int, int_tmr_cb, conn);
	INIT_TIMER(&conn->t_rep_rel, rep_rel_tmr_cb, conn);

	/* this might change at runtime, as it is not a constant :/ */
	sccp_scoc_fsm.log_subsys = DLSCCP;

	/* we simply use the connection ID as FSM instance name */
	snprintf(name, sizeof(name), "%u", conn->conn_id);
	conn->fi = osmo_fsm_inst_alloc(&sccp_scoc_fsm, conn, conn,
					LOGL_DEBUG, name);
	if (!conn->fi) {
		rb_erase(&conn->node, &user->inst->connections);
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

/* Return an unused SCCP connection ID.
 * Callers should check the returned value: on negative return value, there are no unused IDs available.
 * \param[in] sccp  The SCCP instance to determine a new connection ID for.
 * \return unused ID on success (range [0x0, 0x00fffffe]) or negative on elapsed max_attempts without an unused id (<0).
 */
int osmo_sccp_instance_next_conn_id(struct osmo_sccp_instance *sccp)
{
	int max_attempts = 0x00FFFFFE;

	/* SUA: RFC3868 sec 3.10.4:
	*    The source reference number is a 4 octet long integer.
	*    This is allocated by the source SUA instance.
	* M3UA/SCCP: ITU-T Q.713 sec 3.3:
	*    The "source local reference" parameter field is a three-octet field containing a
	*    reference number which is generated and used by the local node to identify the
	*    connection section after the connection section is set up.
	*    The coding "all ones" is reserved for future use.
	* Hence, as we currently use the connection ID also as local reference,
	* let's simply use 24 bit ids to fit all link types (excluding 0x00ffffff).
	*/
	while (OSMO_LIKELY((max_attempts--) > 0)) {
		/* Optimized modulo operation (% 0x00FFFFFE) using bitwise AND plus CMP: */
		sccp->next_id = (sccp->next_id + 1) & 0x00FFFFFF;
		if (OSMO_UNLIKELY(sccp->next_id == 0x00FFFFFF))
			sccp->next_id = 0;

		if (!conn_find_by_id(sccp, sccp->next_id))
			return sccp->next_id;
	}

	return -1;
}

/* Search for next free connection ID and allocate conn */
static struct sccp_connection *conn_create(struct osmo_sccp_user *user)
{
	int conn_id = osmo_sccp_instance_next_conn_id(user->inst);
	if (conn_id < 0)
		return NULL;
	return conn_create_id(user, conn_id);
}

static void conn_opt_data_clear_cache(struct sccp_connection *conn)
{
	if (conn->opt_data_cache) {
		msgb_free(conn->opt_data_cache);
		conn->opt_data_cache = NULL;
	}
}

/* destroy a SCCP connection state, releasing all timers, terminating
 * FSM and releasing associated memory */
static void conn_destroy(struct sccp_connection *conn)
{
	conn_opt_data_clear_cache(conn);

	conn_stop_connect_timer(conn);
	conn_stop_inact_timers(conn);
	conn_stop_release_timers(conn);
	rb_erase(&conn->node, &conn->inst->connections);

	osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_REQUEST, NULL);

	talloc_free(conn);
}

/* allocate a message buffer for an SCCP User Primitive */
static struct msgb *scu_msgb_alloc(void)
{
	return msgb_alloc(SCU_MSGB_SIZE, "SCCP User Primitive");
}

/* generate a RELRE (release request) xua_msg for given conn */
static struct xua_msg *xua_gen_relre(struct sccp_connection *conn,
				     uint32_t cause,
				     struct osmo_scu_prim *prim)
{
	struct xua_msg *xua = xua_msg_alloc();

	if (!xua)
		return NULL;

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RELEASE | cause);
	/* optional: importance */
	if (prim && msgb_l2(prim->oph.msg))
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));

	return xua;
}

/* generate xua_msg, encode it and send it to SCRC */
static int xua_gen_relre_and_send(struct sccp_connection *conn, uint32_t cause,
				  struct osmo_scu_prim *prim)
{
	struct xua_msg *xua;

	xua = xua_gen_relre(conn, cause, prim);
	if (!xua)
		return -1;

	/* amend this with point code information; The SUA RELRE
	 * includes neither called nor calling party address! */
	xua->mtp.dpc = conn->remote_pc;
	sccp_scrc_rx_scoc_conn_msg(conn->inst, xua);
	xua_msg_free(xua);
	return 0;
}

/* Send cached optional data (if any) from expected message type and clear cache */
static void xua_opt_data_send_cache(struct sccp_connection *conn, int exp_type, uint8_t msg_class)
{
	const struct xua_dialect *dialect = &xua_dialect_sua;
	const struct xua_msg_class *xmc = dialect->class[msg_class];

	if (!conn->opt_data_cache)
		return;

	if (conn->opt_data_cache->cb[0] != exp_type) {
		/* Caller (from the FSM) knows what was the source of Optional Data we're sending.
		 * Compare this information with source of Optional Data recorded while caching
		 * to make sure we're on the same page.
		 */
		LOGP(DLSCCP, LOGL_ERROR, "unexpected message type %s != cache source %s\n",
			 xua_class_msg_name(xmc, exp_type), xua_class_msg_name(xmc, conn->opt_data_cache->cb[0]));
	} else {
		osmo_sccp_tx_data(conn->user, conn->conn_id, msgb_data(conn->opt_data_cache), msgb_length(conn->opt_data_cache));
	}

	conn_opt_data_clear_cache(conn);
}

/* Check if optional data should be dropped, log given error message if so */
static bool xua_drop_data_check_drop(const struct osmo_scu_prim *prim, unsigned lim, const char *message)
{
	if (msgb_l2len(prim->oph.msg) > lim) {
		LOGP(DLSCCP, LOGL_ERROR,
			 "%s: dropping optional data with length %u > %u - %s\n",
			 osmo_scu_prim_name(&prim->oph), msgb_l2len(prim->oph.msg), lim, message);
		return true;
	}
	return false;
}

/* Cache the optional data (if necessary)
 * returns true if Optional Data should be kept while encoding the message */
static bool xua_opt_data_cache_keep(struct sccp_connection *conn, const struct osmo_scu_prim *prim, int msg_type)
{
	uint8_t *buf;
	uint32_t max_optional_data = conn->inst->max_optional_data;

	if (xua_drop_data_check_drop(prim, SCCP_MAX_DATA, "cache overrun"))
		return false;

	if (msgb_l2len(prim->oph.msg) > max_optional_data) {
		if (conn->opt_data_cache) {
			/* Caching optional data, but there already is optional data occupying the cache: */
			LOGP(DLSCCP, LOGL_ERROR, "replacing unsent %u bytes of optional data cache with %s optional data\n",
				 msgb_length(conn->opt_data_cache), osmo_scu_prim_name(&prim->oph));
			msgb_trim(conn->opt_data_cache, 0);
		} else {
			conn->opt_data_cache = msgb_alloc_c(conn, SCCP_MAX_DATA, "SCCP optional data cache for CR/CC/RLSD");
		}

		buf = msgb_put(conn->opt_data_cache, msgb_l2len(prim->oph.msg));
		memcpy(buf, msgb_l2(prim->oph.msg), msgb_l2len(prim->oph.msg));

		conn->opt_data_cache->cb[0] = msg_type;

		return false;
	}
	return true;
}

/* Check optional Data size limit, cache if necessary, return indication whether original opt data should be sent */
static bool xua_opt_data_length_lim(struct sccp_connection *conn, const struct osmo_scu_prim *prim, int msg_type)
{
	uint32_t max_optional_data = conn->inst->max_optional_data;

	if (!(prim && msgb_l2(prim->oph.msg) && msgb_l2len(prim->oph.msg)))
		return false;

	switch (msg_type) {
	case SUA_CO_CORE: /* §4.2 Connection request (CR) */
	case SUA_CO_COAK: /* §4.3 Connection confirm (CC) */
		return xua_opt_data_cache_keep(conn, prim, msg_type);
	case SUA_CO_COREF: /* §4.4 Connection refused (CREF) */
		if (xua_drop_data_check_drop(prim, max_optional_data, "over ITU-T Rec. Q.713 §4.4 limit")) {
			/* From the state diagrams in ITU-T Rec Q.714, there's no way to send DT1 neither before nor after CREF
			 * at this point, so the only option we have is to drop optional data:
			 * see Figure C.3 / Q.714 (sheet 2 of 6) */
			return false;
		}
		break;
	case SUA_CO_RELRE: /* §4.5 Released (RLSD) */
		if (msgb_l2len(prim->oph.msg) > max_optional_data) {
			if (xua_drop_data_check_drop(prim, SCCP_MAX_DATA, "protocol error"))
				return false;
			/* There's no need to cache the optional data since the connection is still active at this point:
			 * Send the Optional Data in a DT1 ahead of the RLSD, because it is too large to be sent in one message.
			 */
			osmo_sccp_tx_data(conn->user, conn->conn_id, msgb_l2(prim->oph.msg), msgb_l2len(prim->oph.msg));
			return false;
		}
		break;
	default:
		return true;
	}

	return true;
}

/* generate a 'struct xua_msg' of requested type from connection +
 * primitive data */
static struct xua_msg *xua_gen_msg_co(struct sccp_connection *conn, uint32_t event,
				      const struct osmo_scu_prim *prim, int msg_type)
{
	bool encode_opt_data = xua_opt_data_length_lim(conn, prim, msg_type);
	struct xua_msg *xua = xua_msg_alloc();

	if (!xua)
		return NULL;

	switch (msg_type) {
	case SUA_CO_CORE: /* Connect Request == SCCP CR */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CORE);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, conn->sccp_class);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &conn->called_addr);
		xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, 0); /* TODO */
		/* optional: sequence number (class 3 only) */
		if (conn->calling_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &conn->calling_addr);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: hop count */
		/* optional: importance */
		break;
	case SUA_CO_COAK: /* Connect Acknowledge == SCCP CC */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COAK);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, conn->sccp_class);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, 0); /* TODO */
		/* optional: sequence number (class 3 only) */
		if (conn->called_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &conn->called_addr);
		/* optional: hop count; importance; priority */
		/* FIXME: destination address will [only] be present in
		 * case the CORE message conveys the source address
		 * parameter */
		if (conn->calling_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &conn->calling_addr);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: importance */
		break;
	case SUA_CO_RELRE: /* Release Request == SCCP RLSD */
		if (!prim)
			goto prim_needed;
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RELEASE | prim->u.disconnect.cause);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: importance */
		break;
	case SUA_CO_RELCO: /* Release Confirm == SCCP RLC */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELCO);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		break;
	case SUA_CO_CODT: /* Connection Oriented Data Transfer == SCCP DT1 */
		if (!prim)
			goto prim_needed;
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CODT);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		/* Sequence number only in expedited data */
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		/* optional: priority; correlation id */
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));
		break;
	case SUA_CO_COIT: /* Connection Oriented Interval Timer == SCCP IT */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COIT);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, conn->sccp_class);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		/* optional: sequence number; credit (both class 3 only) */
		break;
	case SUA_CO_COREF: /* Connect Refuse == SCCP CREF */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COREF);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		//xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | prim->u.disconnect.cause);
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | SCCP_REFUSAL_UNEQUIPPED_USER);
		/* optional: source addr */
		if (conn->called_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &conn->called_addr);
		/* conditional: dest addr */
		if (conn->calling_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &conn->calling_addr);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: importance */
		break;
	/* FIXME */
	default:
		LOGP(DLSCCP, LOGL_ERROR, "Don't know how to encode msg_type %u\n", msg_type);
		xua_msg_free(xua);
		return NULL;
	}
	return xua;

prim_needed:
	xua_msg_free(xua);
	LOGP(DLSCCP, LOGL_ERROR, "%s must be called with valid 'prim' "
	     "pointer for msg_type=%u\n", __func__, msg_type);
	return NULL;
}

/* generate xua_msg, encode it and send it to SCRC
 * returns 0 on success, negative on error
 */
static int xua_gen_encode_and_send(struct sccp_connection *conn, uint32_t event,
				   const struct osmo_scu_prim *prim, int msg_type)
{
	struct xua_msg *xua;

	xua = xua_gen_msg_co(conn, event, prim, msg_type);
	if (!xua)
		return -ENOMEM;

	/* amend this with point code information; Many CO msgs
	 * includes neither called nor calling party address! */
	xua->mtp.dpc = conn->remote_pc;
	sccp_scrc_rx_scoc_conn_msg(conn->inst, xua);
	xua_msg_free(xua);
	return 0;
}

/* allocate a SCU primitive to be sent to the user */
static struct osmo_scu_prim *scu_prim_alloc(unsigned int primitive, enum osmo_prim_operation operation)
{
	struct msgb *upmsg = scu_msgb_alloc();
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			primitive, operation, upmsg);
	upmsg->l2h = upmsg->tail;
	return prim;
}

/* high-level function to generate a SCCP User primitive of requested
 * type based on the connection and currently processed XUA message */
static void scu_gen_encode_and_send(struct sccp_connection *conn, uint32_t event,
				    struct xua_msg *xua, unsigned int primitive,
				    enum osmo_prim_operation operation)
{
	struct osmo_scu_prim *scu_prim;
	struct osmo_scu_disconn_param *udisp;
	struct osmo_scu_connect_param *uconp;
	struct osmo_scu_data_param *udatp;
	struct xua_msg_part *data_ie;

	scu_prim = scu_prim_alloc(primitive, operation);

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		udisp = &scu_prim->u.disconnect;
		udisp->conn_id = conn->conn_id;
		udisp->responding_addr = conn->called_addr;
		udisp->importance = conn->importance;
		udisp->originator = OSMO_SCCP_ORIG_UNDEFINED;
		//udisp->in_sequence_control;
		if (xua) {
			udisp->cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE);
			if (xua_msg_find_tag(xua, SUA_IEI_SRC_ADDR))
				sua_addr_parse(&udisp->responding_addr, xua, SUA_IEI_SRC_ADDR);
			data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
			udisp->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
			if (data_ie) {
				struct msgb *upmsg = scu_prim->oph.msg;
				upmsg->l2h = msgb_put(upmsg, data_ie->len);
				memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
			}
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		uconp = &scu_prim->u.connect;
		uconp->conn_id = conn->conn_id;
		uconp->called_addr = conn->called_addr;
		uconp->calling_addr = conn->calling_addr;
		uconp->sccp_class = conn->sccp_class;
		uconp->importance = conn->importance;
		if (xua) {
			data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
			if (data_ie) {
				struct msgb *upmsg = scu_prim->oph.msg;
				upmsg->l2h = msgb_put(upmsg, data_ie->len);
				memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
			}
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		uconp = &scu_prim->u.connect;
		uconp->conn_id = conn->conn_id;
		uconp->called_addr = conn->called_addr;
		uconp->calling_addr = conn->calling_addr;
		//scu_prim->u.connect.in_sequence_control
		uconp->sccp_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) & 3;
		uconp->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
		data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
		if (data_ie) {
			struct msgb *upmsg = scu_prim->oph.msg;
			upmsg->l2h = msgb_put(upmsg, data_ie->len);
			memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		udatp = &scu_prim->u.data;
		udatp->conn_id = conn->conn_id;
		udatp->importance = conn->importance;
		data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
		if (data_ie) {
			struct msgb *upmsg = scu_prim->oph.msg;
			upmsg->l2h = msgb_put(upmsg, data_ie->len);
			memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
		}
		break;
	default:
		LOGPFSML(conn->fi, LOGL_ERROR, "Unsupported primitive %u:%u\n",
			 scu_prim->oph.primitive, scu_prim->oph.operation);
		talloc_free(scu_prim->oph.msg);
		return;
	}

	sccp_user_prim_up(conn->user, scu_prim);
}


/***********************************************************************
 * Actual SCCP Connection Oriented Control (SCOC) Finite State Machine
 ***********************************************************************/

/* Figure C.2/Q.714 (sheet 1 of 7) and C.3/Q.714 (sheet 1 of 6) */
static void scoc_fsm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;
	struct osmo_scu_connect_param *uconp;
	struct xua_msg *xua = NULL;
	int rc;

	switch (event) {
	case SCOC_E_SCU_N_CONN_REQ:
		prim = data;
		uconp = &prim->u.connect;
		/* copy relevant parameters from prim to conn */
		conn->called_addr = uconp->called_addr;
		conn->calling_addr = uconp->calling_addr;
		conn->sccp_class = uconp->sccp_class;
		/* generate + send CR PDU to SCRC */
		rc = xua_gen_encode_and_send(conn, event, prim, SUA_CO_CORE);
		if (rc < 0)
			LOGPFSML(fi, LOGL_ERROR, "Failed to initiate connection: %s\n", strerror(-rc));
		else {
			/* start connection timer */
			conn_start_connect_timer(conn);
			osmo_fsm_inst_state_chg(fi, S_CONN_PEND_OUT, 0, 0);
		}
		break;
#if 0
	case SCOC_E_SCU_N_TYPE1_REQ:
		/* ?!? */
		break;
#endif
	case SCOC_E_RCOC_RLSD_IND:
		/* send release complete to SCRC */
		xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		break;
	case SCOC_E_RCOC_REL_COMPL_IND:
		/* do nothing */
		break;
	case SCOC_E_RCOC_OTHER_NPDU:
#if 0
		if (src_ref) {
			/* FIXME: send ERROR to SCRC */
		}
#endif
		break;
	/* destination node / incoming connection */
	/* Figure C.3 / Q.714 (sheet 1 of 6) */
	case SCOC_E_RCOC_CONN_IND:
		xua = data;
		/* copy relevant parameters from xua to conn */
		sua_addr_parse(&conn->calling_addr, xua, SUA_IEI_SRC_ADDR);
		sua_addr_parse(&conn->called_addr, xua, SUA_IEI_DEST_ADDR);
		conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
		conn->sccp_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) & 3;
		conn->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
		/* 3.1.6.1 The originating node of the CR message
		 * (identified by the OPC in the calling party address
		 * or by default by the OPC in the MTP label, [and the
		 * MTP-SAP instance]) is associated with the incoming
		 * connection section. */
		if (conn->calling_addr.presence & OSMO_SCCP_ADDR_T_PC)
			conn->remote_pc = conn->calling_addr.pc;
		else {
			/* Hack to get the MTP label here ?!? */
			conn->remote_pc = xua->mtp.opc;
		}

		osmo_fsm_inst_state_chg(fi, S_CONN_PEND_IN, 0, 0);
		/* N-CONNECT.ind to User */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_CONNECT,
					PRIM_OP_INDICATION);
		break;
	}
}

static void scoc_fsm_idle_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	conn_destroy(fi->priv);
}

/* Figure C.3 / Q.714 (sheet 2 of 6) */
static void scoc_fsm_conn_pend_in(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;

	switch (event) {
	case SCOC_E_SCU_N_CONN_RESP:
		prim = data;
		/* FIXME: assign local reference (only now?) */
		/* FIXME: assign sls, protocol class and credit */
		xua_gen_encode_and_send(conn, event, prim, SUA_CO_COAK);
		/* start inactivity timers */
		conn_start_inact_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_ACTIVE, 0, 0);
		xua_opt_data_send_cache(conn, SUA_CO_COAK, SUA_MSGC_CO);
		break;
	case SCOC_E_SCU_N_DISC_REQ:
		prim = data;
		/* release resources: implicit */
		xua_gen_encode_and_send(conn, event, prim, SUA_CO_COREF);
		/* N. B: we've ignored CREF sending errors as there's no recovery option anyway */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	}
}

/* Figure C.2/Q.714 (sheet 2 of 7) */
static void scoc_fsm_conn_pend_out(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;
	struct xua_msg *xua = NULL;

	switch (event) {
	case SCOC_E_SCU_N_DISC_REQ:
		prim = data;
		conn->release_cause = prim->u.disconnect.cause;
		osmo_fsm_inst_state_chg(fi, S_WAIT_CONN_CONF, 0, 0);
		/* keep conn timer running(!) */
		break;
	case SCOC_E_CONN_TMR_EXP:
		/* N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, NULL, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		/* below implicitly releases resources + local ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_ROUT_FAIL_IND:
	case SCOC_E_RCOC_CREF_IND:
		xua = data;
		/* stop conn timer */
		conn_stop_connect_timer(conn);
		/* release local res + ref (implicit by going to idle) */
		/* N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		/* below implicitly releases resources + local ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_RLSD_IND:
		xua = data;
		/* RLC to SCRC */
		xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		/* stop conn timer */
		conn_stop_connect_timer(conn);
		/* release local res + ref (implicit) */
		/* N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_OTHER_NPDU:
		xua = data;
		conn_start_connect_timer(conn);
		/* release local res + ref (implicit) */
		/* N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_CC_IND:
		xua = data;
		/* stop conn timer */
		conn_stop_connect_timer(conn);
		/* start inactivity timers */
		conn_start_inact_timers(conn);
		/* TODO: assign PCU and credit */
		/* associate remote ref to conn */
		conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
		/* 3.1.4.2 The node sending the CC message (identified
		 * by the parameter OPC contained in the
		 * MTP-TRANSFER.indication primitive which conveyed the
		 * CC message [plus the MTP-SAP instance]) is associated
		 * with the connection section. */
		conn->remote_pc = xua->mtp.opc;

		osmo_fsm_inst_state_chg(fi, S_ACTIVE, 0, 0);
		/* If CR which was used to initiate this connection had excessive Optional Data which we had to cache,
		 * now is the time to send it: the connection is already active but we hadn't notified upper layers about it
		 * so we have the connection all to ourselves and can use it to transmit "leftover" data via DT1 */
		xua_opt_data_send_cache(conn, SUA_CO_CORE, xua->hdr.msg_class);

		/* N-CONNECT.conf to user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_CONNECT,
					PRIM_OP_CONFIRM);
		break;
	}
}

/* Figure C.2/Q.714 (sheet 3 of 7) */
static void scoc_fsm_wait_conn_conf(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct xua_msg *xua = NULL;

	switch (event) {
	case SCOC_E_RCOC_RLSD_IND:
		xua = data;
		/* release complete to SCRC */
		xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		/* stop conn timer */
		conn_stop_connect_timer(conn);
		/* release local res + ref (implicit) */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_CC_IND:
		xua = data;
		/* stop conn timer */
		conn_stop_connect_timer(conn);
		/* associate rem ref to conn */
		conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
		/* 3.1.4.2 The node sending the CC message (identified
		 * by the parameter OPC contained in the
		 * MTP-TRANSFER.indication primitive which conveyed the
		 * CC message [plus the MTP-SAP instance]) is associated
		 * with the connection section. */
		conn->remote_pc = xua->mtp.opc;

		/* released to SCRC */
		xua_gen_relre_and_send(conn, conn->release_cause, NULL);
		/* start rel timer */
		conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	case SCOC_E_RCOC_OTHER_NPDU:
	case SCOC_E_RCOC_CREF_IND:
	case SCOC_E_RCOC_ROUT_FAIL_IND:
		xua = data;
		/* stop conn timer */
		conn_stop_connect_timer(conn);
		/* release local res + ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_CONN_TMR_EXP:
		/* release local res + ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	}
}

/* C.2/Q.714 (sheet 4+5 of 7) and C.3/Q714 (sheet 3+4 of 6) */
static void scoc_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_msg *xua = data;
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;

	switch (event) {
#pragma message ("TODO: internal disco: send N-DISCONNECT.ind to user")
		/* send N-DISCONNECT.ind to user */
		/*scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);*/
		/* fall-through */
	case SCOC_E_SCU_N_DISC_REQ:
		prim = data;
		/* stop inact timers */
		conn_stop_inact_timers(conn);
		/* send RLSD to SCRC */
		xua_gen_encode_and_send(conn, event, prim, SUA_CO_RELRE);
		/* start rel timer */
		conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	case SCOC_E_RCOC_CREF_IND:
	case SCOC_E_RCOC_CC_IND:
	case SCOC_E_RCOC_REL_COMPL_IND:
		/* do nothing */
		break;
	case SCOC_E_RCOC_RLSD_IND:
		/* send N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		/* release res + local ref (implicit) */
		/* stop inact timers */
		conn_stop_inact_timers(conn);
		/* RLC to SCRC */
		xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_ERROR_IND:
		xua = data;
		/* FIXME: check for cause service_class_mismatch */
		/* release res + local ref (implicit) */
		/* send N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		/* stop inact timers */
		conn_stop_inact_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_T_IAR_EXP:
		/* stop inact timers */
		conn_stop_inact_timers(conn);
		xua = xua_msg_alloc();
		xua_msg_add_u32(xua, SUA_IEI_CAUSE,
				SUA_CAUSE_T_RELEASE | SCCP_RELEASE_CAUSE_EXPIRATION_INACTIVE);
		xua_msg_add_u32(xua, SUA_IEI_IMPORTANCE, conn->importance);
		/* Send N-DISCONNECT.ind to local user */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		talloc_free(xua);
		/* Send RLSD to peer */
		xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_EXPIRATION_INACTIVE, NULL);
		/* start release timer */
		conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	case SCOC_E_RCOC_ROUT_FAIL_IND:
		/* send N-DISCONNECT.ind to user */
		scu_gen_encode_and_send(conn, event, NULL, OSMO_SCU_PRIM_N_DISCONNECT,
					PRIM_OP_INDICATION);
		/* stop inact timers */
		conn_stop_inact_timers(conn);
		/* start release timer */
		conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	/* Figure C.4/Q.714 */
	case SCOC_E_SCU_N_DATA_REQ:
	case SCOC_E_SCU_N_EXP_DATA_REQ:
		prim = data;
		xua_gen_encode_and_send(conn, event, prim, SUA_CO_CODT);
		conn_restart_tx_inact_timer(conn);
		break;
	case SCOC_E_RCOC_DT1_IND:
		/* restart receive inactivity timer */
		conn_restart_rx_inact_timer(conn);
		/* TODO: M-bit */
		scu_gen_encode_and_send(conn, event, xua, OSMO_SCU_PRIM_N_DATA,
					PRIM_OP_INDICATION);
		break;
	/* Figure C.4/Q.714 (sheet 4 of 4) */
	case SCOC_E_RCOC_IT_IND:
		xua = data;
		/* check if remote reference is what we expect */
		/* check class is what we expect */
		if (xua_msg_get_u32(xua, SUA_IEI_SRC_REF) != conn->remote_ref ||
		    xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) != conn->sccp_class) {
			/* Release connection */
			/* Stop inactivity Timers */
			conn_stop_inact_timers(conn);
			xua = xua_msg_alloc();
			xua_msg_add_u32(xua, SUA_IEI_CAUSE,
					SUA_CAUSE_T_RELEASE | SCCP_RELEASE_CAUSE_INCONSISTENT_CONN_DATA);
			xua_msg_add_u32(xua, SUA_IEI_IMPORTANCE, conn->importance);
			/* send N-DISCONNECT.ind to user */
			scu_gen_encode_and_send(conn, event, xua,
						OSMO_SCU_PRIM_N_DISCONNECT,
						PRIM_OP_INDICATION);
			talloc_free(xua);
			/* Send RLSD to SCRC */
			xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_INCONSISTENT_CONN_DATA, NULL);
			talloc_free(xua);
			/* Start release timer */
			conn_start_rel_timer(conn);
			osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		}
		conn_restart_rx_inact_timer(conn);
		break;
	case SCOC_E_T_IAS_EXP:
		/* Send IT to peer */
		xua_gen_encode_and_send(conn, event, NULL, SUA_CO_COIT);
		conn_restart_tx_inact_timer(conn);
		break;
	}
}

/* C.2/Q.714 (sheet 6+7 of 7) and C.3/Q.714 (sheet 5+6 of 6) */
static void scoc_fsm_disconn_pend(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;

	switch (event) {
	case SCOC_E_RCOC_REL_COMPL_IND:
	case SCOC_E_RCOC_RLSD_IND:
		/* release res + local ref (implicit) */
		/* freeze local ref */
		/* stop release + interval timers */
		conn_stop_release_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_ROUT_FAIL_IND:
	case SCOC_E_RCOC_OTHER_NPDU:
		/* do nothing */
		break;
	case SCOC_E_T_REL_EXP: /* release timer exp */
		/* send RLSD */
		xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_UNQUALIFIED, NULL);
		/* start interval timer */
		conn_start_int_timer(conn);
		/* start repeat release timer */
		conn_start_rep_rel_timer(conn);
		break;
	case SCOC_E_T_INT_EXP: /* interval timer exp */
		/* TODO: Inform maintenance */
		/* stop release and interval timers */
		conn_stop_release_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_T_REP_REL_EXP: /* repeat release timer exp */
		/* send RLSD */
		xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_UNQUALIFIED, NULL);
		/* re-start repeat release timer */
		conn_start_rep_rel_timer(conn);
		break;
	}
}

static const struct osmo_fsm_state sccp_scoc_states[] = {
	[S_IDLE] = {
		.name = "IDLE",
		.action = scoc_fsm_idle,
		.onenter= scoc_fsm_idle_onenter,
		.in_event_mask = S(SCOC_E_SCU_N_CONN_REQ) |
				 //S(SCOC_E_SCU_N_TYPE1_REQ) |
				 S(SCOC_E_RCOC_CONN_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_REL_COMPL_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU),
		.out_state_mask = S(S_CONN_PEND_OUT) |
				  S(S_CONN_PEND_IN),
	},
	[S_CONN_PEND_IN] = {
		.name = "CONN_PEND_IN",
		.action = scoc_fsm_conn_pend_in,
		.in_event_mask = S(SCOC_E_SCU_N_CONN_RESP) |
				 S(SCOC_E_SCU_N_DISC_REQ),
		.out_state_mask = S(S_IDLE) |
				  S(S_ACTIVE),
	},
	[S_CONN_PEND_OUT] = {
		.name = "CONN_PEND_OUT",
		.action = scoc_fsm_conn_pend_out,
		.in_event_mask = S(SCOC_E_SCU_N_DISC_REQ) |
				 S(SCOC_E_CONN_TMR_EXP) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU) |
				 S(SCOC_E_RCOC_CREF_IND) |
				 S(SCOC_E_RCOC_CC_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_ACTIVE) |
				  S(S_WAIT_CONN_CONF),
	},
	[S_ACTIVE] = {
		.name = "ACTIVE",
		.action = scoc_fsm_active,
		.in_event_mask = S(SCOC_E_SCU_N_DISC_REQ) |
				/* internal disconnect */
				 S(SCOC_E_RCOC_CREF_IND) |
				 S(SCOC_E_RCOC_REL_COMPL_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_ERROR_IND) |
				 S(SCOC_E_T_IAR_EXP) |
				 S(SCOC_E_T_IAS_EXP) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND) |
				 S(SCOC_E_SCU_N_DATA_REQ) |
				 S(SCOC_E_SCU_N_EXP_DATA_REQ) |
				 S(SCOC_E_RCOC_DT1_IND) |
				 S(SCOC_E_RCOC_IT_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_DISCONN_PEND),
	},
	[S_DISCONN_PEND] = {
		.name = "DISCONN_PEND",
		.action = scoc_fsm_disconn_pend,
		.in_event_mask = S(SCOC_E_RCOC_REL_COMPL_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU) |
				 S(SCOC_E_T_REL_EXP) |
				 S(SCOC_E_T_INT_EXP) |
				 S(SCOC_E_T_REP_REL_EXP),
		.out_state_mask = S(S_IDLE),
	},
	[S_RESET_IN] = {
		.name = "RESET_IN",
	},
	[S_RESET_OUT] = {
		.name = "RESET_OUT",
	},
	[S_BOTHWAY_RESET] = {
		.name = "BOTHWAY_RESET",
	},
	[S_WAIT_CONN_CONF] = {
		.name = "WAIT_CONN_CONF",
		.action = scoc_fsm_wait_conn_conf,
		.in_event_mask = S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_CC_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU) |
				 S(SCOC_E_CONN_TMR_EXP) |
				 S(SCOC_E_RCOC_CREF_IND) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_DISCONN_PEND),
	},
};

struct osmo_fsm sccp_scoc_fsm = {
	.name = "SCCP-SCOC",
	.states = sccp_scoc_states,
	.num_states = ARRAY_SIZE(sccp_scoc_states),
	/* ".log_subsys = DLSCCP" doesn't work as DLSCCP is not a constant */
	.event_names = scoc_event_names,
};

/* map from SCCP return cause to SCCP Refusal cause */
static const uint8_t cause_map_cref[] = {
	[SCCP_RETURN_CAUSE_SUBSYSTEM_CONGESTION] =
				SCCP_REFUSAL_SUBSYTEM_CONGESTION,
	[SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE] =
				SCCP_REFUSAL_SUBSYSTEM_FAILURE,
	[SCCP_RETURN_CAUSE_UNEQUIPPED_USER] =
				SCCP_REFUSAL_UNEQUIPPED_USER,
	[SCCP_RETURN_CAUSE_UNQUALIFIED] =
				SCCP_REFUSAL_UNQUALIFIED,
	[SCCP_RETURN_CAUSE_SCCP_FAILURE] =
				SCCP_REFUSAL_SCCP_FAILURE,
	[SCCP_RETURN_CAUSE_HOP_COUNTER_VIOLATION] =
				SCCP_REFUSAL_HOP_COUNTER_VIOLATION,
};

static uint8_t get_cref_cause_for_ret(uint8_t ret_cause)
{
	if (ret_cause < ARRAY_SIZE(cause_map_cref))
		return cause_map_cref[ret_cause];
	else
		return SCCP_REFUSAL_UNQUALIFIED;
}

/* Generate a COREF message purely based on an incoming SUA message,
 * without the use of any local connection state */
static struct xua_msg *gen_coref_without_conn(struct osmo_sccp_instance *inst,
					      struct xua_msg *xua_in,
					      uint32_t ref_cause)
{
	struct xua_msg *xua;

	xua = xua_msg_alloc();
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COREF);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, inst->route_ctx);

	xua_msg_copy_part(xua, SUA_IEI_DEST_REF, xua_in, SUA_IEI_SRC_REF);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | ref_cause);
	/* optional: source addr */
	xua_msg_copy_part(xua, SUA_IEI_SRC_ADDR, xua_in, SUA_IEI_DEST_ADDR);
	/* conditional: dest addr */
	xua_msg_copy_part(xua, SUA_IEI_DEST_ADDR, xua_in, SUA_IEI_SRC_ADDR);
	/* optional: importance */
	xua_msg_copy_part(xua, SUA_IEI_IMPORTANCE, xua_in, SUA_IEI_IMPORTANCE);
	/* optional: data */
	xua_msg_copy_part(xua, SUA_IEI_DATA, xua_in, SUA_IEI_DATA);

	return xua;
}

/* Find a SCCP user for given SUA message (based on SUA_IEI_DEST_ADDR */
static struct osmo_sccp_user *sccp_find_user(struct osmo_sccp_instance *inst,
					     struct xua_msg *xua)
{
	int rc;
	struct osmo_sccp_addr called_addr;

	rc = sua_addr_parse(&called_addr, xua, SUA_IEI_DEST_ADDR);
	if (rc < 0) {
		LOGP(DLSCCP, LOGL_ERROR, "Cannot find SCCP User for XUA "
			"Message %s without valid DEST_ADDR\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		return NULL;
	}

	if (!(called_addr.presence & OSMO_SCCP_ADDR_T_SSN)) {
		LOGP(DLSCCP, LOGL_ERROR, "Cannot resolve SCCP User for "
			"XUA Message %s without SSN in CalledAddr\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		return NULL;
	}

	return sccp_user_find(inst, called_addr.ssn, called_addr.pc);
}

/*! \brief SCOC: Receive SCRC Routing Failure
 *  \param[in] inst SCCP Instance on which we operate
 *  \param[in] xua SUA message that was failed to route
 *  \param[in] return_cause Reason (cause) for routing failure */
void sccp_scoc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				struct xua_msg *xua, uint32_t return_cause)
{
	uint32_t conn_id;
	struct sccp_connection *conn;

	LOGP(DLSCCP, LOGL_NOTICE, "SCRC Routing Failure for message %s\n",
	     xua_hdr_dump(xua, &xua_dialect_sua));

	/* try to dispatch to connection FSM (if any) */
	conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);
	conn = conn_find_by_id(inst, conn_id);
	if (conn) {
		osmo_fsm_inst_dispatch(conn->fi,
					SCOC_E_RCOC_ROUT_FAIL_IND, xua);
	} else {
		/* generate + send CREF directly */
		struct xua_msg *cref;
		uint8_t cref_cause = get_cref_cause_for_ret(return_cause);
		cref = gen_coref_without_conn(inst, xua, cref_cause);
		sccp_scrc_rx_scoc_conn_msg(inst, cref);
		xua_msg_free(cref);
	}
}

/* Generate a COERR based in input arguments */
static struct xua_msg *gen_coerr(uint32_t route_ctx, uint32_t dest_ref,
				uint32_t err_cause)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COERR);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, dest_ref);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_ERROR | err_cause);

	return xua;
}

/* generate COERR from incoming XUA and send it */
static void tx_coerr_from_xua(struct osmo_sccp_instance *inst,
				struct xua_msg *in, uint32_t err_cause)
{
	struct xua_msg *xua;
	uint32_t route_ctx, dest_ref;

	route_ctx = xua_msg_get_u32(in, SUA_IEI_ROUTE_CTX);
	/* get *source* reference and use as destination ref */
	dest_ref = xua_msg_get_u32(in, SUA_IEI_SRC_REF);

	xua = gen_coerr(route_ctx, dest_ref, err_cause);
	/* copy over the MTP parameters */
	xua->mtp.dpc = in->mtp.opc;
	xua->mtp.opc = in->mtp.dpc;
	xua->mtp.sio = in->mtp.sio;

	/* sent to SCRC for transmission */
	sccp_scrc_rx_scoc_conn_msg(inst, xua);
	xua_msg_free(xua);
}

/* Generate a RELCO based in input arguments */
static struct xua_msg *gen_relco(uint32_t route_ctx, uint32_t dest_ref,
				uint32_t src_ref)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELCO);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, dest_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, src_ref);

	return xua;
}

/* generate RELCO from incoming XUA and send it */
static void tx_relco_from_xua(struct osmo_sccp_instance *inst,
				struct xua_msg *in)
{
	struct xua_msg *xua;
	uint32_t route_ctx, dest_ref, src_ref;

	route_ctx = xua_msg_get_u32(in, SUA_IEI_ROUTE_CTX);
	/* get *source* reference and use as destination ref */
	dest_ref = xua_msg_get_u32(in, SUA_IEI_SRC_REF);
	/* get *dest* reference and use as source ref */
	src_ref = xua_msg_get_u32(in, SUA_IEI_DEST_REF);

	xua = gen_relco(route_ctx, dest_ref, src_ref);
	/* copy over the MTP parameters */
	xua->mtp.dpc = in->mtp.opc;
	xua->mtp.opc = in->mtp.dpc;
	xua->mtp.sio = in->mtp.sio;

	/* send to SCRC for transmission */
	sccp_scrc_rx_scoc_conn_msg(inst, xua);
	xua_msg_free(xua);
}

/* Generate a RLSD based in input arguments */
static struct xua_msg *gen_rlsd(uint32_t route_ctx, uint32_t dest_ref,
				uint32_t src_ref)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, dest_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, src_ref);

	return xua;
}

/* Generate a RLSD to both the remote side and the local conn */
static void tx_rlsd_from_xua_twoway(struct sccp_connection *conn,
				    struct xua_msg *in)
{
	struct xua_msg *xua;
	uint32_t route_ctx, dest_ref, src_ref;

	route_ctx = xua_msg_get_u32(in, SUA_IEI_ROUTE_CTX);
	/* get *source* reference and use as destination ref */
	dest_ref = xua_msg_get_u32(in, SUA_IEI_SRC_REF);
	/* get *source* reference and use as destination ref */
	src_ref = xua_msg_get_u32(in, SUA_IEI_DEST_REF);

	/* Generate RLSD towards remote peer */
	xua = gen_rlsd(route_ctx, dest_ref, src_ref);
	/* copy over the MTP parameters */
	xua->mtp.dpc = in->mtp.opc;
	xua->mtp.opc = in->mtp.dpc;
	xua->mtp.sio = in->mtp.sio;
	/* send to SCRC for transmission */
	sccp_scrc_rx_scoc_conn_msg(conn->inst, xua);
	xua_msg_free(xua);

	/* Generate RLSD towards local peer */
	xua = gen_rlsd(conn->inst->route_ctx, conn->conn_id, conn->remote_ref);
	xua->mtp.dpc = in->mtp.dpc;
	xua->mtp.opc = conn->remote_pc;
	xua->mtp.sio = in->mtp.sio;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_RCOC_RLSD_IND, xua);
	xua_msg_free(xua);
}

/* process received message for unassigned local reference */
static void sccp_scoc_rx_unass_local_ref(struct osmo_sccp_instance *inst,
					 struct xua_msg *xua)
{
	/* we have received a message with unassigned destination local
	 * reference and thus apply the action indicated in Table
	 * B.2/Q.714 */
	switch (xua->hdr.msg_type) {
	case SUA_CO_COAK: /* CC */
	case SUA_CO_COIT: /* IT */
	case SUA_CO_RESRE: /* RSR */
	case SUA_CO_RESCO: /* RSC */
		/* Send COERR */
		tx_coerr_from_xua(inst, xua, SCCP_ERROR_LRN_MISMATCH_UNASSIGNED);
		break;
	case SUA_CO_COREF: /* CREF */
	case SUA_CO_RELCO: /* RLC */
	case SUA_CO_CODT: /* DT1 */
	case SUA_CO_CODA: /* AK */
	case SUA_CO_COERR: /* ERR */
		/* DISCARD */
		break;
	case SUA_CO_RELRE: /* RLSD */
		/* Send RLC */
		tx_relco_from_xua(inst, xua);
		break;
	default:
		LOGP(DLSCCP, LOGL_NOTICE, "Unhandled %s\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}
}

/* process received message for invalid source local reference */
static void sccp_scoc_rx_inval_src_ref(struct sccp_connection *conn,
				       struct xua_msg *xua,
				       uint32_t inval_src_ref)
{
	LOGP(DLSCCP, LOGL_NOTICE,
	     "Received message for source ref %u on conn with mismatching remote ref %u\n",
	     inval_src_ref, conn->remote_ref);

	/* we have received a message with invalid source local
	 * reference and thus apply the action indicated in Table
	 * B.2/Q.714 */
	switch (xua->hdr.msg_type) {
	case SUA_CO_RELRE: /* RLSD */
	case SUA_CO_RESRE: /* RSR */
	case SUA_CO_RESCO: /* RSC */
		/* Send ERR */
		tx_coerr_from_xua(conn->inst, xua, SCCP_ERROR_LRN_MISMATCH_INCONSISTENT);
		break;
	case SUA_CO_COIT: /* IT */
		/* FIXME: RLSD to both sides */
		tx_rlsd_from_xua_twoway(conn, xua);
		break;
	case SUA_CO_RELCO: /* RLC */
		/* DISCARD */
		break;
	default:
		LOGP(DLSCCP, LOGL_NOTICE, "Unhandled %s\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}
}

/* process received message for invalid origin point code */
static void sccp_scoc_rx_inval_opc(struct sccp_connection *conn,
				   struct xua_msg *xua)
{
	LOGP(DLSCCP, LOGL_NOTICE,
	     "Received message %s for opc=%u=%s on conn with mismatching remote pc=%u=%s\n",
	     xua_hdr_dump(xua, &xua_dialect_sua),
	     xua->mtp.opc, osmo_ss7_pointcode_print(conn->inst->ss7, xua->mtp.opc),
	     conn->remote_pc, osmo_ss7_pointcode_print2(conn->inst->ss7, conn->remote_pc));
	/* we have received a message with invalid origin PC and thus
	 * apply the action indicated in Table B.2/Q.714 */
	switch (xua->hdr.msg_type) {
	case SUA_CO_RELRE: /* RLSD */
	case SUA_CO_RESRE: /* RSR */
	case SUA_CO_RESCO: /* RSC */
		/* Send ERR */
		tx_coerr_from_xua(conn->inst, xua, SCCP_ERROR_POINT_CODE_MISMATCH);
		break;
	case SUA_CO_RELCO: /* RLC */
	case SUA_CO_CODT: /* DT1 */
	case SUA_CO_CODA: /* AK */
	case SUA_CO_COERR: /* ERR */
		/* DISCARD */
		break;
	default:
		LOGP(DLSCCP, LOGL_NOTICE, "Unhandled %s\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}
}

/*! \brief Main entrance function for primitives from the SCRC (Routing Control)
 *  \param[in] inst SCCP Instance in which we operate
 *  \param[in] xua SUA message in xua_msg format */
void sccp_scoc_rx_from_scrc(struct osmo_sccp_instance *inst,
			    struct xua_msg *xua)
{
	struct sccp_connection *conn;
	struct osmo_sccp_user *scu;
	uint32_t src_loc_ref;
	int event;

	/* we basically try to convert the SUA message into an event,
	 * and then dispatch the event to the connection-specific FSM.
	 * If it is a CORE (Connect REquest), we create the connection
	 * (and implicitly its FSM) first */

	if (xua->hdr.msg_type == SUA_CO_CORE) {
		scu = sccp_find_user(inst, xua);
		if (!scu) {
			/* this shouldn't happen, as the caller should
			 * have already verified that a local user is
			 * equipped for this SSN */
			LOGP(DLSCCP, LOGL_ERROR, "Cannot find user for "
				"CORE ?!?\n");
			return;
		}
		/* Allocate new connection */
		conn = conn_create(scu);
		conn->incoming = true;
	} else {
		uint32_t conn_id;
		/* Resolve existing connection */
		conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);
		conn = conn_find_by_id(inst, conn_id);
		if (!conn) {
			LOGP(DLSCCP, LOGL_NOTICE, "Received %s: Cannot find connection for "
			     "local reference %u\n", xua_hdr_dump(xua, &xua_dialect_sua), conn_id);
			sccp_scoc_rx_unass_local_ref(inst, xua);
			return;
		}
	}
	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->fi);

	DEBUGP(DLSCCP, "Received %s for local reference %u\n",
		xua_hdr_dump(xua, &xua_dialect_sua), conn->conn_id);

	if (xua->hdr.msg_type != SUA_CO_CORE &&
	    xua->hdr.msg_type != SUA_CO_COAK &&
	    xua->hdr.msg_type != SUA_CO_COREF) {
		if (xua_msg_find_tag(xua, SUA_IEI_SRC_REF)) {
			/* Check if received source local reference !=
			 * the one we saved in local state */
			src_loc_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
			if (src_loc_ref != conn->remote_ref) {
				sccp_scoc_rx_inval_src_ref(conn, xua, src_loc_ref);
				return;
			}
		}

		/* Check if received OPC != the remote_pc we stored locally */
		if (xua->mtp.opc != conn->remote_pc) {
			sccp_scoc_rx_inval_opc(conn, xua);
			return;
		}
	}

	/* Map from XUA message to event */
	event = xua_msg_event_map(xua, sua_scoc_event_map, ARRAY_SIZE(sua_scoc_event_map));
	if (event < 0) {
		LOGP(DLSCCP, LOGL_ERROR, "Cannot map SCRC msg %s to event\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		/* Table B.1/Q714 states DISCARD for any message with
		 * unknown type */
		return;
	}

	/* Dispatch event to existing connection */
	osmo_fsm_inst_dispatch(conn->fi, event, xua);
}

/* get the Connection ID of the given SCU primitive */
static uint32_t scu_prim_conn_id(const struct osmo_scu_prim *prim)
{
	switch (prim->oph.primitive) {
	case OSMO_SCU_PRIM_N_CONNECT:
		return prim->u.connect.conn_id;
	case OSMO_SCU_PRIM_N_DATA:
		return prim->u.data.conn_id;
	case OSMO_SCU_PRIM_N_DISCONNECT:
		return prim->u.disconnect.conn_id;
	case OSMO_SCU_PRIM_N_RESET:
		return prim->u.reset.conn_id;
	default:
		return 0;
	}
}

/*! Main entrance function for primitives from SCCP User.
 * The caller is required to free oph->msg, otherwise the same as osmo_sccp_user_sap_down().
 *  \param[in] scu SCCP User sending us the primitive
 *  \param[in] oph Osmocom primitive sent by the user
 *  \returns 0 on success; negative on error */
int osmo_sccp_user_sap_down_nofree(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_sccp_instance *inst = scu->inst;
	struct sccp_connection *conn;
	int rc = 0;
	int event;

	LOGP(DLSCCP, LOGL_DEBUG, "Received SCCP User Primitive (%s)\n",
		osmo_scu_prim_name(&prim->oph));

	switch (OSMO_PRIM_HDR(&prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST):
	/* other CL primitives? */
		/* Connectionless by-passes this altogether */
		return sccp_sclc_user_sap_down_nofree(scu, oph);
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST):
		/* Allocate new connection structure */
		conn = conn_create_id(scu, prim->u.connect.conn_id);
		if (!conn) {
			/* FIXME: inform SCCP user with proper reply */
			LOGP(DLSCCP, LOGL_ERROR, "Cannot create conn-id for primitive %s\n",
			     osmo_scu_prim_name(&prim->oph));
			return rc;
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_RESPONSE):
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST):
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_REQUEST):
	case OSMO_PRIM(OSMO_SCU_PRIM_N_RESET, PRIM_OP_REQUEST):
		/* Resolve existing connection structure */
		conn = conn_find_by_id(inst, scu_prim_conn_id(prim));
		if (!conn) {
			/* FIXME: inform SCCP user with proper reply */
			LOGP(DLSCCP, LOGL_ERROR, "Received unknown conn-id %u for primitive %s\n",
			     scu_prim_conn_id(prim), osmo_scu_prim_name(&prim->oph));
			return rc;
		}
		break;
	default:
		LOGP(DLSCCP, LOGL_ERROR, "Received unknown primitive %s\n",
			osmo_scu_prim_name(&prim->oph));
		return -1;
	}

	/* Map from primitive to event */
	event = osmo_event_for_prim(oph, scu_scoc_event_map);

	/* Dispatch event into connection */
	return osmo_fsm_inst_dispatch(conn->fi, event, prim);
}

/*! Main entrance function for primitives from SCCP User.
 * Implies a msgb_free(oph->msg), otherwise the same as osmo_sccp_user_sap().
 *  \param[in] scu SCCP User sending us the primitive
 *  \param[in] oph Osmocom primitive sent by the user
 *  \returns 0 on success; negative on error */
int osmo_sccp_user_sap_down(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct msgb *msg = prim->oph.msg;
	int rc = osmo_sccp_user_sap_down_nofree(scu, oph);
	msgb_free(msg);
	return rc;
}

void sccp_scoc_flush_connections(struct osmo_sccp_instance *inst)
{
	struct rb_node *node;
	while ((node = rb_first(&inst->connections))) {
		struct sccp_connection *conn = container_of(node, struct sccp_connection, node);
		conn_destroy(conn);
	}

}

#include <osmocom/vty/vty.h>

static void vty_show_connection(struct vty *vty, struct sccp_connection *conn)
{
	struct osmo_ss7_instance *s7i = conn->inst->ss7;
	struct osmo_sccp_addr *remote_addr;
	uint32_t local_pc = OSMO_SS7_PC_INVALID;

	if (osmo_ss7_pc_is_valid(conn->user->pc))
		local_pc = conn->user->pc;
	else if (osmo_ss7_pc_is_valid(s7i->cfg.primary_pc))
		local_pc = s7i->cfg.primary_pc;

	if (conn->incoming)
		remote_addr = &conn->calling_addr;
	else
		remote_addr = &conn->called_addr;

	vty_out(vty, "%c %06x %3u %7s ", conn->incoming ? 'I' : 'O',
		conn->conn_id, conn->user->ssn,
		osmo_ss7_pointcode_print(s7i, local_pc));
	vty_out(vty, "%16s %06x %3u %7s%s",
		osmo_fsm_inst_state_name(conn->fi), conn->remote_ref, remote_addr->ssn,
		osmo_ss7_pointcode_print(s7i, conn->remote_pc),
		VTY_NEWLINE);
}

void sccp_scoc_show_connections(struct vty *vty, struct osmo_sccp_instance *inst)
{
	struct sccp_connection *conn;
	struct rb_node *node;

	vty_out(vty, "I Local              Conn.            Remote            %s", VTY_NEWLINE);
	vty_out(vty, "O Ref    SSN PC      State            Ref    SSN PC     %s", VTY_NEWLINE);
	vty_out(vty, "- ------ --- ------- ---------------- ------ --- -------%s", VTY_NEWLINE);

	for (node = rb_first(&inst->connections); node; node = rb_next(node)) {
		conn = container_of(node, struct sccp_connection, node);
		vty_show_connection(vty, conn);
	}
}
