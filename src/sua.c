/* Minimal implementation of RFC 3868 - SCCP User Adaptation Layer */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>

#include <osmocom/netif/stream.h>
#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/sua.h>

#define SUA_MSGB_SIZE 1500

/* Appendix C.4 of Q.714 (all in milliseconds) */
#define CONNECTION_TIMER	( 1 * 60 * 100)
#define TX_INACT_TIMER		( 7 * 60 * 100)	/* RFC 3868 Ch. 8. */
#define RX_INACT_TIMER		(15 * 60 * 100) /* RFC 3868 Ch. 8. */
#define RELEASE_TIMER		(     10 * 100)
#define RELEASE_REP_TIMER	(     10 * 100)
#define INT_TIMER		( 1 * 60 * 100)
#define GUARD_TIMER		(23 * 60 * 100)
#define RESET_TIMER		(     10 * 100)

static int DSUA = -1;

struct osmo_sccp_user {
	/* global list of SUA users? */
	struct llist_head list;
	/* set if we are a server */
	struct osmo_stream_srv_link *server;
	struct osmo_stream_cli *client;
	struct llist_head links;
	/* user call-back function in case of incoming primitives */
	osmo_prim_cb prim_cb;
	void *priv;
};

struct osmo_sccp_link {
	/* list of SUA links per sua_user */
	struct llist_head list;
	/* sua user to which we belong */
	struct osmo_sccp_user *user;
	/* local list of (SCCP) connections in this link */
	struct llist_head connections;
	/* next connection local reference */
	uint32_t next_id;
	int is_server;
	void *data;
};

enum sua_connection_state {
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

static const struct value_string conn_state_names[] = {
	{ S_IDLE, 		"IDLE" },
	{ S_CONN_PEND_IN,	"CONN_PEND_IN" },
	{ S_CONN_PEND_OUT,	"CONN_PEND_OUT" },
	{ S_ACTIVE,		"ACTIVE" },
	{ S_DISCONN_PEND,	"DISCONN_PEND" },
	{ S_RESET_IN,		"RESET_IN" },
	{ S_RESET_OUT,		"RESET_OUT" },
	{ S_BOTHWAY_RESET,	"BOTHWAY_RESET" },
	{ S_WAIT_CONN_CONF,	"WAIT_CONN_CONF" },
	{ 0, NULL }
};

struct sua_connection {
	struct llist_head list;
	struct osmo_sccp_link *link;
	struct osmo_sccp_addr calling_addr;
	struct osmo_sccp_addr called_addr;
	uint32_t conn_id;
	uint32_t remote_ref;
	enum sua_connection_state state;
	struct osmo_timer_list timer;
	/* inactivity timers */
	struct osmo_timer_list tias;
	struct osmo_timer_list tiar;
};


/***********************************************************************
 * Message encoding helper functions
 ***********************************************************************/

#define XUA_HDR(class, type)	((struct xua_common_hdr) { .spare = 0, .msg_class = (class), .msg_type = (type) })

static int msgb_t16l16vp_put(struct msgb *msg, uint16_t tag, uint16_t len, const uint8_t *data)
{
	uint8_t *cur;
	unsigned int rest;
	unsigned int tlv_len = 4 + len + (4 - (len % 4));

	if (msgb_tailroom(msg) < tlv_len)
		return -ENOMEM;

	/* tag */
	msgb_put_u16(msg, tag);
	/* length */
	msgb_put_u16(msg, len + 4);
	/* value */
	cur = msgb_put(msg, len);
	memcpy(cur, data, len);
	/* padding */
	rest = (4 - (len % 4)) & 0x3;
	if (rest > 0) {
		cur = msgb_put(msg, rest);
		memset(cur, 0, rest);
	}

	return 0;
}

static int msgb_t16l16vp_put_u32(struct msgb *msg, uint16_t tag, uint32_t val)
{
	uint32_t val_n = htonl(val);

	return msgb_t16l16vp_put(msg, tag, sizeof(val_n), (uint8_t *)&val_n);
}

static int xua_msg_add_u32(struct xua_msg *xua, uint16_t iei, uint32_t val)
{
	uint32_t val_n = htonl(val);
	return xua_msg_add_data(xua, iei, sizeof(val_n), (uint8_t *) &val_n);
}

static uint32_t xua_msg_get_u32(struct xua_msg *xua, uint16_t iei)
{
	struct xua_msg_part *part = xua_msg_find_tag(xua, iei);
	uint32_t rc = 0;
	if (part)
		rc = ntohl(*(uint32_t *)part->dat);
	return rc;
}

static int xua_msg_add_sccp_addr(struct xua_msg *xua, uint16_t iei, const struct osmo_sccp_addr *addr)
{
	struct msgb *tmp = msgb_alloc(128, "SCCP Address");
	int rc;

	if (!tmp)
		return -ENOMEM;

	msgb_put_u16(tmp, 2); /* route on SSN + PC */
	msgb_put_u16(tmp, 7); /* always put all addresses on SCCP side */

	if (addr->presence & OSMO_SCCP_ADDR_T_GT) {
		/* FIXME */
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_PC) {
		msgb_t16l16vp_put_u32(tmp, SUA_IEI_PC, addr->pc);
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN) {
		msgb_t16l16vp_put_u32(tmp, SUA_IEI_SSN, addr->ssn);
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_IPv4) {
		/* FIXME: IPv4 address */
	} else if (addr->presence & OSMO_SCCP_ADDR_T_IPv6) {
		/* FIXME: IPv6 address */
	}
	rc = xua_msg_add_data(xua, iei, msgb_length(tmp), tmp->data);
	msgb_free(tmp);

	return rc;
}


/***********************************************************************
 * SUA Link and Connection handling
 ***********************************************************************/

static struct osmo_sccp_link *sua_link_new(struct osmo_sccp_user *user, int is_server)
{
	struct osmo_sccp_link *link;

	link = talloc_zero(user, struct osmo_sccp_link);
	if (!link)
		return NULL;

	link->user = user;
	link->is_server = is_server;
	INIT_LLIST_HEAD(&link->connections);

	llist_add_tail(&link->list, &user->links);

	return link;
}

static void conn_destroy(struct sua_connection *conn);

static void sua_link_destroy(struct osmo_sccp_link *link)
{
	struct sua_connection *conn;

	llist_for_each_entry(conn, &link->connections, list)
		conn_destroy(conn);

	llist_del(&link->list);

	/* FIXME: do we need to cleanup the sccp link? */

	talloc_free(link);
}

static int sua_link_send(struct osmo_sccp_link *link, struct msgb *msg)
{
	msgb_sctp_ppid(msg) = SUA_PPID;

	DEBUGP(DSUA, "sua_link_send(%s)\n", osmo_hexdump(msg->data, msgb_length(msg)));

	if (link->is_server)
		osmo_stream_srv_send(link->data, msg);
	else
		osmo_stream_cli_send(link->data, msg);

	return 0;
}

static struct sua_connection *conn_find_by_id(struct osmo_sccp_link *link, uint32_t id)
{
	struct sua_connection *conn;

	llist_for_each_entry(conn, &link->connections, list) {
		if (conn->conn_id == id)
			return conn;
	}
	return NULL;
}

static void tx_inact_tmr_cb(void *data)
{
	struct sua_connection *conn = data;
	struct xua_msg *xua = xua_msg_alloc();
	struct msgb *outmsg;

	/* encode + send the CLDT */
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COIT);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0);	/* FIXME */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, 2);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
	/* optional: sequence number; credit (both class 3 only) */

	outmsg = xua_to_msg(1, xua);
	xua_msg_free(xua);

	sua_link_send(conn->link, outmsg);
}

static void rx_inact_tmr_cb(void *data)
{
	struct sua_connection *conn = data;

	/* FIXME: release connection */
	/* Send N-DISCONNECT.ind to local user */
	/* Send RLSD to peer */
	/* enter disconnect pending state with release timer pending */
}


static struct sua_connection *conn_create_id(struct osmo_sccp_link *link, uint32_t conn_id)
{
	struct sua_connection *conn = talloc_zero(link, struct sua_connection);

	conn->conn_id = conn_id;
	conn->link = link;
	conn->state = S_IDLE;

	llist_add_tail(&conn->list, &link->connections);

	conn->tias.cb = tx_inact_tmr_cb;
	conn->tias.data = conn;
	conn->tiar.cb = rx_inact_tmr_cb;
	conn->tiar.data = conn;

	return conn;
}

static struct sua_connection *conn_create(struct osmo_sccp_link *link)
{
	uint32_t conn_id;

	do {
		conn_id = link->next_id++;
	} while (conn_find_by_id(link, conn_id));

	return conn_create_id(link, conn_id);
}

static void conn_destroy(struct sua_connection *conn)
{
	/* FIXME: do some cleanup; inform user? */
	osmo_timer_del(&conn->tias);
	osmo_timer_del(&conn->tiar);
	llist_del(&conn->list);
	talloc_free(conn);
}

static void conn_state_set(struct sua_connection *conn,
			   enum sua_connection_state state)
{
	DEBUGP(DSUA, "(%u) state chg %s->", conn->conn_id,
		get_value_string(conn_state_names, conn->state));
	DEBUGPC(DSUA, "%s\n",
		get_value_string(conn_state_names, state));
	conn->state = state;
}

static void conn_restart_tx_inact_timer(struct sua_connection *conn)
{
	osmo_timer_schedule(&conn->tias, TX_INACT_TIMER / 100,
			    (TX_INACT_TIMER % 100) * 10);
}

static void conn_restart_rx_inact_timer(struct sua_connection *conn)
{
	osmo_timer_schedule(&conn->tiar, RX_INACT_TIMER / 100,
			    (RX_INACT_TIMER % 100) * 10);
}

static void conn_start_inact_timers(struct sua_connection *conn)
{
	conn_restart_tx_inact_timer(conn);
	conn_restart_rx_inact_timer(conn);
}


static struct msgb *sua_msgb_alloc(void)
{
	return msgb_alloc(SUA_MSGB_SIZE, "SUA Primitive");
}


/***********************************************************************
 * Handling of messages from the User SAP
 ***********************************************************************/

/* user program sends us a N-CONNNECT.req to initiate a new connection */
static int sua_connect_req(struct osmo_sccp_link *link, struct osmo_scu_prim *prim)
{
	struct osmo_scu_connect_param *par = &prim->u.connect;
	struct xua_msg *xua = xua_msg_alloc();
	struct sua_connection *conn;
	struct msgb *outmsg;

	if (par->sccp_class != 2) {
		LOGP(DSUA, LOGL_ERROR, "N-CONNECT.req for unsupported "
			"SCCP class %u\n", par->sccp_class);
		/* FIXME: Send primitive to user */
		return -EINVAL;
	}

	conn = conn_create_id(link, par->conn_id);
	if (!conn) {
		/* FIXME: Send primitive to user */
		return -EINVAL;
	}

	memcpy(&conn->called_addr, &par->called_addr,
		sizeof(conn->called_addr));
	memcpy(&conn->calling_addr, &par->calling_addr,
		sizeof(conn->calling_addr));

	/* encode + send the CLDT */
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CORE);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0);	/* FIXME */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, par->sccp_class);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
	xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &par->called_addr);
	xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, 0); /* FIXME */
	/* sequence number */
	if (par->calling_addr.presence)
		xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &par->calling_addr);
	/* optional: hop count; importance; priority; credit */
	if (msgb_l2(prim->oph.msg))
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));

	outmsg = xua_to_msg(1, xua);
	xua_msg_free(xua);

	/* FIXME: Start CONNECTION_TIMER */
	conn_state_set(conn, S_CONN_PEND_OUT);

	return sua_link_send(link, outmsg);
}

/* user program sends us a N-CONNNECT.resp, presumably against a
 * N-CONNECT.ind */
static int sua_connect_resp(struct osmo_sccp_link *link, struct osmo_scu_prim *prim)
{
	struct osmo_scu_connect_param *par = &prim->u.connect;
	struct xua_msg *xua = xua_msg_alloc();
	struct sua_connection *conn;
	struct msgb *outmsg;

	/* check if we already know a connection for this conn_id */
	conn = conn_find_by_id(link, par->conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "N-CONNECT.resp for unknown "
			"connection ID %u\n", par->conn_id);
		/* FIXME: Send primitive to user */
		return -ENODEV;
	}

	if (conn->state != S_CONN_PEND_IN) {
		LOGP(DSUA, LOGL_ERROR, "N-CONNECT.resp in wrong state %s\n",
			get_value_string(conn_state_names, conn->state));
		/* FIXME: Send primitive to user */
		return -EINVAL;
	}

	/* encode + send the COAK message */
	xua = xua_msg_alloc();
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COAK);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0);	/* FIXME */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, par->sccp_class);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
	xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, 0);	/* FIXME */
	/* sequence number */
	if (par->calling_addr.presence)
		xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &par->calling_addr);
	/* optional: hop count; importance; priority */
	/* FIXME: destination address will be present in case the CORE
	 * message conveys the source address parameter */
	if (par->called_addr.presence)
		xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &par->called_addr);
	if (msgb_l2(prim->oph.msg))
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));

	outmsg = xua_to_msg(1, xua);
	xua_msg_free(xua);

	conn_state_set(conn, S_ACTIVE);
	conn_start_inact_timers(conn);

	return sua_link_send(link, outmsg);
}

/* user wants to send connection-oriented data */
static int sua_data_req(struct osmo_sccp_link *link, struct osmo_scu_prim *prim)
{
	struct osmo_scu_data_param *par = &prim->u.data;
	struct xua_msg *xua;
	struct sua_connection *conn;
	struct msgb *outmsg;

	/* check if we know about this conncetion, and obtain reference */
	conn = conn_find_by_id(link, par->conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "N-DATA.req for unknown "
			"connection ID %u\n", par->conn_id);
		/* FIXME: Send primitive to user */
		return -ENODEV;
	}

	if (conn->state != S_ACTIVE) {
		LOGP(DSUA, LOGL_ERROR, "N-DATA.req in wrong state %s\n",
			get_value_string(conn_state_names, conn->state));
		/* FIXME: Send primitive to user */
		return -EINVAL;
	}

	conn_restart_tx_inact_timer(conn);

	/* encode + send the CODT message */
	xua = xua_msg_alloc();
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CODT);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0);	/* FIXME */
	/* Sequence number only in expedited data */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
	/* optional: priority; correlation id */
	xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
			 msgb_l2(prim->oph.msg));

	outmsg = xua_to_msg(1, xua);
	xua_msg_free(xua);

	return sua_link_send(link, outmsg);
}

/* user wants to disconnect a connection */
static int sua_disconnect_req(struct osmo_sccp_link *link, struct osmo_scu_prim *prim)
{
	struct osmo_scu_disconn_param *par = &prim->u.disconnect;
	struct xua_msg *xua;
	struct sua_connection *conn;
	struct msgb *outmsg;

	/* resolve reference of connection */
	conn = conn_find_by_id(link, par->conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "N-DISCONNECT.req for unknown "
			"connection ID %u\n", par->conn_id);
		/* FIXME: Send primitive to user */
		return -ENODEV;
	}

	/* encode + send the RELRE */
	xua = xua_msg_alloc();
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0);	/* FIXME */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, par->cause);
	/* optional: importance */
	if (msgb_l2(prim->oph.msg))
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));

	outmsg = xua_to_msg(1, xua);
	xua_msg_free(xua);

	conn_state_set(conn, S_DISCONN_PEND);
	conn_destroy(conn);

	LOGP(DSUA, LOGL_NOTICE, "About to send the SUA RELRE\n");
	return sua_link_send(link, outmsg);
}

/* user wants to send connectionless data */
static int sua_unitdata_req(struct osmo_sccp_link *link, struct osmo_scu_prim *prim)
{
	struct osmo_scu_unitdata_param *par = &prim->u.unitdata;
	struct xua_msg *xua = xua_msg_alloc();
	struct msgb *outmsg;

	/* encode + send the CLDT */
	xua->hdr = XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, 0);	/* FIXME */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, 0);
	xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &par->calling_addr);
	xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &par->called_addr);
	xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, par->in_sequence_control);
	/* optional: importance, ... correlation id? */
	xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
			 msgb_l2(prim->oph.msg));

	outmsg = xua_to_msg(1, xua);
	xua_msg_free(xua);

	return sua_link_send(link, outmsg);
}

/* user hands us a SCCP-USER SAP primitive down into the stack */
int osmo_sua_user_link_down(struct osmo_sccp_link *link, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct msgb *msg = prim->oph.msg;
	int rc = 0;

	LOGP(DSUA, LOGL_DEBUG, "Received SCCP User Primitive (%s)\n",
		osmo_scu_prim_name(&prim->oph));

	switch (OSMO_PRIM_HDR(&prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST):
		rc = sua_connect_req(link, prim);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_RESPONSE):
		rc = sua_connect_resp(link, prim);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST):
		rc = sua_data_req(link, prim);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_REQUEST):
		rc = sua_disconnect_req(link, prim);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST):
		rc = sua_unitdata_req(link, prim);
		break;
	default:
		rc = -1;
	}

	if (rc != 1)
		msgb_free(msg);

	return rc;
}


/***********************************************************************
 * Mandatory IE checking
 ***********************************************************************/

#define MAND_IES(msgt, ies)	[msgt] = (ies)

static const uint16_t cldt_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_SRC_ADDR,
	SUA_IEI_DEST_ADDR, SUA_IEI_SEQ_CTRL, SUA_IEI_DATA, 0
};

static const uint16_t cldr_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_CAUSE, SUA_IEI_SRC_ADDR,
	SUA_IEI_DEST_ADDR, 0
};

static const uint16_t codt_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_DATA, 0
};

static const uint16_t coda_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, 0
};

static const uint16_t core_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_SRC_REF,
	SUA_IEI_DEST_ADDR, SUA_IEI_SEQ_CTRL, 0
};

static const uint16_t coak_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_DEST_REF,
	SUA_IEI_SRC_REF, SUA_IEI_SEQ_CTRL, 0
};

static const uint16_t coref_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_CAUSE, 0
};

static const uint16_t relre_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF,
	SUA_IEI_CAUSE, 0
};

static const uint16_t relco_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, 0
};

static const uint16_t resre_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF,
	SUA_IEI_CAUSE, 0
};

static const uint16_t resco_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, 0
};

static const uint16_t coerr_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_CAUSE, 0
};

static const uint16_t coit_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_SRC_REF,
	SUA_IEI_DEST_REF, 0
};

static const uint16_t *mand_ies_cl[256] = {
	MAND_IES(SUA_CL_CLDT, cldt_mand_ies),
	MAND_IES(SUA_CL_CLDR, cldr_mand_ies),
};

static const uint16_t *mand_ies_co[256] = {
	MAND_IES(SUA_CO_CODT, codt_mand_ies),
	MAND_IES(SUA_CO_CODA, coda_mand_ies),
	MAND_IES(SUA_CO_CORE, core_mand_ies),
	MAND_IES(SUA_CO_COAK, coak_mand_ies),
	MAND_IES(SUA_CO_COREF, coref_mand_ies),
	MAND_IES(SUA_CO_RELRE, relre_mand_ies),
	MAND_IES(SUA_CO_RELCO, relco_mand_ies),
	MAND_IES(SUA_CO_RESRE, resre_mand_ies),
	MAND_IES(SUA_CO_RESCO, resco_mand_ies),
	MAND_IES(SUA_CO_COERR, coerr_mand_ies),
	MAND_IES(SUA_CO_COIT, coit_mand_ies),
};

static int check_all_mand_ies(const uint16_t **mand_ies, struct xua_msg *xua)
{
	uint8_t msg_type = xua->hdr.msg_type;
	const uint16_t *ies = mand_ies[msg_type];
	uint16_t ie;

	for (ie = *ies; ie; ie = *ies++) {
		if (!xua_msg_find_tag(xua, ie)) {
			LOGP(DSUA, LOGL_ERROR, "SUA Message %u:%u should "
				"contain IE 0x%04x, but doesn't\n",
				xua->hdr.msg_class, msg_type, ie);
			return 0;
		}
	}

	return 1;
}


/***********************************************************************
 * Receiving SUA messsages from SCTP
 ***********************************************************************/

static int sua_parse_addr(struct osmo_sccp_addr *out,
			  struct xua_msg *xua,
			  uint16_t iei)
{
	const struct xua_msg_part *param = xua_msg_find_tag(xua, iei);

	if (!param)
		return -ENODEV;

	/* FIXME */
	return 0;
}

static int sua_rx_cldt(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct osmo_scu_unitdata_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg = sua_msgb_alloc();
	uint32_t protocol_class;

	/* fill primitive */
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.unitdata;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_UNITDATA,
			PRIM_OP_INDICATION, upmsg);
	sua_parse_addr(&param->called_addr, xua, SUA_IEI_DEST_ADDR);
	sua_parse_addr(&param->calling_addr, xua, SUA_IEI_SRC_ADDR);
	param->in_sequence_control = xua_msg_get_u32(xua, SUA_IEI_SEQ_CTRL);
	protocol_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	param->return_option = protocol_class & 0x80;
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

	/* copy data */
	upmsg->l2h = msgb_put(upmsg, data_ie->len);
	memcpy(upmsg->l2h, data_ie->dat, data_ie->len);

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	return 0;
}


/* connectioness messages received from socket */
static int sua_rx_cl(struct osmo_sccp_link *link,
		     struct xua_msg *xua, struct msgb *msg)
{
	int rc = -1;

	if (!check_all_mand_ies(mand_ies_cl, xua))
		return -1;

	switch (xua->hdr.msg_type) {
	case SUA_CL_CLDT:
		rc = sua_rx_cldt(link, xua);
		break;
	case SUA_CL_CLDR:
	default:
		break;
	}

	return rc;
}

/* RFC 3868 3.3.3 / SCCP CR */
static int sua_rx_core(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct osmo_scu_connect_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg;
	struct sua_connection *conn;

	/* fill conn */
	conn = conn_create(link);
	sua_parse_addr(&conn->called_addr, xua, SUA_IEI_DEST_ADDR);
	sua_parse_addr(&conn->calling_addr, xua, SUA_IEI_SRC_ADDR);
	conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);

	/* fill primitive */
	upmsg = sua_msgb_alloc();
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.connect;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_INDICATION, upmsg);
	param->conn_id = conn->conn_id;
	memcpy(&param->called_addr, &conn->called_addr,
		sizeof(param->called_addr));
	memcpy(&param->calling_addr, &conn->calling_addr,
		sizeof(param->calling_addr));
	//param->in_sequence_control;
	param->sccp_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) & 3;
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

	if (data_ie) {
		/* copy data */
		upmsg->l2h = msgb_put(upmsg, data_ie->len);
		memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
	}

	conn_state_set(conn, S_CONN_PEND_IN);

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	return 0;
}

/* RFC 3868 3.3.4 / SCCP CC */
static int sua_rx_coak(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct sua_connection *conn;
	struct osmo_scu_connect_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg;
	uint32_t conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);

	/* resolve conn */
	conn = conn_find_by_id(link, conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "COAK for unknown reference %u\n",
			conn_id);
		/* FIXME: send error reply down the sua link? */
		return -1;
	}
	conn_restart_rx_inact_timer(conn);

	if (conn->state != S_CONN_PEND_OUT) {
		LOGP(DSUA, LOGL_ERROR, "COAK in wrong state %s\n",
			get_value_string(conn_state_names, conn->state));
		/* FIXME: send error reply down the sua link? */
		return -EINVAL;
	}

	/* track remote reference */
	conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);

	/* fill primitive */
	upmsg = sua_msgb_alloc();
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.connect;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_CONFIRM, upmsg);
	param->conn_id = conn->conn_id;
	memcpy(&param->called_addr, &conn->called_addr,
		sizeof(param->called_addr));
	memcpy(&param->calling_addr, &conn->calling_addr,
		sizeof(param->calling_addr));
	//param->in_sequence_control;
	param->sccp_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) & 3;
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

	if (data_ie) {
		/* copy data */
		upmsg->l2h = msgb_put(upmsg, data_ie->len);
		memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
	}

	conn_state_set(conn, S_ACTIVE);
	conn_start_inact_timers(conn);

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	return 0;
}

/* RFC 3868 3.3.5 / SCCP CREF */
static int sua_rx_coref(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct sua_connection *conn;
	struct osmo_scu_connect_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg;
	uint32_t conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);
	uint32_t cause;

	/* resolve conn */
	conn = conn_find_by_id(link, conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "COREF for unknown reference %u\n",
			conn_id);
		/* FIXME: send error reply down the sua link? */
		return -1;
	}
	conn_restart_rx_inact_timer(conn);

	/* fill primitive */
	upmsg = sua_msgb_alloc();
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.connect;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DISCONNECT,
			PRIM_OP_INDICATION, upmsg);
	param->conn_id = conn_id;
	memcpy(&param->called_addr, &conn->called_addr,
		sizeof(param->called_addr));
	memcpy(&param->calling_addr, &conn->calling_addr,
		sizeof(param->calling_addr));
	//param->in_sequence_control;
	/* TODO evaluate cause:
	 * cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE); */
	/* optional: src addr */
	/* optional: dest addr */
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
	if (data_ie) {
		/* copy data */
		upmsg->l2h = msgb_put(upmsg, data_ie->len);
		memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
	}

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	conn_state_set(conn, S_IDLE);
	conn_destroy(conn);

	return 0;
}

/* RFC 3868 3.3.6 / SCCP RLSD */
static int sua_rx_relre(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct sua_connection *conn;
	struct osmo_scu_connect_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg;
	uint32_t conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);
	uint32_t cause;

	/* resolve conn */
	conn = conn_find_by_id(link, conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "RELRE for unknown reference %u\n",
			conn_id);
		/* FIXME: send error reply down the sua link? */
		return -1;
	}

	/* fill primitive */
	upmsg = sua_msgb_alloc();
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.connect;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DISCONNECT,
			PRIM_OP_INDICATION, upmsg); /* what primitive? */

	param->conn_id = conn_id;
	/* source reference */
	cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE);
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
	if (data_ie) {
		/* copy data */
		upmsg->l2h = msgb_put(upmsg, data_ie->len);
		memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
	}

	memcpy(&param->called_addr, &conn->called_addr,
		sizeof(param->called_addr));
	memcpy(&param->calling_addr, &conn->calling_addr,
		sizeof(param->calling_addr));

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	conn_state_set(conn, S_IDLE);
	conn_destroy(conn);

	return 0;
}

/* RFC 3868 3.3.7 / SCCP RLC */
static int sua_rx_relco(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct sua_connection *conn;
	struct osmo_scu_connect_param *param;
	struct msgb *upmsg;
	uint32_t conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);

	/* resolve conn */
	conn = conn_find_by_id(link, conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "RELCO for unknown reference %u\n",
			conn_id);
		/* FIXME: send error reply down the sua link? */
		return -1;
	}
	conn_restart_rx_inact_timer(conn);

	/* fill primitive */
	upmsg = sua_msgb_alloc();
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.connect;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DISCONNECT,
			PRIM_OP_CONFIRM, upmsg); /* what primitive? */

	param->conn_id = conn_id;
	/* source reference */
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

	memcpy(&param->called_addr, &conn->called_addr,
		sizeof(param->called_addr));
	memcpy(&param->calling_addr, &conn->calling_addr,
		sizeof(param->calling_addr));

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	conn_destroy(conn);

	return 0;

}

/* RFC3868 3.3.1 / SCCP DT1 */
static int sua_rx_codt(struct osmo_sccp_link *link, struct xua_msg *xua)
{
	struct osmo_scu_prim *prim;
	struct sua_connection *conn;
	struct osmo_scu_data_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
	struct msgb *upmsg;
	uint32_t conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);
	uint8_t *cur;

	/* resolve conn */
	conn = conn_find_by_id(link, conn_id);
	if (!conn) {
		LOGP(DSUA, LOGL_ERROR, "DT1 for unknown reference %u\n",
			conn_id);
		/* FIXME: send error reply down the sua link? */
		return -1;
	}

	if (conn->state != S_ACTIVE) {
		LOGP(DSUA, LOGL_ERROR, "DT1 in invalid state %s\n",
			get_value_string(conn_state_names, conn->state));
		/* FIXME: send error reply down the sua link? */
		return -1;
	}

	conn_restart_rx_inact_timer(conn);

	/* fill primitive */
	upmsg = sua_msgb_alloc();
	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.data;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_INDICATION, upmsg);
	param->conn_id = conn_id;
	param->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

	/* copy data */
	upmsg->l2h = msgb_put(upmsg, data_ie->len);
	memcpy(upmsg->l2h, data_ie->dat, data_ie->len);

	/* send to user SAP */
	link->user->prim_cb(&prim->oph, link);

	return 0;
}


/* connection-oriented messages received from socket */
static int sua_rx_co(struct osmo_sccp_link *link,
		     struct xua_msg *xua, struct msgb *msg)
{
	int rc = -1;

	if (!check_all_mand_ies(mand_ies_co, xua))
		return -1;

	switch (xua->hdr.msg_type) {
	case SUA_CO_CORE:
		rc = sua_rx_core(link, xua);
		break;
	case SUA_CO_COAK:
		rc = sua_rx_coak(link, xua);
		break;
	case SUA_CO_COREF:
		rc = sua_rx_coref(link, xua);
		break;
	case SUA_CO_RELRE:
		rc = sua_rx_relre(link, xua);
		break;
	case SUA_CO_RELCO:
		rc = sua_rx_relco(link, xua);
		break;
	case SUA_CO_CODT:
		rc = sua_rx_codt(link, xua);
		break;
	case SUA_CO_RESCO:
	case SUA_CO_RESRE:
	case SUA_CO_CODA:
	case SUA_CO_COERR:
	case SUA_CO_COIT:
		/* FIXME */
	default:
		break;
	}

	return rc;
}

/* process SUA message received from socket */
static int sua_rx_msg(struct osmo_sccp_link *link, struct msgb *msg)
{
	struct xua_msg *xua;
	int rc = -1;

	xua = xua_from_msg(1, msgb_length(msg), msg->data);
	if (!xua) {
		LOGP(DSUA, LOGL_ERROR, "Unable to parse incoming "
			"SUA message\n");
		return -EIO;
	}

	LOGP(DSUA, LOGL_DEBUG, "Received SUA Message (%u:%u)\n",
		xua->hdr.msg_class, xua->hdr.msg_type);

	switch (xua->hdr.msg_class) {
	case SUA_MSGC_CL:
		rc = sua_rx_cl(link, xua, msg);
		break;
	case SUA_MSGC_CO:
		rc = sua_rx_co(link, xua, msg);
		break;
	case SUA_MSGC_MGMT:
	case SUA_MSGC_SNM:
	case SUA_MSGC_ASPSM:
	case SUA_MSGC_ASPTM:
	case SUA_MSGC_RKM:
		/* FIXME */
	default:
		break;
	}

	xua_msg_free(xua);

	return rc;
}

/***********************************************************************
 * libosmonetif integration
 ***********************************************************************/

#include <osmocom/netif/stream.h>
#include <netinet/sctp.h>

/* netif code tells us we can read something from the socket */
static int sua_srv_conn_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_sccp_link *link = osmo_stream_srv_get_data(conn);
	struct msgb *msg = msgb_alloc(SUA_MSGB_SIZE, "SUA Server Rx");
	struct sctp_sndrcvinfo sinfo;
	unsigned int ppid;
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read SUA message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGP(DSUA, LOGL_DEBUG, "sua_srv_conn_cb(): sctp_recvmsg() returned %d\n",
	     rc);
	if (rc < 0) {
		close(ofd->fd);
		osmo_fd_unregister(ofd);
		ofd->fd = -1;
		return rc;
	} else if (rc == 0) {
		close(ofd->fd);
		osmo_fd_unregister(ofd);
		ofd->fd = -1;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		printf("NOTIFICATION %u flags=0x%x\n", notif->sn_header.sn_type, notif->sn_header.sn_flags);
		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			printf("===> ASSOC CHANGE:");
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_UP:
				printf(" UP\n");
				break;
			case SCTP_COMM_LOST:
				printf(" LOST\n");
				break;
			case SCTP_RESTART:
				printf(" RESTART\n");
				break;
			case SCTP_SHUTDOWN_COMP:
				printf(" SHUTDOWN COMP\n");
				break;
			case SCTP_CANT_STR_ASSOC:
				printf(" CANT STR ASSOC\n");
				break;
			}
			break;
		case SCTP_PEER_ADDR_CHANGE:
			printf("===> PEER ADDR CHANGE\n");
			break;
		case SCTP_SHUTDOWN_EVENT:
			printf("===> SHUTDOWN EVT (libosmo-sccp sua.c sua_srv_conn_cb())\n");
			close(ofd->fd);
			osmo_fd_unregister(ofd);
			ofd->fd = -1;
			break;
		case SCTP_SEND_FAILED:
			printf("===> SCTP_SEND_FAILED\n");
			break;
		case SCTP_REMOTE_ERROR:
			printf("===> SCTP_REMOTE_ERROR\n");
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			printf("===> SCTP_PARTIAL_DELIVERY_EVENT\n");
			break;
		case SCTP_ADAPTATION_INDICATION:
			printf("===> SCTP_ADAPTATION_INDICATION\n");
			break;
		case SCTP_AUTHENTICATION_INDICATION:
			printf("===> SCTP_AUTHENTICATION_INDICATION\n");
			break;
#ifdef SCTP_SENDER_DRY_EVENT
		case SCTP_SENDER_DRY_EVENT:
			printf("===> SCTP_SENDER_DRY_EVENT\n");
			break;
#endif
		default:
			printf("===> unknown sn_type %u 0x%x\n",
			       notif->sn_header.sn_type,
			       notif->sn_header.sn_type);
			break;
		}
		msgb_free(msg);
		return 0;
	}

	ppid = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_ppid(msg) = ppid;
	msgb_sctp_stream(msg) = ntohl(sinfo.sinfo_stream);
	msg->dst = link;

	switch (ppid) {
	case SUA_PPID:
		rc = sua_rx_msg(link, msg);
		break;
	default:
		LOGP(DSUA, LOGL_NOTICE, "SCTP chunk for unknown PPID %u "
			"received\n", ppid);
		rc = 0;
		break;
	}

	msgb_free(msg);
	return rc;
}

static int sua_srv_conn_closed_cb(struct osmo_stream_srv *srv)
{
	struct osmo_sccp_link *sual = osmo_stream_srv_get_data(srv);
	struct sua_connection *conn;

	LOGP(DSUA, LOGL_INFO, "SCTP connection closed\n");

	/* remove from per-user list of sua links */
	llist_del(&sual->list);

	llist_for_each_entry(conn, &sual->connections, list) {
		/* FIXME: send RELEASE request */
	}
	talloc_free(sual);
	osmo_stream_srv_set_data(srv, NULL);

	return 0;
}

static int sua_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_sccp_user *user = osmo_stream_srv_link_get_data(link);
	struct osmo_stream_srv *srv;
	struct osmo_sccp_link *sual;

	LOGP(DSUA, LOGL_INFO, "New SCTP connection accepted\n");

	srv = osmo_stream_srv_create(user, link, fd,
				     sua_srv_conn_cb,
				     sua_srv_conn_closed_cb, NULL);
	if (!srv) {
		close(fd);
		return -1;
	}

	/* create new SUA link and connect both data structures */
	sual = sua_link_new(user, 1);
	if (!sual) {
		osmo_stream_srv_destroy(srv);
		return -1;
	}
	sual->data = srv;
	osmo_stream_srv_set_data(srv, sual);

	return 0;
}

int osmo_sua_server_listen(struct osmo_sccp_user *user, const char *hostname, uint16_t port)
{
	int rc;

	if (user->server)
		osmo_stream_srv_link_close(user->server);
	else {
		user->server = osmo_stream_srv_link_create(user);
		osmo_stream_srv_link_set_data(user->server, user);
		osmo_stream_srv_link_set_accept_cb(user->server, sua_accept_cb);
	}

	osmo_stream_srv_link_set_addr(user->server, hostname);
	osmo_stream_srv_link_set_port(user->server, port);
	osmo_stream_srv_link_set_proto(user->server, IPPROTO_SCTP);

	rc = osmo_stream_srv_link_open(user->server);
	if (rc < 0) {
		osmo_stream_srv_link_destroy(user->server);
		user->server = NULL;
		return rc;
	}

	return 0;
}

/* netif code tells us we can read something from the socket */
static int sua_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
	struct osmo_sccp_link *link = osmo_stream_cli_get_data(conn);
	struct msgb *msg = msgb_alloc(SUA_MSGB_SIZE, "SUA Client Rx");
	struct sctp_sndrcvinfo sinfo;
	unsigned int ppid;
	int flags = 0;
	int rc;

	LOGP(DSUA, LOGL_DEBUG, "sua_cli_read_cb() rx\n");

	if (!msg)
		return -ENOMEM;

	/* read SUA message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	if (rc < 0) {
		close(ofd->fd);
		osmo_fd_unregister(ofd);
		ofd->fd = -1;
		return rc;
	} else if (rc == 0) {
		close(ofd->fd);
		osmo_fd_unregister(ofd);
		ofd->fd = -1;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		printf("NOTIFICATION %u flags=0x%x\n", notif->sn_header.sn_type, notif->sn_header.sn_flags);
		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			printf("===> ASSOC CHANGE:");
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_UP:
				printf(" UP\n");
				break;
			case SCTP_COMM_LOST:
				printf(" LOST\n");
				break;
			case SCTP_RESTART:
				printf(" RESTART\n");
				break;
			case SCTP_SHUTDOWN_COMP:
				printf(" SHUTDOWN COMP\n");
				break;
			case SCTP_CANT_STR_ASSOC:
				printf(" CANT STR ASSOC\n");
				break;
			}
			break;
		case SCTP_PEER_ADDR_CHANGE:
			printf("===> PEER ADDR CHANGE\n");
			break;
		case SCTP_SHUTDOWN_EVENT:
			printf("===> SHUTDOWN EVT (libosmo-sccp sua.c sua_cli_read_cb())\n");
			close(ofd->fd);
			osmo_fd_unregister(ofd);
			ofd->fd = -1;
			msgb_free(msg);
			return -1;
		case SCTP_SEND_FAILED:
			printf("===> SCTP_SEND_FAILED\n");
			break;
		case SCTP_REMOTE_ERROR:
			printf("===> SCTP_REMOTE_ERROR\n");
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			printf("===> SCTP_PARTIAL_DELIVERY_EVENT\n");
			break;
		case SCTP_ADAPTATION_INDICATION:
			printf("===> SCTP_ADAPTATION_INDICATION\n");
			break;
		case SCTP_AUTHENTICATION_INDICATION:
			printf("===> SCTP_AUTHENTICATION_INDICATION\n");
			break;
#ifdef SCTP_SENDER_DRY_EVENT
		case SCTP_SENDER_DRY_EVENT:
			printf("===> SCTP_SENDER_DRY_EVENT\n");
			break;
#endif
		default:
			printf("===> unknown sn_type %u 0x%x\n",
			       notif->sn_header.sn_type,
			       notif->sn_header.sn_type);
			break;
		}
		msgb_free(msg);
		return 0;
	}

	ppid = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_ppid(msg) = ppid;
	msgb_sctp_stream(msg) = ntohl(sinfo.sinfo_stream);
	msg->dst = link;

	switch (ppid) {
	case SUA_PPID:
		rc = sua_rx_msg(link, msg);
		break;
	default:
		LOGP(DSUA, LOGL_NOTICE, "SCTP chunk for unknown PPID %u "
			"received\n", ppid);
		rc = 0;
		break;
	}

	msgb_free(msg);
	return rc;
}

int osmo_sua_client_connect(struct osmo_sccp_user *user, const char *hostname, uint16_t port)
{
	struct osmo_stream_cli *cli;
	struct osmo_sccp_link *sual;
	int rc;

	cli = osmo_stream_cli_create(user);
	if (!cli)
		return -1;
	osmo_stream_cli_set_addr(cli, hostname);
	osmo_stream_cli_set_port(cli, port);
	osmo_stream_cli_set_proto(cli, IPPROTO_SCTP);
	osmo_stream_cli_set_reconnect_timeout(cli, 5);
	osmo_stream_cli_set_read_cb(cli, sua_cli_read_cb);

	/* create SUA link and associate it with stream_cli */
	sual = sua_link_new(user, 0);
	if (!sual) {
		osmo_stream_cli_destroy(cli);
		return -1;
	}
	sual->data = cli;
	osmo_stream_cli_set_data(cli, sual);

	rc = osmo_stream_cli_open2(cli, 1);
	if (rc < 0) {
		sua_link_destroy(sual);
		osmo_stream_cli_destroy(cli);
		return rc;
	}
	user->client = cli;

	return 0;
}

struct osmo_sccp_link *osmo_sua_client_get_link(struct osmo_sccp_user *user)
{
	return osmo_stream_cli_get_data(user->client);
}

static LLIST_HEAD(sua_users);

struct osmo_sccp_user *osmo_sua_user_create(void *ctx, osmo_prim_cb prim_cb,
					    void *priv)
{
	struct osmo_sccp_user *user = talloc_zero(ctx, struct osmo_sccp_user);

	user->prim_cb = prim_cb;
	user->priv = priv;
	INIT_LLIST_HEAD(&user->links);

	llist_add_tail(&user->list, &sua_users);

	return user;
}

void *osmo_sccp_link_get_user_priv(struct osmo_sccp_link *slink)
{
	return slink->user->priv;
}

void osmo_sua_user_destroy(struct osmo_sccp_user *user)
{
	struct osmo_sccp_link *link;

	llist_del(&user->list);

	llist_for_each_entry(link, &user->links, list)
		sua_link_destroy(link);

	talloc_free(user);
}

void osmo_sua_set_log_area(int area)
{
	xua_set_log_area(area);
	DSUA = area;
}
