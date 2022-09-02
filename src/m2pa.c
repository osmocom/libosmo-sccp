/* Implementation of RFC 4165 - MTP3 User Adaptation Layer */

/* (C) 2022 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
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

#include <osmocom/sigtran/protocol/m2pa.h>
#include <osmocom/sigtran/osmo_ss7.h>

enum mtp2_mtp3_primitives {
	/* L2->L3 up the stack */
	L2_L3_MESSAGE_RECEIVED,
	L2_L3_OUT_OF_SERVICE,
	L2_L3_IN_SERVICE,
	L2_L3_REMOTE_PROCESSOR_OUTAGE,
	L2_L3_REMOTE_PROCESSOR_RECOVERED,

	/* L2<-L3 down the stack */
	L3_L2_MESSAGE_FOR_TRANSMISSION,
	L3_L2_EMERGENCY,
	L3_L2_EMERGENCY_CEASES,
	L3_L2_START,
	L3_L2_STOP,
	L3_L2_FLUSH_BUFFERS,
	L3_L2_CONTINUE,

	/* below primitives can just be function calls? */
	L3_L2_RETRIEVE_BSNT,
	L2_L3_BSNT,
	L2_L3_BSNT_NOT_RETRIEVABLE,
	L3_L2_RETRIEVAL_REQUEST_AND_FSNC,
	L2_L3_RETRIEVED_MESSAGES,
	L2_L3_RETRIEVAL_COMPLETE,
	L2_L3_RETRIEVAL_NOT_POSSIBLE,
};

#define LOGPM2P(m2p, subsys, level, fmt, args ...)		\
	LOGPLINK((m2p)->link, subsys, level, fmt, ##args)

struct osmo_ss7_link;

struct osmo_m2pa_peer {
	/*! back-pointer to SS7 link (which is part of an SS7 instance */
	struct osmo_ss7_link *link;

	/*! osmo_stream / libosmo-netif handles */
	struct osmo_stream_cli *client;
	struct osmo_stream_srv *server;

	/*! pre-formatted human readable local/remote socket name */
	char *sock_name;

	/*! Rate Counter Group */
	struct rate_ctr_grouip *ctrg;

	struct {
		struct osmo_ss7_asp_peer local;
		struct osmo_ss7_asp_peer remote;
		bool is_server; /* inverse of 'passive' in vty */
	} cfg;
};

/*! obtain the ss7 instance from a m2pa_peer */
static inline struct osmo_ss7_instance *m2pa_peer_inst(struct osmo_m2pa_peer *m2p)
{
	if (!m2p || !m2p->link)
		return NULL;
	return m2p->link->linkset->inst;
}


struct osmo_m2pa_server {
};





static int m2pa_rx_user_data(struct osmo_m2pa_peer *m2p, struct msg *msg)
{
}

static int m2pa_rx_link_status(struct osmo_m2pa_peer *m2p, struct msg *msg)
{
	/* FIXME: dispatch to a FSM */
}

static int m2pa_rx_msg(struct osmo_m2pa_peer *m2p, struct msg *msg)
{
	struct m2pa_header *hdr = msgb_l2h(msg);
	uint32_t msg_length;

	/* various header consistency / compatibility checks */
	if (msgb_l2len(msg) < sizeof(*hdr)) {
		LOGPM2P(m2p, DLM2PA, LOGL_NOTICE, "Dropping short M2PA message (%u bytes)\n",
			msgb_l2len(msg));
		goto out_err;
	}
	if (hdr->common.version != M2PA_VERSION) {
		LOGPM2P(m2p, DLM2PA, LOGL_NOTICE, "Dropping unknown M2PA Version %u\n",
			hdr->common.version);
		goto out_err;
	}
	if (hdr->common.msg_class != M2PA_CLS_M2PA) {
		LOGPM2P(m2p, DLM2PA, LOGL_NOTICE, "Dropping unknown M2PA Message Class %u\n",
			hdr->common.msg_class);
		goto out_err;
	}

	/* verify outer message length with length field inside M2PA common header */
	msg_length = ntohl(hdr->common.msg_length);
	if (msg_length < msgb_l2len(msg)) {
		int trail_len = msgb_l2len(msg) - msg_length;
		LOGPM2P(m2p, DLM2PA, LOGL_NOTICE, "Received M2PA Message with %d bytes trailer\n",
			trail_len);
		/* trim the msgb to the length indicated in-line */
		msgb_pull(msg, trail_len);
	} else if (msg_length > msgb_l2len(msg)) {
		LOGPM2P(m2p, DLM2PA, LOGL_NOTICE, "Dropping truncated M2PA Message\n");
		goto out_err;
	}

	/* dispatch based on message type */
	switch (hdr->common.msg_type) {
	case M2PA_MSGT_USER_DATA:
		rc = m2pa_rx_user_data(m2p, msg);
		break;
	case M2PA_MSGT_LINK_STATUS:
		rc = m2pa_rx_link_status(m2p, msg);
		break;
	default:
		LOGPM2P(m2p, DLM2PA, LOGL_NOTICE, "Dropping unknown M2PA Message Type %u\n",
			hdr->common.msg_type);
		goto out_err;
	}

	return rc;

out_err:
	/* increment some rate counter */
	return -1;
}









static void log_sctp_notification(struct osmo_m2pa_peer *m2p, const char *pfx,
				  union sctp_notification *notif)
{
	int log_level;

	LOGPM2P(m2p, DLM2PA, LOGL_INFO, "%s SCTP NOTIFICATION %u flags=0x%0x\n",
		pfx, notif->sn_header.sn_type,
		notif->sn_header.sn_flags);

	log_level = get_logevel_by_sn_type(notif->sn_header.sn_type);

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		LOGPM2P(m2p, DLM2PA, log_level, "%s SCTP_ASSOC_CHANGE: %s\n",
			pfx, osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
		break;
	default:
		LOGPM2P(m2p, DLM2PA, log_level, "%s %s\n",
			pfx, osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		break;
	}
}

/* netif code tells us we can read something from the socket */
static int m2pa_srv_conn_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_m2pa_peer *m2p = osmo_stream_srv_get_data(conn);
	struct msgb *msg = m2pa_msgb_alloc("M2PA Server Rx");
	struct sctp_sndrcvinfo sinfo;
	unsigned int ppid;
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read M2PA message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPM2P(m2p, DLM2PA, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		__func__, rc, flags);
	if (rc < 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else if (rc == 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);

		log_sctp_notification(m2p, "M2PA SRV", notif);

		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
			break;
		case SCTP_ASSOC_CHANGE:
#if 0
			if (notif->sn_assoc_change.sac_state == SCTP_RESTART)
				xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RESTART,
							     PRIM_OP_INDICATION);
#endif
			rc = 0;
			break;
		default:
			rc = 0;
			break;
		}
		goto out;
	}

	ppid = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_ppid(msg) = ppid;
	msgb_sctp_stream(msg) = sinfo.sinfo_stream;
	msg->dst = m2p;

	rate_ctr_inc2(m2p->ctrg, SS7_ASP_CTR_PKT_RX_TOTAL);

	if (ppid == M2PA_PPID)
		rc = m2pa_rx_msg(m2p, msg);
	else
		rc = m2pa_rx_unknown(m2p, ppid, msg);

out:
	msgb_free(msg);
	return rc;
}

/* client has established SCTP connection to server */
static int m2pa_cli_connect_cb(struct osmo_stream_cli *cli)
{
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(cli);
	struct osmo_m2pa_peer *m2p = osmo_stream_cli_get_data(cli);

	/* update the socket name */
	talloc_free(m2p->sock_name);
	m2p->sock_name = osmo_sock_get_name(m2p, ofd->fd);

	LOGPM2P(m2p, DLM2PA, LOGL_INFO, "Client connected %s\n", m2p->sock_name);

#if 0
	if (asp->lm && asp->lm->prim_cb) {
		/* Notify layer manager that a connection has been
		 * established */
		xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION);
	} else {
		/* directly as the ASP FSM to start by sending an ASP-UP ... */
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
	}
#endif

	return 0;
}

static void m2pa_cli_close(struct osmo_stream_cli *cli)
{
	struct osmo_m2pa_peer *m2p = osmo_stream_cli_get_data(cli);

	osmo_stream_cli_close(cli);
#if 0
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_COMM_DOWN_IND, asp);
	/* send M-SCTP_RELEASE.ind to XUA Layer Manager */
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION);
#endif
}

static void m2pa_cli_close_and_reconnect(struct osmo_stream_cli *cli)
{
	m2pa_cli_close(cli);
	osmo_stream_cli_reconnect(cli);
}

static int m2pa_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
	struct osmo_m2pa_peer *m2p = osmo_stream_cli_get_data(conn);
	struct msgb *msg = m2pa_msgb_alloc("M2PA Client Rx");
	struct sctp_sndrcvinfo sinfo;
	unsigned int ppid;
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read M2PA message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPM2P(m2p, DLM2PA, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		__func__, rc, flags);
	if (rc < 0) {
		m2pa_cli_close_and_reconnect(conn);
		goto out;
	} else if (rc == 0) {
		m2pa_cli_close_and_reconnect(conn);
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);

		log_sctp_notification(m2p, "M2PA CLNT", notif);

		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			m2pa_cli_close_and_reconnect(conn);
			break;
		case SCTP_ASSOC_CHANGE:
			if (notif->sn_assoc_change.sac_state == SCTP_RESTART)
				xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RESTART,
							     PRIM_OP_INDICATION);
		default:
			break;
		}
		rc = 0;
		goto out;
	}

	if (rc == 0)
		goto out;

	ppid = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_ppid(msg) = ppid;
	msgb_sctp_stream(msg) = sinfo.sinfo_stream;
	msg->dst = asp;

	rate_ctr_inc2(m2p->ctrg, SS7_ASP_CTR_PKT_RX_TOTAL);

	if (ppid == M2PA_PPID)
		rc = m2pa_rx_msg(m2p, msg);
	else
		rc = m2pa_rx_unknown(m2p, ppid, msg);

out:
	msgb_free(msg);
	return rc;
}

static int m2pa_srv_conn_closed_cb(struct osmo_stream_srv *srv)
{
	struct osmo_m2pa_peer *m2p = osmo_stream_srv_get_data(srv);

	LOGP(DLM2PA, LOGL_INFO, "%s: connection closed\n", m2p ? m2p->cfg.name : "?");

	if (!m2p)
		return 0;

#if 0
	/* notify ASP FSM and everyone else */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_COMM_DOWN_IND, NULL);

	/* delete any RKM-dynamically allocated ASs for this ASP */
	xua_rkm_cleanup_dyn_as_for_asp(asp);

	/* send M-SCTP_RELEASE.ind to Layer Manager */
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION);
#endif

	m2p->server = NULL;

	return 0;
}


/* server has accept()ed a new SCTP association, let's find the M2P for
 * it (if any) */
static int m2pa_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_m2pa_server *om2s = osmo_stream_srv_link_get_data(link);
	struct osmo_stream_srv *srv;
	struct osmo_m2pa_peer *m2p;
	char *sock_name = osmo_sock_get_name(link, fd);

	LOGP(DLM2PA, LOGL_INFO, "%s: New M2PA connection accepted\n", sock_name);

	srv = osmo_stream_srv_create(om2s, link, fd, m2pa_srv_conn_cb, m2pa_srv_conn_closed_cb, NULL);
	if (!srv) {
		LOGP(DLM2PA, LOGL_ERROR, "%s: Unable to create stream server for connection\n", sock_name);
		close(fd);
		talloc_free(sock_name);
		return -1;
	}

	m2p = osmo_m2pa_peer_find_by_socket_addr(fd);
	if (m2p) {
		LOGP(DLM2PA, LOGL_INFO, "%s: matched connection to M2PA Link %s\n",
			sock_name, asp->cfg.name);
		/* we need to check if we already have a socket associated, and close it.  Otherwise it might
		 * happen that both the listen-fd for this accept() and the old socket are marked 'readable'
		 * during the same scheduling interval, and we're processing them in the "wrong" order, i.e.
		 * we first see the accept of the new fd before we see the close on the old fd */
		if (m2p->server) {
			LOGPM2P(m2p, DLM2PA, LOGL_FATAL, "accept of new connection from %s before old was closed "
				"-> close old one\n", sock_name);
			osmo_stream_srv_set_data(m2p->server, NULL);
			osmo_stream_srv_destroy(m2p->server);
			m2p->server = NULL;
		}
	} else {
		LOGP(DLM2PA, LOGL_NOTICE, "%s: M2PA connection without matching M2PA link definition\n", sock_name);
	}

	/* update the M2P reference back to the server over which the
	 * connection came in */
	m2p->server = srv;
	m2p->xua_server = om2s;
	/* update the M2P socket name */
	talloc_free(m2p->sock_name);
	m2p->sock_name = talloc_reparent(link, m2p, sock_name);
	/* make sure the conn_cb() is called with the asp as private
	 * data */
	osmo_stream_srv_set_data(srv, m2p);

#if 0
	/* send M-SCTP_ESTABLISH.ind to Layer Manager */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_EST_IND, 0);
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION);
#endif

	return 0;
}


/* push a M2PA header to the front of the given message */
static void msgb_push_m2pa_hdr(struct msgb *msg, uint8_t msg_type)
{
	struct m2pa_header *hdr;

	msg->l2h = msgb_push(msg, sizeof(*hdr));
	hdr = (struct m2pa_header *) msg->l2h;

	hdr->common.version = M2PA_VERSION;
	hdr->common.spare = 0;
	hdr->common.msg_class = M2PA_CLS_M2PA;
	hdr->common.msg_type = msg_type;
	hdr->common.msg_length = htonl(msgb_l2len(msg));
	/* BSN / FSN are handled in osmo_m2pa_peer_send() */
}

/*! Send a LINK-STATUS message to the given M2PA peer */
int osmo_m2pa_peer_send_link_status(struct osmo_m2pa_peer *m2p, enum m2pa_link_status sts)
{
	struct msgb *msg = msgb_alloc_c(m2p, 1024);

	if (!msg)
		return -ENOMEM;

	/* 32bit status is the entire message content */
	msg_put_u32(msg, htonl(sts));

	msgb_push_m2pa_hdr(msg, M2PA_MSGT_LINK_STATUS, bsn, fsn);

	return osmo_m2pa_peer_send(m2p, msg);
}

/*! \brief send a fully encoded msgb via a given M2PA peer
 *  \param[in] m2p MTP2 Peer through which to send
 *  \param[in] msg message buffer to transmit. Ownership transferred.
 *  \returns 0 on success; negative in case of error */
int osmo_m2pa_peer_send(struct osmo_m2pa_peer *m2p, struct msgb *msg)
{
	struct m2pa_header *hdr = msgb_l2h(msg);
	OSMO_ASSERT(ss7_initialized);

	msgb_sctp_ppid(msg) = M2PA_PPID;

	/* M2PA uses two streams in each direction for each association.  Stream
   	 * 0 in each direction is designated for Link Status messages.  Stream 1
	 * is designated for User Data messages, as well as Link Status messages
	 * that must remain in sequence with the User Data messages. */
	switch (hdr->m2pa.common.msg_type) {
	case M2PA_MSGT_USER_DATA:
		msgb_sctp_stream(msg) = 1;
		break;
	case M2PA_MSGT_LINK_STATUS:
		lsts = htonl((uint32_t *) hdr->data);
		switch (lsts) {
		case M2PA_LSTS_PROCESSOR_OUTAGE:
		case M2PA_LSTS_PROCESSOR_RECOVERED:
		/* TODO: READY after processor outage on 1! */
			msgb_sctp_stream(msg) = 1;
			break;
		default:
			msgb_sctp_stream(msg) = 0;
			break;
		}
		break;
	default:
		OSMO_ASSERT(0);
	}

	hdr->m2pa.bsn = htonl(bsn);
	hdr->m2pa.fsn = htonl(fsn);

	rate_ctr_inc2(m2p->ctrg, SS7_ASP_CTR_PKT_TX_TOTAL);

	if (m2p->cfg.is_server) {
		if (!m2p->server) {
			LOGPM2P(m2p, DLM2PA, LOGL_ERROR, "Cannot transmit, no m2p->server\n");
			/* FIXME: what to do here? delete the route? send DUNA? */
			msgb_free(msg);
			return -EIO;
		}
		osmo_stream_srv_send(m2p->server, msg);
	} else {
		if (!m2p->client) {
			LOGPM2P(m2p, DLM2PA, LOGL_ERROR, "Cannot transmit, no m2p->client\n");
			/* FIXME: what to do here? delete the route? send DUNA? */
			msgb_free(msg);
			return -EIO;
		}
		if (!osmo_stream_cli_is_connected(m2p->client)) {
			LOGPM2P(m2p, DLM2PA, LOGL_ERROR, "Cannot transmit, m2p->client not connected\n");
			msgb_free(msg);
			return -EIO;
		}
		osmo_stream_cli_send(m2p->client, msg);
	}

	return 0;
}

void osmo_m2pa_peer_disconnect(struct osmo_m2pa_peer *m2p)
{
	if (m2p->server)
		osmo_stream_srv_destroy(m2p->server);
		/* the close_cb() will handle the remaining cleanup here */
	else if (m2p->client)
		xua_cli_close_and_reconnect(m2p->client);
}

/***********************************************************************
 * M2PA SCTP Server
 ***********************************************************************/

struct osmo_m2pa_server *
osmo_ss7_m2pa_server_find(struct osmo_ss7_instance *inst, uint16_t local_port)
{
	struct osmo_m2pa_server *m2s;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(m2s, &inst->m2pa_servers, list) {
		if (local_port == m2s->cfg.local.port)
			return m2s;
	}
	return NULL;
}


/*! \brief create a new M2PA server configured with given ip/port
 *  \param[in] ctx talloc allocation context
 *  \param[in] local_port local SCTP port to bind/listen to
 *  \param[in] local_host local IP address to bind/listen to (optional)
 *  \returns callee-allocated \ref osmo_m2pa_server in case of success
 */
struct osmo_m2pa_server *
osmo_m2pa_server_create(struct osmo_ss7_instance *inst, uint16_t local_port, const char *local_host)
{
	struct osmo_m2pa_server *om2s = talloc_zero(inst, struct osmo_m2pa_server);

	OSMO_ASSERT(ss7_initialized);
	if (!om2s)
		return NULL;

	LOGP(DLM2PA, LOGL_INFO, "Creating M2PA Server %s:%u\n", local_host, local_port);

	//INIT_LLIST_HEAD(&om2s->asp_list);

	//om2s->cfg.proto = proto;
	om2s->cfg.local.port = local_port;

	om2s->server = osmo_stream_srv_link_create(om2s);
	osmo_stream_srv_link_set_data(om2s->server, om2s);
	osmo_stream_srv_link_set_accept_cb(om2s->server, xua_accept_cb);

	osmo_stream_srv_link_set_nodelay(om2s->server, true);
	osmo_stream_srv_link_set_port(om2s->server, om2s->cfg.local.port);
	osmo_stream_srv_link_set_proto(om2s->server, IPPROTO_SCTP);

	osmo_ss7_xua_server_set_local_host(om2s, local_host);

	LOGP(DLM2PA, LOGL_INFO, "Created M2PA server on %s:%" PRIu16 "\n", local_host, local_port);

	om2s->inst = inst;
	llist_add_tail(&om2s->list, &inst->m2pa_servers);

	return om2s;
}

/*! \brief Set the M2PA server to bind/listen to the currently configured ip/port
 *  \param[in] m2s M2PA server to operate
 *  \returns 0 on success, negative value on error.
 */
int
osmo_ss7_m2pa_server_bind(struct osmo_m2pa_server *m2s)
{
	char buf[512];
	int rc;

	rc = osmo_ss7_asp_peer_snprintf(buf, sizeof(buf), &m2s->cfg.local);
	if (rc < 0) {
		LOGP(DLM2PA, LOGL_INFO, "Failed parsing M2PA Server osmo_ss7_asp_peer\n");
	} else {
		LOGP(DLM2PA, LOGL_INFO, "(Re)binding M2PA Server to %s\n", buf);
	}
	return osmo_stream_srv_link_open(m2s->server);
}

int
osmo_ss7_m2pa_server_set_local_host(struct osmo_m2pa_server *m2s, const char *local_host)
{
	return osmo_ss7_xua_server_set_local_hosts(m2s, &local_host, 1);
}

int
osmo_ss7_m2pa_server_set_local_hosts(struct osmo_m2pa_server *m2s, const char **local_hosts, size_t local_host_cnt)
{
	int rc;

	OSMO_ASSERT(ss7_initialized);
	rc = osmo_ss7_asp_peer_set_hosts(&m2s->cfg.local, m2s, local_hosts, local_host_cnt);
	if (rc < 0)
		return rc;

	return osmo_stream_srv_link_set_addrs(m2s->server, (const char **)m2s->cfg.local.host, m2s->cfg.local.host_cnt);
}

int
osmo_ss7_m2pa_server_add_local_host(struct osmo_m2pa_server *m2s, const char *local_host)
{
	int rc;

	rc = osmo_ss7_asp_peer_add_host(&m2s->cfg.local, m2s, local_host);
	if (rc < 0)
		return rc;

	return osmo_stream_srv_link_set_addrs(m2s->server, (const char **)m2s->cfg.local.host, m2s->cfg.local.host_cnt);
}

bool osmo_ss7_m2pa_server_set_default_local_hosts(struct osmo_m2pa_server *om2s)
{
	/* If no local addr was set, or erased after _create(): */
	if (!om2s->cfg.local.host_cnt) {
		/* "::" Covers both IPv4 and IPv6 */
		if (ipv6_sctp_supported("::", true))
			osmo_ss7_m2pa_server_set_local_host(om2s, "::");
		else
			osmo_ss7_m2pa_server_set_local_host(om2s, "0.0.0.0");
		return true;
	}
	return false;
}

void osmo_ss7_m2pa_server_destroy(struct osmo_m2pa_server *m2s)
{
	//struct osmo_ss7_asp *asp, *asp2;

	if (m2s->server) {
		osmo_stream_srv_link_close(m2s->server);
		osmo_stream_srv_link_destroy(m2s->server);
	}
#if 0
	/* iterate and close all connections established in relation
	 * with this server */
	llist_for_each_entry_safe(asp, asp2, &m2s->asp_list, siblings)
		osmo_ss7_asp_destroy(asp);
#endif

	llist_del(&m2s->list);
	talloc_free(m2s);
}
