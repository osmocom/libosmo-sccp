/* Core SS7 xUA Server */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/netif/sctp.h>

#include "sccp_internal.h"
#include "xua_internal.h"
#include "ss7_internal.h"
#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"

/***********************************************************************
 * SS7 xUA Server
 ***********************************************************************/

/* server has accept()ed a new SCTP association, let's find the ASP for
 * it (if any) */
static int xua_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_xua_server *oxs = osmo_stream_srv_link_get_data(link);
	struct osmo_stream_srv *srv;
	struct osmo_ss7_asp *asp;
	char *sock_name = osmo_sock_get_name(link, fd);
	const char *proto_name = get_value_string(osmo_ss7_asp_protocol_vals, oxs->cfg.proto);
	int rc = 0;

	LOGP(DLSS7, LOGL_INFO, "%s: New %s connection accepted\n", sock_name, proto_name);

	if (oxs->cfg.proto == OSMO_SS7_ASP_PROT_IPA) {
		srv = osmo_stream_srv_create(oxs, link, fd,
					     ss7_asp_ipa_srv_conn_cb,
					     ss7_asp_xua_srv_conn_closed_cb, NULL);
	} else {
		srv = osmo_stream_srv_create(oxs, link, fd,
					     ss7_asp_xua_srv_conn_cb,
					     ss7_asp_xua_srv_conn_closed_cb, NULL);
	}
	if (!srv) {
		LOGP(DLSS7, LOGL_ERROR, "%s: Unable to create stream server "
		     "for connection\n", sock_name);
		close(fd);
		talloc_free(sock_name);
		return -1;
	}

	asp = ss7_asp_find_by_socket_addr(fd);
	if (asp) {
		LOGP(DLSS7, LOGL_INFO, "%s: matched connection to ASP %s\n",
			sock_name, asp->cfg.name);
		/* we need to check if we already have a socket associated, and close it.  Otherwise it might
		 * happen that both the listen-fd for this accept() and the old socket are marked 'readable'
		 * during the same scheduling interval, and we're processing them in the "wrong" order, i.e.
		 * we first see the accept of the new fd before we see the close on the old fd */
		if (asp->server) {
			LOGPASP(asp, DLSS7, LOGL_FATAL, "accept of new connection from %s before old was closed "
				"-> close old one\n", sock_name);
			osmo_stream_srv_set_data(asp->server, NULL);
			osmo_stream_srv_destroy(asp->server);
			asp->server = NULL;
		}
	} else {
		if (!oxs->cfg.accept_dyn_reg) {
			LOGP(DLSS7, LOGL_NOTICE, "%s: %s connection without matching "
			     "ASP definition and no dynamic registration enabled, terminating\n",
			     sock_name, proto_name);
		} else {
			char namebuf[32];
			static uint32_t dyn_asp_num = 0;
			snprintf(namebuf, sizeof(namebuf), "asp-dyn-%u", dyn_asp_num++);
			asp = osmo_ss7_asp_find_or_create(oxs->inst, namebuf, 0, 0,
							  oxs->cfg.proto);
			if (asp) {
				char hostbuf[INET6_ADDRSTRLEN];
				const char *hostbuf_ptr = &hostbuf[0];
				char portbuf[16];

				osmo_sock_get_ip_and_port(fd, hostbuf, sizeof(hostbuf), portbuf, sizeof(portbuf), false);
				LOGP(DLSS7, LOGL_INFO, "%s: created dynamic ASP %s\n",
					sock_name, asp->cfg.name);
				asp->cfg.is_server = true;
				asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
				asp->cfg.local.port = oxs->cfg.local.port;
				asp->cfg.remote.port = atoi(portbuf);
				asp->dyn_allocated = true;
				asp->server = srv;
				osmo_ss7_asp_peer_set_hosts(&asp->cfg.local, asp,
							    (const char * const*)oxs->cfg.local.host,
							    oxs->cfg.local.host_cnt);
				osmo_ss7_asp_peer_set_hosts(&asp->cfg.remote, asp,
							    &hostbuf_ptr, 1);
				osmo_ss7_asp_restart(asp);
			}
		}
		if (!asp) {
			osmo_stream_srv_destroy(srv);
			talloc_free(sock_name);
			return -1;
		}
		llist_add_tail(&asp->siblings, &oxs->asp_list);
	}

	/* update the ASP reference back to the server over which the
	 * connection came in */
	asp->server = srv;
	asp->xua_server = oxs;

	/* update the ASP socket name */
	talloc_free(asp->sock_name);
	asp->sock_name = talloc_reparent(link, asp, sock_name);
	osmo_stream_srv_set_name(asp->server, asp->cfg.name);
	/* make sure the conn_cb() is called with the asp as private
	 * data */
	osmo_stream_srv_set_data(srv, asp);

	if (oxs->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		rc = ss7_asp_apply_peer_primary_address(asp);
		rc = ss7_asp_apply_primary_address(asp);
	}

	/* send M-SCTP_ESTABLISH.ind to Layer Manager */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_EST_IND, 0);
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION);

	return rc;
}

/*! \brief create a new xUA server configured with given ip/port
 *  \param[in] ctx talloc allocation context
 *  \param[in] proto protocol (xUA variant) to use
 *  \param[in] local_port local SCTP port to bind/listen to
 *  \param[in] local_host local IP address to bind/listen to (optional)
 *  \returns callee-allocated \ref osmo_xua_server in case of success
 */
struct osmo_xua_server *
osmo_ss7_xua_server_create(struct osmo_ss7_instance *inst, enum osmo_ss7_asp_protocol proto,
			   uint16_t local_port, const char *local_host)
{
	struct osmo_xua_server *oxs = talloc_zero(inst, struct osmo_xua_server);

	OSMO_ASSERT(ss7_initialized);
	if (!oxs)
		return NULL;

	LOGP(DLSS7, LOGL_INFO, "Creating %s Server %s:%u\n",
		get_value_string(osmo_ss7_asp_protocol_vals, proto), local_host, local_port);

	INIT_LLIST_HEAD(&oxs->asp_list);

	oxs->cfg.proto = proto;
	oxs->cfg.local.port = local_port;

	oxs->server = osmo_stream_srv_link_create(oxs);
	osmo_stream_srv_link_set_name(oxs->server, osmo_ss7_asp_protocol_name(proto));
	osmo_stream_srv_link_set_data(oxs->server, oxs);
	osmo_stream_srv_link_set_accept_cb(oxs->server, xua_accept_cb);

	osmo_stream_srv_link_set_nodelay(oxs->server, true);
	osmo_stream_srv_link_set_port(oxs->server, oxs->cfg.local.port);
	osmo_stream_srv_link_set_proto(oxs->server, ss7_asp_proto_to_ip_proto(proto));

	osmo_ss7_xua_server_set_local_host(oxs, local_host);

	LOGP(DLSS7, LOGL_INFO, "Created %s server on %s:%" PRIu16 "\n",
		get_value_string(osmo_ss7_asp_protocol_vals, proto), local_host, local_port);

	oxs->inst = inst;
	llist_add_tail(&oxs->list, &inst->xua_servers);

	/* The SUA code internally needs SCCP to work */
	if (proto == OSMO_SS7_ASP_PROT_SUA)
		osmo_ss7_ensure_sccp(inst);

	return oxs;
}

/*! \brief Set the xUA server to bind/listen to the currently configured ip/port
 *  \param[in] xs xUA server to operate
 *  \returns 0 on success, negative value on error.
 */
int
osmo_ss7_xua_server_bind(struct osmo_xua_server *xs)
{
	char buf[512];
	int rc;
	const char *proto = get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto);

	rc = osmo_ss7_asp_peer_snprintf(buf, sizeof(buf), &xs->cfg.local);
	if (rc < 0) {
		LOGP(DLSS7, LOGL_INFO, "Failed parsing %s Server osmo_ss7_asp_peer\n", proto);
	} else {
		LOGP(DLSS7, LOGL_INFO, "(Re)binding %s Server to %s\n",
		     proto, buf);
	}
	return osmo_stream_srv_link_open(xs->server);
}

int
osmo_ss7_xua_server_set_local_host(struct osmo_xua_server *xs, const char *local_host)
{
	return osmo_ss7_xua_server_set_local_hosts(xs, &local_host, 1);
}

int
osmo_ss7_xua_server_set_local_hosts(struct osmo_xua_server *xs, const char **local_hosts, size_t local_host_cnt)
{
	int rc;
	OSMO_ASSERT(ss7_initialized);

	rc = osmo_ss7_asp_peer_set_hosts(&xs->cfg.local, xs, local_hosts, local_host_cnt);
	if (rc < 0)
		return rc;
	return osmo_stream_srv_link_set_addrs(xs->server, (const char **)xs->cfg.local.host, xs->cfg.local.host_cnt);
}

int
osmo_ss7_xua_server_add_local_host(struct osmo_xua_server *xs, const char *local_host)
{
	int rc;

	rc = osmo_ss7_asp_peer_add_host(&xs->cfg.local, xs, local_host);
	if (rc < 0)
		return rc;
	return osmo_stream_srv_link_set_addrs(xs->server, (const char **)xs->cfg.local.host, xs->cfg.local.host_cnt);
}

bool ss7_xua_server_set_default_local_hosts(struct osmo_xua_server *oxs)
{
	/* If no local addr was set, or erased after _create(): */
	if (!oxs->cfg.local.host_cnt) {
		/* "::" Covers both IPv4 and IPv6 */
		if (ss7_ipv6_sctp_supported("::", true))
			osmo_ss7_xua_server_set_local_host(oxs, "::");
		else
			osmo_ss7_xua_server_set_local_host(oxs, "0.0.0.0");
		return true;
	}
	return false;
}

void osmo_ss7_xua_server_destroy(struct osmo_xua_server *xs)
{
	struct osmo_ss7_asp *asp, *asp2;

	if (xs->server) {
		osmo_stream_srv_link_close(xs->server);
		osmo_stream_srv_link_destroy(xs->server);
	}
	/* iterate and close all connections established in relation
	 * with this server */
	llist_for_each_entry_safe(asp, asp2, &xs->asp_list, siblings)
		osmo_ss7_asp_destroy(asp);

	llist_del(&xs->list);
	talloc_free(xs);
}
