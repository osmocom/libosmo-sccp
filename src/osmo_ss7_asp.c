/* Core SS7 ASP Handling */

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

static int _setsockopt_peer_primary_addr(int fd, const struct osmo_sockaddr *saddr)
{
	int rc;

	struct sctp_setpeerprim so_sctp_setpeerprim = {0};

	/* rfc6458 sec 8: "For the one-to-one style sockets and branched-off one-to-many
	 * style sockets (see Section 9.2), this association ID parameter is ignored"
	 */

	/* NOTE: Requires setting:
	 * - sysctl net.sctp.addip_enable = 1, otherwise EPERM is returned
	 * - sysctl net.sctp.auth_enable = 1, RFC 5061 4.2.7 "An implementation supporting this
	 *   extension MUST list the ASCONF,the ASCONF-ACK, and the AUTH chunks in
	 *   its INIT and INIT-ACK parameters."
	 */

	so_sctp_setpeerprim.sspp_addr = saddr->u.sas;
	rc = setsockopt(fd, IPPROTO_SCTP, SCTP_SET_PEER_PRIMARY_ADDR,
			&so_sctp_setpeerprim, sizeof(so_sctp_setpeerprim));
	if (rc < 0) {
		char buf[128];
		int err = errno;
		strerror_r(err, (char *)buf, sizeof(buf));
		LOGP(DLSS7, LOGL_ERROR, "setsockopt(SCTP_SET_PEER_PRIMARY_ADDR, %s) failed: %s%s\n",
		     osmo_sockaddr_to_str(saddr), buf,
		     err == EPERM ? " (EPERM: Make sure you have sysctl 'net.sctp.auth_enable' "
				    "and 'net.sctp.addip_enable' set to 1)" : "");
	}
	return rc;
}

static int _setsockopt_primary_addr(int fd, const struct osmo_sockaddr *saddr)
{
	int rc;

	struct sctp_prim so_sctp_prim = {0};

	/* rfc6458 sec 8: "For the one-to-one style sockets and branched-off one-to-many
	 * style sockets (see Section 9.2), this association ID parameter is ignored"
	 */

	so_sctp_prim.ssp_addr = saddr->u.sas;
	rc = setsockopt(fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
			&so_sctp_prim, sizeof(so_sctp_prim));
	if (rc < 0) {
		char buf[128];
		strerror_r(errno, (char *)buf, sizeof(buf));
		LOGP(DLSS7, LOGL_ERROR, "setsockopt(SCTP_PRIMARY_ADDR, %s) failed: %s\n",
		     osmo_sockaddr_to_str(saddr), buf);
	}
	return rc;
}

/***********************************************************************
 * SS7 Application Server Process
 ***********************************************************************/

struct value_string osmo_ss7_asp_protocol_vals[] = {
	{ OSMO_SS7_ASP_PROT_NONE,	"none" },
	{ OSMO_SS7_ASP_PROT_SUA,	"sua" },
	{ OSMO_SS7_ASP_PROT_M3UA,	"m3ua" },
	{ OSMO_SS7_ASP_PROT_IPA,	"ipa" },
	{ 0, NULL }
};

const struct value_string osmo_ss7_asp_role_names[] = {
	{ OSMO_SS7_ASP_ROLE_ASP,	"ASP" },
	{ OSMO_SS7_ASP_ROLE_SG,		"SG" },
	{ OSMO_SS7_ASP_ROLE_IPSP,	"IPSP" },
	{ 0, NULL }
};

int ss7_asp_proto_to_ip_proto(enum osmo_ss7_asp_protocol proto)
{
	switch (proto) {
	case OSMO_SS7_ASP_PROT_IPA:
		return IPPROTO_TCP;
	case OSMO_SS7_ASP_PROT_SUA:
	case OSMO_SS7_ASP_PROT_M3UA:
	default:
		return IPPROTO_SCTP;
	}
}

static const uint16_t prot2port[] = {
	[OSMO_SS7_ASP_PROT_NONE] = 0,
	[OSMO_SS7_ASP_PROT_SUA] = SUA_PORT,
	[OSMO_SS7_ASP_PROT_M3UA] = M3UA_PORT,
	[OSMO_SS7_ASP_PROT_IPA] = 5000,
};

int osmo_ss7_asp_protocol_port(enum osmo_ss7_asp_protocol prot)
{
	if (prot >= ARRAY_SIZE(prot2port))
		return -EINVAL;
	else
		return prot2port[prot];
}

static const struct rate_ctr_desc ss7_asp_rcd[] = {
	[SS7_ASP_CTR_PKT_RX_TOTAL] = { "rx:packets:total", "Total number of packets received" },
	[SS7_ASP_CTR_PKT_RX_UNKNOWN] = { "rx:packets:unknown", "Number of packets received for unknown PPID" },
	[SS7_ASP_CTR_PKT_TX_TOTAL] = { "tx:packets:total", "Total number of packets transmitted" },
};

static const struct rate_ctr_group_desc ss7_asp_rcgd = {
	.group_name_prefix = "sigtran_asp",
	.group_description = "SIGTRAN Application Server Process",
	.num_ctr = ARRAY_SIZE(ss7_asp_rcd),
	.ctr_desc = ss7_asp_rcd,
};
static unsigned int g_ss7_asp_rcg_idx;

int ss7_asp_apply_new_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx)
{
	const char *new_loc_addr;
	int fd;

	OSMO_ASSERT(loc_idx < asp->cfg.local.host_cnt);
	new_loc_addr = asp->cfg.local.host[loc_idx];

	LOGPASP(asp, DLSS7, LOGL_INFO, "Add local address %s\n",
		new_loc_addr);

	if (asp->cfg.is_server)
		fd = osmo_stream_srv_get_fd(asp->server);
	else
		fd = osmo_stream_cli_get_fd(asp->client);

	if (fd < 0)
		return fd;

	return osmo_sock_multiaddr_add_local_addr(fd, &new_loc_addr, 1);
}

int ss7_asp_apply_drop_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx)
{
	const char *new_loc_addr;
	int fd;

	OSMO_ASSERT(loc_idx < asp->cfg.local.host_cnt);
	new_loc_addr = asp->cfg.local.host[loc_idx];

	LOGPASP(asp, DLSS7, LOGL_INFO, "Remove local address %s\n",
		new_loc_addr);

	if (asp->cfg.is_server)
		fd = osmo_stream_srv_get_fd(asp->server);
	else
		fd = osmo_stream_cli_get_fd(asp->client);

	if (fd < 0)
		return fd;

	return osmo_sock_multiaddr_del_local_addr(fd, &new_loc_addr, 1);
}

int ss7_asp_apply_peer_primary_address(const struct osmo_ss7_asp *asp)
{
	struct osmo_sockaddr_str addr_str;
	struct osmo_sockaddr addr;
	uint16_t local_port;
	int fd, rc;

	/* No SCTP Peer Primary Address explicitly configured, do nothing. */
	if (asp->cfg.local.idx_primary == -1)
		return 0;
	OSMO_ASSERT(asp->cfg.local.idx_primary < asp->cfg.local.host_cnt);

	if (asp->cfg.is_server)
		fd = osmo_stream_srv_get_fd(asp->server);
	else
		fd = osmo_stream_cli_get_fd(asp->client);

	if (fd < 0)
		return fd;

	if (asp->cfg.local.port == 0) {
		char port_buf[16];
		osmo_sock_get_local_ip_port(fd, port_buf, sizeof(port_buf));
		local_port = atoi(port_buf);
	} else {
		local_port = asp->cfg.local.port;
	}
	rc = osmo_sockaddr_str_from_str(&addr_str,
					asp->cfg.local.host[asp->cfg.local.idx_primary],
					local_port);
	if (rc < 0)
		return rc;
	rc = osmo_sockaddr_str_to_sockaddr(&addr_str, &addr.u.sas);
	if (rc < 0)
		return rc;
	LOGPASP(asp, DLSS7, LOGL_INFO, "Set Peer's Primary Address %s\n",
		osmo_sockaddr_to_str(&addr));
	rc = _setsockopt_peer_primary_addr(fd, &addr);

	return rc;
}

int ss7_asp_apply_primary_address(const struct osmo_ss7_asp *asp)
{
	struct osmo_sockaddr_str addr_str;
	struct osmo_sockaddr addr;
	int fd, rc;

	/* No SCTP Primary Address explicitly configured, do nothing. */
	if (asp->cfg.remote.idx_primary == -1)
		return 0;
	OSMO_ASSERT(asp->cfg.remote.idx_primary < asp->cfg.remote.host_cnt);

	if (asp->cfg.is_server)
		fd = osmo_stream_srv_get_fd(asp->server);
	else
		fd = osmo_stream_cli_get_fd(asp->client);

	if (fd < 0)
		return fd;

	rc = osmo_sockaddr_str_from_str(&addr_str,
					asp->cfg.remote.host[asp->cfg.remote.idx_primary],
					asp->cfg.remote.port);
	if (rc < 0)
		return rc;
	rc = osmo_sockaddr_str_to_sockaddr(&addr_str, &addr.u.sas);
	if (rc < 0)
		return rc;
	LOGPASP(asp, DLSS7, LOGL_INFO, "Set Primary Address %s\n",
		osmo_sockaddr_to_str(&addr));
	rc = _setsockopt_primary_addr(fd, &addr);
	return rc;
}

/* Returns whether the address signalled in the SCTP_PEER_ADDR_CHANGE matches
 * the user-configured Primary Address. */
static bool sctp_peer_addr_change_ev_addr_matches_our_primary(const struct osmo_ss7_asp *asp,
							      const union sctp_notification *notif)
{
	const char *primary_str;
	int primary_str_type;
	struct osmo_sockaddr ev_addr, primary;

	OSMO_ASSERT(asp->cfg.remote.idx_primary >= 0);

	primary_str = asp->cfg.remote.host[asp->cfg.remote.idx_primary];
	primary_str_type = osmo_ip_str_type(primary_str);
	memcpy(&ev_addr.u.sas, &notif->sn_paddr_change.spc_aaddr, sizeof(ev_addr.u.sas));

	/* This whole switch is to properly compare addresses (take into account v6mapped IPv4 addresses): */
	switch (ev_addr.u.sa.sa_family) {
	case AF_INET:
		switch (primary_str_type) {
		case AF_INET:
			primary = ev_addr; /* Copy AF + port */
			inet_pton(AF_INET, primary_str, &primary.u.sin.sin_addr);
			return (osmo_sockaddr_cmp(&primary, &ev_addr) == 0);
		case AF_INET6:
			/* for sure not the same */
			return false;
		}
		return false;
	case AF_INET6:
		/* "ev_addr" can either be a IPv6 addr or a v6-mapped IPv4
		 * address. Compare both as IPv6 (or v6-mapped IPv4) addresses. */
		primary = ev_addr; /* Copy AF + port */
		inet_pton(AF_INET6, primary_str, &primary.u.sin6.sin6_addr);
		return (osmo_sockaddr_cmp(&primary, &ev_addr) == 0);
	default:
		return false;
	}
}

/* Simple SCTP Path-manager tracking/driving the VTY-user-configured primary
 * address against the kernel when assoc state changes: */
static void asp_handle_sctp_notif_monitor_primary_address(const struct osmo_ss7_asp *asp,
							  const union sctp_notification *notif)
{
	bool match;

	if (asp->cfg.remote.idx_primary == -1)
		return;
	if (notif->sn_header.sn_type != SCTP_PEER_ADDR_CHANGE)
		return;

	switch (notif->sn_paddr_change.spc_state) {
	case SCTP_ADDR_AVAILABLE:
	case SCTP_ADDR_ADDED:
	case SCTP_ADDR_CONFIRMED:
		/* If our primary addr became available/added/confirmed, set it */
		match = sctp_peer_addr_change_ev_addr_matches_our_primary(asp, notif);
		if (match)
			ss7_asp_apply_primary_address(asp);
		break;
	case SCTP_ADDR_MADE_PRIM:
		/* If another primary addr was made primary, overwrite it by setting it again */
		match = sctp_peer_addr_change_ev_addr_matches_our_primary(asp, notif);
		if (!match)
			ss7_asp_apply_primary_address(asp);
	default:
		break;
	}
}

/* Set default values for local and remote peer hosts if they are not yet set.
 *  \param[in] asp ASP for which to set default hosts.
 *  \returns true if values where changed, false otherwise.
 *
 * If the ASP is already started, osmo_ss7_asp_restart() must be called
 * afterwards in order to apply the new settings.
 * This API is internal, hence doesn't appear in osmo_ss7.h
 */
bool ss7_asp_set_default_peer_hosts(struct osmo_ss7_asp *asp)
{
	bool changed = false;
	/* If no local addr was set */
	if (!asp->cfg.local.host_cnt) {
		bool rem_has_v4 = false, rem_has_v6 = false;
		int i;
		for (i = 0; i < asp->cfg.remote.host_cnt; i++) {
			if (osmo_ip_str_type(asp->cfg.remote.host[i]) == AF_INET6)
				rem_has_v6 = true;
			else
				rem_has_v4 = true;
		}
		/* "::" Covers both IPv4 and IPv6, but if only IPv4
		 * address are set on the remote side, IPv4 on the local
		 * side must be set too */
		if (ss7_ipv6_sctp_supported("::", true) && !(rem_has_v4 && !rem_has_v6))
			osmo_ss7_asp_peer_add_host(&asp->cfg.local, asp, "::");
		else
			osmo_ss7_asp_peer_add_host(&asp->cfg.local, asp, "0.0.0.0");
		changed = true;
	}
	/* If no remote addr was set */
	if (!asp->cfg.remote.host_cnt) {
		osmo_ss7_asp_peer_add_host(&asp->cfg.remote, asp, "127.0.0.1");
		if (ss7_ipv6_sctp_supported("::1", false))
			osmo_ss7_asp_peer_add_host(&asp->cfg.remote, asp, "::1");
		changed = true;
	}
	return changed;
}

static uint16_t get_in_port(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (((struct sockaddr_in *)sa)->sin_port);
	case AF_INET6:
		return (((struct sockaddr_in6 *)sa)->sin6_port);
	default:
		return 0;
	}
}

/* Converts string representation of v4-mappend-on-v6 IP addr to a pure IPv4 address.
 * Example: ::ffff:172.18.19.200 => 172.18.19.200
 */
static void chop_v4_mapped_on_v6_prefix(char *buf)
{
	char *last_colon;
	size_t len;
	char *first_dot = strchr(buf, '.');

	if (!first_dot)
		return; /* Not an IPv4-mappend-on-v6 string representation, nothing to do */
	last_colon = strrchr(buf, ':');
	if (!last_colon)
		return; /* pure IPv4 address, nothing to do */

	len = strlen(last_colon + 1);
	memmove(buf, last_colon + 1, len);
	buf[len] = '\0';
}

/*! \brief Find an ASP definition matching the local+remote IP/PORT of given fd
 *  \param[in] fd socket descriptor of given socket
 *  \returns SS7 ASP in case a matching one is found; NULL otherwise */
struct osmo_ss7_asp *
ss7_asp_find_by_socket_addr(int fd)
{
	struct osmo_ss7_instance *inst;
	struct sockaddr_storage sa_l, sa_r;
	socklen_t sa_len_l = sizeof(sa_l);
	socklen_t sa_len_r = sizeof(sa_r);
	char hostbuf_l[64], hostbuf_r[64];
	uint16_t local_port, remote_port;
	bool loc_is_v6, rem_is_v6;
	int rc;

	OSMO_ASSERT(ss7_initialized);
	/* convert local and remote IP to string */
	rc = getsockname(fd, (struct sockaddr *)&sa_l, &sa_len_l);
	if (rc < 0)
		return NULL;
	rc = getnameinfo((struct sockaddr *)&sa_l, sa_len_l,
			 hostbuf_l, sizeof(hostbuf_l),
			 NULL, 0, NI_NUMERICHOST);
	if (rc < 0)
		return NULL;
	local_port = ntohs(get_in_port((struct sockaddr *)&sa_l));

	rc = getpeername(fd, (struct sockaddr *)&sa_r, &sa_len_r);
	if (rc < 0)
		return NULL;
	rc = getnameinfo((struct sockaddr *)&sa_r, sa_len_r,
			 hostbuf_r, sizeof(hostbuf_r),
			 NULL, 0, NI_NUMERICHOST);
	if (rc < 0)
		return NULL;
	remote_port = ntohs(get_in_port((struct sockaddr *)&sa_r));

	/* If multi-home is used with both IPv4 and IPv6, then the socket is
	 * AF_INET6, and then returned IPv4 addresses are actually v6mapped ones.
	 * We need to convert them to IPv4 before matching.
	 */
	chop_v4_mapped_on_v6_prefix(hostbuf_l);
	chop_v4_mapped_on_v6_prefix(hostbuf_r);
	loc_is_v6 = osmo_ip_str_type(hostbuf_l) == AF_INET6;
	rem_is_v6 = osmo_ip_str_type(hostbuf_r) == AF_INET6;

	/* check all instances for any ASP definition matching the
	 * address combination of local/remote ip/port */
	llist_for_each_entry(inst, &osmo_ss7_instances, list) {
		struct osmo_ss7_asp *asp;
		llist_for_each_entry(asp, &inst->asp_list, list) {
			if (asp->cfg.local.port != local_port)
				continue;
			if (asp->cfg.remote.port && asp->cfg.remote.port != remote_port)
				continue;

			if (!ss7_asp_peer_match_host(&asp->cfg.local, hostbuf_l, loc_is_v6))
				continue; /* didn't match any local.host */

			/* If no remote host was set, it's probably a server and hence we match any cli src */
			if (asp->cfg.remote.host_cnt) {
				if (!ss7_asp_peer_match_host(&asp->cfg.remote, hostbuf_r, rem_is_v6))
					continue; /* didn't match any remote.host */
			}

			return asp;
		}
	}

	return NULL;
}

struct osmo_ss7_asp *ss7_asp_alloc(struct osmo_ss7_instance *inst, const char *name,
				   uint16_t remote_port, uint16_t local_port,
				   enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_asp *asp = talloc_zero(inst, struct osmo_ss7_asp);
	asp->ctrg = rate_ctr_group_alloc(asp, &ss7_asp_rcgd, g_ss7_asp_rcg_idx++);
	if (!asp->ctrg) {
		talloc_free(asp);
		return NULL;
	}
	rate_ctr_group_set_name(asp->ctrg, name);
	asp->inst = inst;
	osmo_ss7_asp_peer_init(&asp->cfg.remote);
	asp->cfg.remote.port = remote_port;
	osmo_ss7_asp_peer_init(&asp->cfg.local);
	asp->cfg.local.port = local_port;
	asp->cfg.proto = proto;
	asp->cfg.name = talloc_strdup(asp, name);

	asp->cfg.T_defs_lm = talloc_memdup(asp, ss7_asp_lm_timer_defaults,
					   sizeof(ss7_asp_lm_timer_defaults));
	osmo_tdefs_reset(asp->cfg.T_defs_lm);

	llist_add_tail(&asp->list, &inst->asp_list);

	/* The SUA code internally needs SCCP to work */
	if (proto == OSMO_SS7_ASP_PROT_SUA)
		osmo_ss7_ensure_sccp(inst);
	return asp;
}

void osmo_ss7_asp_destroy(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	LOGPASP(asp, DLSS7, LOGL_INFO, "Destroying ASP\n");

	if (asp->server)
		osmo_stream_srv_destroy(asp->server);
	if (asp->client)
		osmo_stream_cli_destroy(asp->client);
	if (asp->fi)
		osmo_fsm_inst_term(asp->fi, OSMO_FSM_TERM_REQUEST, NULL);
	if (asp->xua_server)
		llist_del(&asp->siblings);

	/* unlink from all ASs we are part of */
	llist_for_each_entry(as, &asp->inst->as_list, list) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
			if (as->cfg.asps[i] == asp)
				as->cfg.asps[i] = NULL;
		}
	}
	/* unlink from ss7_instance */
	asp->inst = NULL;
	llist_del(&asp->list);
	rate_ctr_group_free(asp->ctrg);
	/* release memory */
	talloc_free(asp);
}

static int xua_cli_read_cb(struct osmo_stream_cli *conn);
static int ipa_cli_read_cb(struct osmo_stream_cli *conn);
static int xua_cli_connect_cb(struct osmo_stream_cli *cli);

int osmo_ss7_asp_restart(struct osmo_ss7_asp *asp)
{
	int rc;
	char bufloc[512], bufrem[512];
	uint8_t byte;

	OSMO_ASSERT(ss7_initialized);
	osmo_ss7_asp_peer_snprintf(bufloc, sizeof(bufloc), &asp->cfg.local);
	osmo_ss7_asp_peer_snprintf(bufrem, sizeof(bufrem), &asp->cfg.remote);
	LOGPASP(asp, DLSS7, LOGL_INFO, "Restarting ASP %s, r=%s<->l=%s\n",
	       asp->cfg.name, bufrem, bufloc);

	if (!asp->cfg.is_server) {
		/* We are in client mode now */
		if (asp->server) {
			/* if we previously were in server mode,
			 * destroy it */
			osmo_stream_srv_destroy(asp->server);
			asp->server = NULL;
		}
		if (!asp->client)
			asp->client = osmo_stream_cli_create(asp);
		if (!asp->client) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Unable to create stream"
				" client for ASP %s\n", asp->cfg.name);
			return -1;
		}
		osmo_stream_cli_set_name(asp->client, asp->cfg.name);
		osmo_stream_cli_set_nodelay(asp->client, true);
		osmo_stream_cli_set_addrs(asp->client, (const char **)asp->cfg.remote.host, asp->cfg.remote.host_cnt);
		osmo_stream_cli_set_port(asp->client, asp->cfg.remote.port);
		osmo_stream_cli_set_local_addrs(asp->client, (const char **)asp->cfg.local.host, asp->cfg.local.host_cnt);
		osmo_stream_cli_set_local_port(asp->client, asp->cfg.local.port);
		osmo_stream_cli_set_proto(asp->client, ss7_asp_proto_to_ip_proto(asp->cfg.proto));
		osmo_stream_cli_set_reconnect_timeout(asp->client, 5);
		osmo_stream_cli_set_connect_cb(asp->client, xua_cli_connect_cb);
		if (asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
			osmo_stream_cli_set_read_cb(asp->client, ipa_cli_read_cb);
		else
			osmo_stream_cli_set_read_cb(asp->client, xua_cli_read_cb);
		osmo_stream_cli_set_data(asp->client, asp);
		byte = 1; /*AUTH is needed by ASCONF. enable, don't abort socket creation if AUTH can't be enabled */
		osmo_stream_cli_set_param(asp->client, OSMO_STREAM_CLI_PAR_SCTP_SOCKOPT_AUTH_SUPPORTED, &byte, sizeof(byte));
		byte = 1; /* enable, don't abort socket creation if ASCONF can't be enabled */
		osmo_stream_cli_set_param(asp->client, OSMO_STREAM_CLI_PAR_SCTP_SOCKOPT_ASCONF_SUPPORTED, &byte, sizeof(byte));
		if (asp->cfg.sctp_init.num_ostreams_present)
			osmo_stream_cli_set_param(asp->client, OSMO_STREAM_CLI_PAR_SCTP_INIT_NUM_OSTREAMS,
						  &asp->cfg.sctp_init.num_ostreams_value,
						  sizeof(asp->cfg.sctp_init.num_ostreams_value));
		if (asp->cfg.sctp_init.max_instreams_present)
			osmo_stream_cli_set_param(asp->client, OSMO_STREAM_CLI_PAR_SCTP_INIT_MAX_INSTREAMS,
						  &asp->cfg.sctp_init.max_instreams_value,
						  sizeof(asp->cfg.sctp_init.max_instreams_value));
		if (asp->cfg.sctp_init.max_attempts_present)
			osmo_stream_cli_set_param(asp->client, OSMO_STREAM_CLI_PAR_SCTP_INIT_MAX_ATTEMPTS,
						  &asp->cfg.sctp_init.max_attempts_value,
						  sizeof(asp->cfg.sctp_init.max_attempts_value));
		if (asp->cfg.sctp_init.max_init_timeo_present)
			osmo_stream_cli_set_param(asp->client, OSMO_STREAM_CLI_PAR_SCTP_INIT_TIMEOUT,
						  &asp->cfg.sctp_init.max_init_timeo_value,
						  sizeof(asp->cfg.sctp_init.max_init_timeo_value));
		rc = osmo_stream_cli_open(asp->client);
		if (rc < 0) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Unable to open stream"
				" client for ASP %s, %s ==> %s\n", asp->cfg.name, bufloc, bufrem);
			/* we don't return error in here because osmo_stream_cli_open()
			   will continue to retry (due to timeout being explicitly set with
			   osmo_stream_cli_set_reconnect_timeout() above) to connect so the error is transient */
		}
	} else {
		/* We are in server mode now */
		if (asp->client) {
			/* if we previously were in client mode,
			 * destroy it */
			osmo_stream_cli_destroy(asp->client);
			asp->client = NULL;
		}
		/* FIXME: ensure we have a SCTP server */
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "ASP Restart for server "
			"not implemented yet!\n");
	}

	/* (re)start the ASP FSM */
	if (asp->fi)
		osmo_fsm_inst_term(asp->fi, OSMO_FSM_TERM_REQUEST, NULL);
	asp->fi = xua_asp_fsm_start(asp, asp->cfg.role, LOGL_DEBUG);

	return 0;
}

bool osmo_ss7_asp_active(const struct osmo_ss7_asp *asp)
{
	if (!asp->fi)
		return false;
	return asp->fi->state == XUA_ASP_S_ACTIVE;
}

bool ss7_asp_is_started(const struct osmo_ss7_asp *asp)
{
	if (asp->cfg.is_server)
		return !!asp->server;
	else
		return !!asp->client;
}

/***********************************************************************
 * libosmo-netif integration for SCTP stream server/client
 ***********************************************************************/

static int get_logevel_by_sn_type(int sn_type)
{
	switch (sn_type) {
	case SCTP_ADAPTATION_INDICATION:
	case SCTP_PEER_ADDR_CHANGE:
#ifdef SCTP_AUTHENTICATION_INDICATION
	case SCTP_AUTHENTICATION_INDICATION:
#endif
#ifdef SCTP_SENDER_DRY_EVENT
	case SCTP_SENDER_DRY_EVENT:
#endif
		return LOGL_INFO;
	case SCTP_ASSOC_CHANGE:
		return LOGL_NOTICE;
	case SCTP_SHUTDOWN_EVENT:
	case SCTP_PARTIAL_DELIVERY_EVENT:
		return LOGL_NOTICE;
	case SCTP_SEND_FAILED:
	case SCTP_REMOTE_ERROR:
		return LOGL_ERROR;
	default:
		return LOGL_NOTICE;
	}
}

static void log_sctp_notification(struct osmo_ss7_asp *asp, const char *pfx,
				  union sctp_notification *notif)
{
	int log_level;

	LOGPASP(asp, DLSS7, LOGL_INFO, "%s SCTP NOTIFICATION %u flags=0x%0x\n",
		pfx, notif->sn_header.sn_type,
		notif->sn_header.sn_flags);

	log_level = get_logevel_by_sn_type(notif->sn_header.sn_type);

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		LOGPASP(asp, DLSS7, log_level, "%s SCTP_ASSOC_CHANGE: %s\n",
			pfx, osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		{
		char addr_str[INET6_ADDRSTRLEN + 10];
		struct sockaddr_storage sa = notif->sn_paddr_change.spc_aaddr;
		osmo_sockaddr_to_str_buf(addr_str, sizeof(addr_str), (const struct osmo_sockaddr *)&sa);
		LOGPASP(asp, DLSS7, log_level, "%s SCTP_PEER_ADDR_CHANGE: %s %s err=%s\n",
			pfx, osmo_sctp_paddr_chg_str(notif->sn_paddr_change.spc_state), addr_str,
			(notif->sn_paddr_change.spc_state == SCTP_ADDR_UNREACHABLE) ?
			osmo_sctp_sn_error_str(notif->sn_paddr_change.spc_error) : "None");
		}
		break;
	default:
		LOGPASP(asp, DLSS7, log_level, "%s %s\n",
			pfx, osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		break;
	}
}

/* netif code tells us we can read something from the socket */
int ss7_asp_ipa_srv_conn_cb(struct osmo_stream_srv *conn)
{
	int fd = osmo_stream_srv_get_fd(conn);
	struct osmo_ss7_asp *asp = osmo_stream_srv_get_data(conn);
	struct msgb *msg = NULL;
	int rc;

	OSMO_ASSERT(fd >= 0);

	/* read IPA message from socket and process it */
	rc = ipa_msg_recv_buffered(fd, &msg, &asp->pending_msg);
	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): ipa_msg_recv_buffered() returned %d\n",
		__func__, rc);
	if (rc <= 0) {
		if (rc == -EAGAIN) {
			/* more data needed */
			return 0;
		}
		osmo_stream_srv_destroy(conn);
		return rc;
	}
	if (osmo_ipa_process_msg(msg) < 0) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Bad IPA message\n");
		osmo_stream_srv_destroy(conn);
		msgb_free(msg);
		return -1;
	}
	msg->dst = asp;
	rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_RX_TOTAL);
	/* we can use the 'fd' return value of osmo_stream_srv_get_fd() here unverified as all we do
	 * is 'roll the dice' to obtain a 4-bit SLS value. */
	return ipa_rx_msg(asp, msg, fd & 0xf);
}

/* netif code tells us we can read something from the socket */
int ss7_asp_xua_srv_conn_cb(struct osmo_stream_srv *conn)
{
	struct osmo_ss7_asp *asp = osmo_stream_srv_get_data(conn);
	struct msgb *msg = m3ua_msgb_alloc("xUA Server Rx");
	unsigned int ppid;
	int flags;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read xUA message from socket and process it */
	rc = osmo_stream_srv_recv(conn, msg);
	flags = msgb_sctp_msg_flags(msg);

	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		__func__, rc, flags);

	if (flags & OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		log_sctp_notification(asp, "xUA CLNT", notif);
		asp_handle_sctp_notif_monitor_primary_address(asp, notif);

		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			if (notif->sn_assoc_change.sac_state == SCTP_RESTART)
				xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RESTART,
							     PRIM_OP_INDICATION);
		default:
			break;
		}

		if (rc == 0) {
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
		} else {
			rc = 0;
		}
		goto out;
	}
	if (rc < 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else if (rc == 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	}

	ppid = msgb_sctp_ppid(msg);
	msg->dst = asp;
	rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_RX_TOTAL);

	if (ppid == SUA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA)
		rc = sua_rx_msg(asp, msg);
	else if (ppid == M3UA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA)
		rc = m3ua_rx_msg(asp, msg);
	else
		rc = ss7_asp_rx_unknown(asp, ppid, msg);

out:
	msgb_free(msg);
	return rc;
}

/* client has established SCTP connection to server */
static int xua_cli_connect_cb(struct osmo_stream_cli *cli)
{
	int fd = osmo_stream_cli_get_fd(cli);
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(cli);
	int rc = 0;

	if (fd < 0)
		return fd;

	/* update the socket name */
	talloc_free(asp->sock_name);
	asp->sock_name = osmo_sock_get_name(asp, fd);

	LOGPASP(asp, DLSS7, LOGL_INFO, "Client connected %s\n", asp->sock_name);

	/* Now that we have the conn in place, the local/remote addresses are
	 * fed and the local port is known for sure. Apply SCTP Primary addresses
	 * if needed:
	 */
	if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		rc = ss7_asp_apply_peer_primary_address(asp);
		rc = ss7_asp_apply_primary_address(asp);
	}

	if (asp->lm && asp->lm->prim_cb) {
		/* Notify layer manager that a connection has been
		 * established */
		xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION);
	} else {
		/* directly as the ASP FSM to start by sending an ASP-UP ... */
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
	}

	return rc;
}

static void xua_cli_close(struct osmo_stream_cli *cli)
{
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(cli);

	osmo_stream_cli_close(cli);
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_COMM_DOWN_IND, asp);
	/* send M-SCTP_RELEASE.ind to XUA Layer Manager */
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION);
}

static void xua_cli_close_and_reconnect(struct osmo_stream_cli *cli)
{
	xua_cli_close(cli);
	osmo_stream_cli_reconnect(cli);
}

/* read call-back for IPA/SCCPlite socket */
static int ipa_cli_read_cb(struct osmo_stream_cli *conn)
{
	int fd = osmo_stream_cli_get_fd(conn);
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(conn);
	struct msgb *msg = NULL;
	int rc;

	OSMO_ASSERT(fd >= 0);

	/* read IPA message from socket and process it */
	rc = ipa_msg_recv_buffered(fd, &msg, &asp->pending_msg);
	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): ipa_msg_recv_buffered() returned %d\n",
		__func__, rc);
	if (rc <= 0) {
		if (rc == -EAGAIN) {
			/* more data needed */
			return 0;
		}
		xua_cli_close_and_reconnect(conn);
		return rc;
	}
	if (osmo_ipa_process_msg(msg) < 0) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Bad IPA message\n");
		xua_cli_close_and_reconnect(conn);
		msgb_free(msg);
		return -1;
	}
	msg->dst = asp;
	rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_RX_TOTAL);
	/* we can use the 'fd' return value of osmo_stream_srv_get_fd() here unverified as all we do
	 * is 'roll the dice' to obtain a 4-bit SLS value. */
	return ipa_rx_msg(asp, msg, fd & 0xf);
}

static int xua_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(conn);
	struct msgb *msg = m3ua_msgb_alloc("xUA Client Rx");
	unsigned int ppid;
	int flags;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read xUA message from socket and process it */
	rc = osmo_stream_cli_recv(conn, msg);
	flags = msgb_sctp_msg_flags(msg);

	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		__func__, rc, flags);

	if (flags & OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		log_sctp_notification(asp, "xUA CLNT", notif);
		asp_handle_sctp_notif_monitor_primary_address(asp, notif);

		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			if (notif->sn_assoc_change.sac_state == SCTP_RESTART)
				xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RESTART,
							     PRIM_OP_INDICATION);
		default:
			break;
		}

		if (rc == 0)
			xua_cli_close_and_reconnect(conn);
		rc = 0;
		goto out;
	}
	if (rc < 0) {
		xua_cli_close_and_reconnect(conn);
		goto out;
	} else if (rc == 0) {
		xua_cli_close_and_reconnect(conn);
		goto out;
	}

	ppid = msgb_sctp_ppid(msg);
	msg->dst = asp;
	rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_RX_TOTAL);

	if (ppid == SUA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA)
		rc = sua_rx_msg(asp, msg);
	else if (ppid == M3UA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA)
		rc = m3ua_rx_msg(asp, msg);
	else
		rc = ss7_asp_rx_unknown(asp, ppid, msg);

out:
	msgb_free(msg);
	return rc;
}

int ss7_asp_xua_srv_conn_closed_cb(struct osmo_stream_srv *srv)
{
	struct osmo_ss7_asp *asp = osmo_stream_srv_get_data(srv);

	LOGP(DLSS7, LOGL_INFO, "%s: connection closed\n", asp ? asp->cfg.name : "?");

	if (!asp)
		return 0;

	/* notify ASP FSM and everyone else */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_COMM_DOWN_IND, NULL);

	/* delete any RKM-dynamically allocated ASs for this ASP */
	xua_rkm_cleanup_dyn_as_for_asp(asp);

	/* send M-SCTP_RELEASE.ind to Layer Manager */
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION);

	asp->server = NULL;

	/* if we were dynamically allocated at accept_cb() time, let's
	 * self-destruct now.  A new connection will re-create the ASP. */
	if (asp->dyn_allocated) {
		/* avoid re-entrance via osmo_stream_srv_destroy() which
		 * called us */
		osmo_ss7_asp_destroy(asp);
	}

	return 0;
}

/*! \brief send a fully encoded msgb via a given ASP
 *  \param[in] asp Application Server Process through which to send
 *  \param[in] msg message buffer to transmit. Ownership transferred.
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_asp_send(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	OSMO_ASSERT(ss7_initialized);

	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_SUA:
		msgb_sctp_ppid(msg) = SUA_PPID;
		break;
	case OSMO_SS7_ASP_PROT_M3UA:
		msgb_sctp_ppid(msg) = M3UA_PPID;
		break;
	case OSMO_SS7_ASP_PROT_IPA:
		break;
	default:
		OSMO_ASSERT(0);
	}

	rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_TX_TOTAL);

	if (asp->cfg.is_server) {
		if (!asp->server) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Cannot transmit, no asp->server\n");
			/* FIXME: what to do here? delete the route? send DUNA? */
			msgb_free(msg);
			return -EIO;
		}
		osmo_stream_srv_send(asp->server, msg);
	} else {
		if (!asp->client) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Cannot transmit, no asp->client\n");
			/* FIXME: what to do here? delete the route? send DUNA? */
			msgb_free(msg);
			return -EIO;
		}
		if (!osmo_stream_cli_is_connected(asp->client)) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Cannot transmit, asp->client not connected\n");
			msgb_free(msg);
			return -EIO;
		}
		osmo_stream_cli_send(asp->client, msg);
	}

	return 0;
}

void osmo_ss7_asp_disconnect(struct osmo_ss7_asp *asp)
{
	if (asp->server)
		osmo_stream_srv_destroy(asp->server);
		/* the close_cb() will handle the remaining cleanup here */
	else if (asp->client)
		xua_cli_close_and_reconnect(asp->client);
}

static osmo_ss7_asp_rx_unknown_cb *g_osmo_ss7_asp_rx_unknown_cb;

/*! Register a call-back function for unknown SCTP PPID / IPA Stream ID */
void osmo_ss7_register_rx_unknown_cb(osmo_ss7_asp_rx_unknown_cb *cb)
{
	g_osmo_ss7_asp_rx_unknown_cb = cb;
}

int ss7_asp_rx_unknown(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg)
{
	rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_RX_UNKNOWN);

	if (g_osmo_ss7_asp_rx_unknown_cb)
		return (*g_osmo_ss7_asp_rx_unknown_cb)(asp, ppid_mux, msg);

	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_IPA:
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Rx IPA for unknown Stream ID 0x%02x: %s\n",
			ppid_mux, msgb_hexdump(msg));
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Rx SCTP chunk for unknown PPID %u: %s\n",
			ppid_mux, msgb_hexdump(msg));
		break;
	}
	return 0;
}

/*! Get the logging subsystem for a given ASP. Used by generic code. */
int osmo_ss7_asp_get_log_subsys(const struct osmo_ss7_asp *asp)
{
	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		return DLM3UA;
	case OSMO_SS7_ASP_PROT_SUA:
		return DLSUA;
	default:
		return DLSS7;
	}
}

/*! \brief Get the name of a given ASP
 *  \param[in] asp The ASP for which the name is requested
 *  \returns The name of the ASP, or NULL if not set
 */
const char *osmo_ss7_asp_get_name(const struct osmo_ss7_asp *asp)
{
	return asp->cfg.name;
}

/*! \brief Get the proto of a given ASP
 *  \param[in] asp The ASP for which the proto is requested
 *  \returns The proto of the ASP
 */
enum osmo_ss7_asp_protocol osmo_ss7_asp_get_proto(const struct osmo_ss7_asp *asp)
{
	return asp->cfg.proto;
}

/*! \brief Get the fd of a given ASP
 *  \param[in] asp The ASP for which the fd is requested
 *  \returns The fd of the ASP if acailable, negative otherwise
 */
int ss7_asp_get_fd(const struct osmo_ss7_asp *asp)
{
	if (asp->cfg.is_server) {
		if (asp->server)
			return osmo_stream_srv_get_fd(asp->server);
	} else {
		if (asp->client)
			return osmo_stream_cli_get_fd(asp->client);
	}
	return -1;
}
