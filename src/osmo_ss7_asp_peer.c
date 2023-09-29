/* SS7 ASP Peer (one endpoint of a conn) */

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

#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_internal.h"


/***********************************************************************
 * SS7 Application Server Process peer
 ***********************************************************************/

void osmo_ss7_asp_peer_init(struct osmo_ss7_asp_peer *peer)
{
	memset(peer, 0, sizeof(*peer));
	peer->idx_primary = -1;
}

int osmo_ss7_asp_peer_snprintf(char *buf, size_t buf_len, struct osmo_ss7_asp_peer *peer)
{
	int len = 0, offset = 0, rem = buf_len;
	int ret, i;
	char *after;
	char *primary;

	if (buf_len < 3)
		return -EINVAL;

	if (peer->host_cnt > 1) {
		ret = snprintf(buf, rem, "(");
		if (ret < 0)
			return ret;
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}
	for (i = 0; i < peer->host_cnt; i++) {
		primary = (peer->idx_primary == i) ? "*" : "";
		if (peer->host_cnt == 1)
			after = "";
		else
			after = (i == (peer->host_cnt - 1)) ? ")" : "|";
		ret = snprintf(buf + offset, rem, "%s%s%s", peer->host[i] ? : "0.0.0.0", primary, after);
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}
	ret = snprintf(buf + offset, rem, ":%u", peer->port);
	if (ret < 0)
		return ret;
	OSMO_SNPRINTF_RET(ret, rem, offset, len);

	return len;
}

/*! \brief Set (copy) addresses for a given ASP peer. Previous addresses are freed.
 *  \param[in] peer Application Server Process peer whose addresses are to be set.
 *  \param[in] talloc_ctx talloc context used to allocate new addresses.
 *  \param[in] hosts Array of strings containing IP addresses.
 *  \param[in] host_cnt Number of strings in hosts
 *  \param[in] idx_primary Index in "hosts" array marking the SCTP Primary Address, -1 if no explicit Primary Address set
 *  \returns 0 on success; negative otherwise */
int osmo_ss7_asp_peer_set_hosts2(struct osmo_ss7_asp_peer *peer, void *talloc_ctx, const char *const*hosts, size_t host_cnt, int idx_primary)
{
	int i = 0;

	if (idx_primary >= (int)host_cnt || idx_primary < -1)
		return -EINVAL;

	if (host_cnt > ARRAY_SIZE(peer->host))
		return -EINVAL;

	for (; i < host_cnt; i++)
		osmo_talloc_replace_string(talloc_ctx, &peer->host[i], hosts[i]);
	for (; i < peer->host_cnt; i++) {
		talloc_free(peer->host[i]);
		peer->host[i] = NULL;
	}

	peer->host_cnt = host_cnt;
	peer->idx_primary = idx_primary;
	return 0;
}

/*! \brief Set (copy) addresses for a given ASP peer. Previous addresses are freed.
 *  \param[in] peer Application Server Process peer whose addresses are to be set.
 *  \param[in] talloc_ctx talloc context used to allocate new addresses.
 *  \param[in] hosts Array of strings containing IP addresses.
 *  \param[in] host_cnt Number of strings in hosts
 *  \returns 0 on success; negative otherwise */
int osmo_ss7_asp_peer_set_hosts(struct osmo_ss7_asp_peer *peer, void *talloc_ctx, const char *const*hosts, size_t host_cnt)
{
	return osmo_ss7_asp_peer_set_hosts2(peer, talloc_ctx, hosts, host_cnt, -1);
}

/* Is string formatted IPv4/v6 addr considered IN(6)ADDR_ANY? */
static inline bool host_is_ip_anyaddr(const char *host, bool is_v6)
{
	/* NULL addr is resolved as 0.0.0.0 (IPv4) by getaddrinfo(), most
	 * probably for backward-compatibility reasons.
	 */
	return is_v6 ? (host && !strcmp(host, "::"))
		     : (!host || !strcmp(host, "0.0.0.0"));
}

/*! \brief Append (copy) address to a given ASP peer. Previous addresses are kept.
 *  \param[in] peer Application Server Process peer the address is appended to.
 *  \param[in] talloc_ctx talloc context used to allocate new address.
 *  \param[in] host string containing an IP address.
 *  \param[in] is_primary_addr whether this IP address is to be added as SCTP Primary Address
 *  \returns 0 on success; negative otherwise */
int osmo_ss7_asp_peer_add_host2(struct osmo_ss7_asp_peer *peer, void *talloc_ctx,
			       const char *host, bool is_primary_addr)
{
	int i;
	bool new_is_v6 = osmo_ip_str_type(host) == AF_INET6;
	bool new_is_any = host_is_ip_anyaddr(host, new_is_v6);
	struct osmo_sockaddr_str addr_str;

	if (osmo_sockaddr_str_from_str(&addr_str, host, 0) < 0)
		return -EINVAL;

	if (new_is_any) {
		/* Makes no sense to have INET(6)_ANY many times, or INET(6)_ANY
		 * together with specific addresses, be it of same or different
		 * IP version: */
		if (peer->host_cnt != 0)
			return -EINVAL;

		/* Makes no sense to have INET(6)_ANY as primary: */
		if (is_primary_addr)
			return -EINVAL;

		if (peer->host_cnt >= ARRAY_SIZE(peer->host))
			return -EINVAL;
		osmo_talloc_replace_string(talloc_ctx, &peer->host[peer->host_cnt], host);
		peer->host_cnt++;
		return 0;
	}

	/* Makes no sense to add specific address to set if INET(6)_ANY
	 * is already set, be it from same or different IP version: */
	for (i = 0; i < peer->host_cnt; i++) {
		bool iter_is_v6 = osmo_ip_str_type(peer->host[i]) == AF_INET6;
		if (host_is_ip_anyaddr(peer->host[i], iter_is_v6))
			return -EINVAL;
	}
	/* Reached this point, no INET(6)_ANY address is set nor we are adding an INET(6)_ANY address. */

	/* Check if address already exists, and then if primary flags need to be changed: */
	for (i = 0; i < peer->host_cnt; i++) {
		struct osmo_sockaddr_str it_addr_str;
		bool it_is_primary;
		osmo_sockaddr_str_from_str(&it_addr_str, peer->host[i], 0);

		if (osmo_sockaddr_str_cmp(&addr_str, &it_addr_str) != 0)
			continue;
		it_is_primary = (peer->idx_primary == i);
		if (is_primary_addr == it_is_primary) {
			/* Nothing to do, return below */
		} else if (is_primary_addr && !it_is_primary) {
			/* Mark it as primary: */
			peer->idx_primary = i;
		} else { /* if (!is_primary_addr && it_is_primary) { */
			/* mark it as non-primary: */
			peer->idx_primary = -1;
		}
		return 0;
	}

	if (peer->host_cnt >= ARRAY_SIZE(peer->host))
		return -EINVAL;

	osmo_talloc_replace_string(talloc_ctx, &peer->host[peer->host_cnt], host);
	if (is_primary_addr)
		peer->idx_primary = peer->host_cnt;
	peer->host_cnt++;
	return 0;
}

/*! \brief Append (copy) address to a given ASP peer. Previous addresses are kept.
 *  \param[in] peer Application Server Process peer the address is appended to.
 *  \param[in] talloc_ctx talloc context used to allocate new address.
 *  \param[in] host string containing an IP address.
 *  \returns 0 on success; negative otherwise */
int osmo_ss7_asp_peer_add_host(struct osmo_ss7_asp_peer *peer, void *talloc_ctx,
			       const char *host)
{
	return osmo_ss7_asp_peer_add_host2(peer, talloc_ctx, host, false);
}

bool ss7_asp_peer_match_host(const struct osmo_ss7_asp_peer *peer, const char *host, bool host_is_v6)
{
	unsigned int i;
	for (i = 0; i < peer->host_cnt; i++) {
		bool iter_is_v6 = osmo_ip_str_type(peer->host[i]) == AF_INET6;
		bool iter_is_anyaddr = host_is_ip_anyaddr(peer->host[i], iter_is_v6);
		/* "::" (v6) covers "0.0.0.0" (v4), but not otherwise */
		if ((iter_is_v6 != host_is_v6) && !(iter_is_v6 && iter_is_anyaddr))
			continue;
		if (iter_is_anyaddr || !strcmp(peer->host[i], host))
			return true;
	}
	return false;
}
