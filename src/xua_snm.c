/* M3UA/SUA [S]SNM Handling */

/* (C) 2021 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>

#include "xua_internal.h"

/* we can share this code between M3UA and SUA as the below conditions are true */
osmo_static_assert(M3UA_SNM_DUNA == SUA_SNM_DUNA, _sa_duna);
osmo_static_assert(M3UA_SNM_DAVA == SUA_SNM_DAVA, _sa_dava);
osmo_static_assert(M3UA_SNM_DAUD == SUA_SNM_DAUD, _sa_dava);
osmo_static_assert(M3UA_IEI_AFFECTED_PC == SUA_IEI_AFFECTED_PC, _sa_aff_pc);
osmo_static_assert(M3UA_IEI_ROUTE_CTX == SUA_IEI_ROUTE_CTX, _sa_rctx);
osmo_static_assert(M3UA_IEI_INFO_STRING == SUA_IEI_INFO_STRING, _sa_inf_str);

static const char *format_affected_pcs_c(void *ctx, const struct osmo_ss7_instance *s7i,
					 const struct xua_msg_part *ie_aff_pc)
{
	const uint32_t *aff_pc = (const uint32_t *) ie_aff_pc->dat;
	unsigned int num_aff_pc = ie_aff_pc->len / sizeof(uint32_t);
	char *out = talloc_strdup(ctx, "");
	int i;

	for (i = 0; i < num_aff_pc; i++) {
		uint32_t _aff_pc = ntohl(aff_pc[i]);
		uint32_t pc = _aff_pc & 0xffffff;
		uint8_t mask = _aff_pc >> 24;

		/* append point code + mask */
		out = talloc_asprintf_append(out, "%s%s/%u, ", i == 0 ? "" : ", ",
					     osmo_ss7_pointcode_print(s7i, pc), mask);
	}
	return out;
}

/* obtain all routing contexts (in network byte order) that exist within the given ASP */
static unsigned int get_all_rctx_for_asp(uint32_t *rctx, unsigned int rctx_size,
					 struct osmo_ss7_asp *asp, struct osmo_ss7_as *excl_as)
{
	unsigned int count = 0;
	struct osmo_ss7_as *as;

	llist_for_each_entry(as, &asp->inst->as_list, list) {
		if (as == excl_as)
			continue;
		if (!osmo_ss7_as_has_asp(as, asp))
			continue;
		if (as->cfg.routing_key.context == 0)
			continue;
		if (count >= rctx_size)
			break;
		rctx[count] = htonl(as->cfg.routing_key.context);
		count++;
	}
	return count;
}

static void xua_tx_snm_available(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
				 const uint32_t *aff_pc, unsigned int num_aff_pc,
				 const char *info_str, bool available)
{
	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		m3ua_tx_snm_available(asp, rctx, num_rctx, aff_pc, num_aff_pc, info_str, available);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		sua_tx_snm_available(asp, rctx, num_rctx, aff_pc, num_aff_pc, NULL, NULL, info_str, available);
		break;
	default:
		break;
	}
}

/* advertise availability of point codes (with masks) */
void xua_snm_pc_available(struct osmo_ss7_as *as, const uint32_t *aff_pc,
			  unsigned int num_aff_pc, const char *info_str, bool available)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_asp *asp;
	uint32_t rctx[32];
	unsigned int num_rctx;

	llist_for_each_entry(asp, &s7i->asp_list, list) {
		/* SSNM is only permitted for ASPs in ACTIVE state */
		if (!osmo_ss7_asp_active(asp))
			continue;

		/* only send DAVA/DUNA if we locally are the SG and the remote is ASP */
		if (asp->cfg.role != OSMO_SS7_ASP_ROLE_SG)
			continue;

		num_rctx = get_all_rctx_for_asp(rctx, ARRAY_SIZE(rctx), asp, as);
		/* this can happen if the given ASP is only in the AS that reports the change,
		 * which shall be excluded */
		if (num_rctx == 0)
			continue;
		xua_tx_snm_available(asp, rctx, num_rctx, aff_pc, num_aff_pc, info_str, available);
	}
}

/* receive DAUD from ASP; pc is 'affected PC' IE with mask in network byte order! */
void xua_snm_rx_daud(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	struct osmo_ss7_instance *s7i = asp->inst;
	unsigned int num_aff_pc;
	unsigned int num_rctx;
	const uint32_t *aff_pc;
	uint32_t rctx[32];
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);
	int i;

	OSMO_ASSERT(ie_aff_pc);
	aff_pc = (const uint32_t *) ie_aff_pc->dat;
	num_aff_pc = ie_aff_pc->len / sizeof(uint32_t);

	num_rctx = get_all_rctx_for_asp(rctx, ARRAY_SIZE(rctx), asp, NULL);

	LOGPASP(asp, log_ss, LOGL_INFO, "Rx DAUD(%s) for %s\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc));

	/* iterate over list of point codes, generate DAVA/DUPU */
	for (i = 0; i < num_aff_pc; i++) {
		uint32_t _aff_pc = ntohl(aff_pc[i]);
		uint32_t pc = _aff_pc & 0xffffff;
		uint8_t mask = _aff_pc >> 24;
		bool is_available = false;

		if (mask == 0) {
			/* one single point code */

			/* FIXME: don't just check for a route; but also check if the route is "active" */
			if (osmo_ss7_route_lookup(s7i, pc))
				is_available = true;

			xua_tx_snm_available(asp, rctx, num_rctx, &aff_pc[i], 1, "Response to DAUD",
					     is_available);
		} else {
			/* TODO: wildcard match */
			LOGPASP(asp, log_ss, LOGL_NOTICE, "DAUD with wildcard match not supported yet\n");
		}
	}
}

/* an incoming xUA DUNA was received from a remote SG */
void xua_snm_rx_duna(struct osmo_ss7_asp *asp, struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	/* TODO: should our processing depend on the RCTX included? I somehow don't think so */
	//struct xua_msg_part *ie_rctx = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);

	OSMO_ASSERT(ie_aff_pc);

	if (asp->cfg.role != OSMO_SS7_ASP_ROLE_ASP)
		return;

	LOGPASP(asp, log_ss, LOGL_NOTICE, "Rx DUNA(%s) for %s\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc));

	xua_snm_pc_available(as, (const uint32_t *)ie_aff_pc->dat, ie_aff_pc->len/4, info_str, false);
}

/* an incoming xUA DAVA was received from a remote SG */
void xua_snm_rx_dava(struct osmo_ss7_asp *asp, struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	/* TODO: should our processing depend on the RCTX included? I somehow don't think so */
	//struct xua_msg_part *ie_rctx = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);

	OSMO_ASSERT(ie_aff_pc);

	if (asp->cfg.role != OSMO_SS7_ASP_ROLE_ASP)
		return;

	LOGPASP(asp, log_ss, LOGL_NOTICE, "Rx DAVA(%s) for %s\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc));

	xua_snm_pc_available(as, (const uint32_t *)ie_aff_pc->dat, ie_aff_pc->len/4, info_str, true);
}
