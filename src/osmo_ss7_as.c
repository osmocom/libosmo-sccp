/* Core SS7 AS Handling */

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

#include <osmocom/sigtran/osmo_ss7.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include "ss7_internal.h"
#include "xua_as_fsm.h"
#include "xua_asp_fsm.h"

/***********************************************************************
 * SS7 Application Server
 ***********************************************************************/

struct value_string osmo_ss7_as_traffic_mode_vals[] = {
	{ OSMO_SS7_AS_TMOD_BCAST,	"broadcast" },
	{ OSMO_SS7_AS_TMOD_LOADSHARE,	"loadshare" },
	{ OSMO_SS7_AS_TMOD_ROUNDROBIN,	"round-robin" },
	{ OSMO_SS7_AS_TMOD_OVERRIDE,	"override" },
	{ 0, NULL }
};

static const struct rate_ctr_desc ss7_as_rcd[] = {
	[SS7_AS_CTR_RX_MSU_TOTAL] = { "rx:msu:total", "Total number of MSU received" },
	[SS7_AS_CTR_TX_MSU_TOTAL] = { "tx:msu:total", "Total number of MSU transmitted" },
};

static const struct rate_ctr_group_desc ss7_as_rcgd = {
	.group_name_prefix = "sigtran_as",
	.group_description = "SIGTRAN Application Server",
	.num_ctr = ARRAY_SIZE(ss7_as_rcd),
	.ctr_desc = ss7_as_rcd,
};
static unsigned int g_ss7_as_rcg_idx;

/*! \brief Allocate an Application Server
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of Application Server
 *  \param[in] proto Protocol of Application Server
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *ss7_as_alloc(struct osmo_ss7_instance *inst, const char *name,
				 enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;

	as = talloc_zero(inst, struct osmo_ss7_as);
	if (!as)
		return NULL;
	as->ctrg = rate_ctr_group_alloc(as, &ss7_as_rcgd, g_ss7_as_rcg_idx++);
	if (!as->ctrg) {
		talloc_free(as);
		return NULL;
	}
	rate_ctr_group_set_name(as->ctrg, name);
	as->inst = inst;
	as->cfg.name = talloc_strdup(as, name);
	as->cfg.proto = proto;
	as->cfg.mode = OSMO_SS7_AS_TMOD_OVERRIDE;
	as->cfg.recovery_timeout_msec = 2000;
	as->cfg.routing_key.l_rk_id = ss7_find_free_l_rk_id(inst);
	as->fi = xua_as_fsm_start(as, LOGL_DEBUG);
	llist_add_tail(&as->list, &inst->as_list);

	return as;
}

/*! \brief Add given ASP to given AS
 *  \param[in] as Application Server to which \ref asp is added
 *  \param[in] asp Application Server Process to be added to \ref as
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_as_add_asp(struct osmo_ss7_as *as, const char *asp_name)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(as->inst, asp_name);
	if (!asp)
		return -ENODEV;

	LOGPAS(as, DLSS7, LOGL_INFO, "Adding ASP %s to AS\n", asp->cfg.name);

	if (osmo_ss7_as_has_asp(as, asp))
		return 0;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (!as->cfg.asps[i]) {
			as->cfg.asps[i] = asp;
			osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_AS_ASSIGNED, as);
			return 0;
		}
	}

	return -ENOSPC;
}

/*! \brief Delete given ASP from given AS
 *  \param[in] as Application Server from which \ref asp is deleted
 *  \param[in] asp Application Server Process to delete from \ref as
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_as_del_asp(struct osmo_ss7_as *as, const char *asp_name)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(as->inst, asp_name);
	if (!asp)
		return -ENODEV;

	LOGPAS(as, DLSS7, LOGL_INFO, "Removing ASP %s from AS\n", asp->cfg.name);

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] == asp) {
			as->cfg.asps[i] = NULL;
			return 0;
		}
	}

	return -EINVAL;
}

/*! \brief Destroy given Application Server
 *  \param[in] as Application Server to destroy */
void osmo_ss7_as_destroy(struct osmo_ss7_as *as)
{
	struct osmo_ss7_route *rt, *rt2;

	OSMO_ASSERT(ss7_initialized);
	LOGPAS(as, DLSS7, LOGL_INFO, "Destroying AS\n");

	if (as->fi)
		osmo_fsm_inst_term(as->fi, OSMO_FSM_TERM_REQUEST, NULL);

	/* find any routes pointing to this AS and remove them */
	llist_for_each_entry_safe(rt, rt2, &as->inst->rtable_system->routes, list) {
		if (rt->dest.as == as)
			osmo_ss7_route_destroy(rt);
	}

	as->inst = NULL;
	llist_del(&as->list);
	rate_ctr_group_free(as->ctrg);
	talloc_free(as);
}

/*! \brief Determine if given AS contains ASP
 *  \param[in] as Application Server in which to look for \ref asp
 *  \param[in] asp Application Server Process to look for in \ref as
 *  \returns true in case \ref asp is part of \ref as; false otherwise */
bool osmo_ss7_as_has_asp(const struct osmo_ss7_as *as,
			 const struct osmo_ss7_asp *asp)
{
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] == asp)
			return true;
	}
	return false;
}

/*! Determine if given AS is in the active state.
 *  \param[in] as Application Server.
 *  \returns true in case as is active; false otherwise. */
bool osmo_ss7_as_active(const struct osmo_ss7_as *as)
{
	if (!as->fi)
		return false;
	return as->fi->state == XUA_AS_S_ACTIVE;
}

/*! Determine if given AS is in the down state.
 *  \param[in] as Application Server.
 *  \returns true in case as is down; false otherwise. */
bool osmo_ss7_as_down(const struct osmo_ss7_as *as)
{
	OSMO_ASSERT(as);

	if (!as->fi)
		return true;
	return as->fi->state == XUA_AS_S_DOWN;
}
