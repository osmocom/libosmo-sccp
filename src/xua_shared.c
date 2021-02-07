/* Shared code between M3UA and SUA implementation */

/* (C) 2015-2021 by Harald Welte <laforge@gnumonks.org>
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
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>

#include "xua_internal.h"

/* if given ASP only has one AS, return that AS */
static struct osmo_ss7_as *find_single_as_for_asp(const struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as, *as_found = NULL;

	llist_for_each_entry(as, &asp->inst->as_list, list) {
		if (!osmo_ss7_as_has_asp(as, asp))
			continue;
		/* check if we already had found another AS within this ASP -> not unique */
		if (as_found)
			return NULL;
		as_found = as;
	}

	return as_found;
}

/* this is why we can use the M3UA constants below in a function shared between M3UA + SUA */
osmo_static_assert(M3UA_ERR_INVAL_ROUT_CTX == SUA_ERR_INVAL_ROUT_CTX, _err_rctx);
osmo_static_assert(M3UA_ERR_NO_CONFGD_AS_FOR_ASP == SUA_ERR_NO_CONFGD_AS_FOR_ASP, _err_as_for_asp);

/*! Find the AS for given ASP + optional routing context IE.
 *  if rctx_ie == NULL, we assume that this ASP is only part of a single AS;
 *  if rctx_ie is given, then we look-up the ASP based on the routing context,
 *  and verify that this ASP is part of it.
 *  \param[out] as caller-provided address-of-pointer to store the found AS
 *  \param[in] asp ASP for which we want to look-up the AS
 *  \param[in] rctx_ie routing context IE (may be NULL) to use for look-up
 *  \returns 0 in case of success; {M3UA,SUA}_ERR_* code in case of error. */
int xua_find_as_for_asp(struct osmo_ss7_as **as, const struct osmo_ss7_asp *asp,
			const struct xua_msg_part *rctx_ie)
{
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);
	*as = NULL;

	if (rctx_ie) {
		uint32_t rctx = xua_msg_part_get_u32(rctx_ie);
		/* Use routing context IE to look up the AS for which the
		 * message was received. */
		*as = osmo_ss7_as_find_by_rctx(asp->inst, rctx);
		if (!*as) {
			LOGPASP(asp, log_ss, LOGL_ERROR, "%s(): invalid routing context: %u\n",
				__func__, rctx);
			return M3UA_ERR_INVAL_ROUT_CTX;
		}

		/* Verify that this ASP is part of the AS. */
		if (!osmo_ss7_as_has_asp(*as, asp)) {
			LOGPASP(asp, log_ss, LOGL_ERROR,
				"%s(): This Application Server Process is not part of the AS %s "
				"resolved by routing context %u\n", __func__, (*as)->cfg.name, rctx);
			return M3UA_ERR_NO_CONFGD_AS_FOR_ASP;
		}
	} else {
		/* no explicit routing context; this only works if there is only one AS in the ASP */
		*as = find_single_as_for_asp(asp);
		if (!*as) {
			LOGPASP(asp, log_ss, LOGL_ERROR,
				"%s(): ASP sent M3UA without Routing Context IE but unable to uniquely "
				"identify the AS for this message\n", __func__);
			return M3UA_ERR_INVAL_ROUT_CTX;
		}
	}

	return 0;
}
