/* SCCP Local Broadcast (LBCS) according to ITU-T Q.713/Q.714 */

/* (C) 2021 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sccp/sccp_types.h>

#include "xua_internal.h"
#include "sccp_internal.h"

/* perform a "local broadcast" of a N-PCSTATE.ind */
void sccp_lbcs_local_bcast_pcstate(struct osmo_sccp_instance *inst,
				   const struct osmo_scu_pcstate_param *pcstate)
{
	struct osmo_sccp_user *scu;

	llist_for_each_entry(scu, &inst->users, list) {
		struct msgb *upmsg = sccp_msgb_alloc(__func__);
		struct osmo_scu_prim *prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
		osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_PCSTATE,
				PRIM_OP_INDICATION, upmsg);
		prim->u.pcstate = *pcstate;
		sccp_user_prim_up(scu, prim);
	}
}

/* perform a "local broadcast" of a N-STATE.ind */
void sccp_lbcs_local_bcast_state(struct osmo_sccp_instance *inst,
				 const struct osmo_scu_state_param *state)
{
	struct osmo_sccp_user *scu;

	llist_for_each_entry(scu, &inst->users, list) {
		struct msgb *upmsg = sccp_msgb_alloc(__func__);
		struct osmo_scu_prim *prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
		osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_STATE,
				PRIM_OP_INDICATION, upmsg);
		prim->u.state = *state;
		sccp_user_prim_up(scu, prim);
	}
}
