/* SCCP Management (SCMG) according to ITU-T Q.713/Q.714 */

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

/*! brief MTP -> SNM (MTP-PAUSE.ind) - inability to providing MTP service Q.714 5.2.2 */
void sccp_scmg_rx_mtp_pause(struct osmo_sccp_instance *inst, uint32_t dpc)
{
	struct osmo_scu_pcstate_param pcstate;
	/* 1) Informs the translation function to update the translation tables. */
	/* 2) SCCP management marks as "prohibited" the status of the remote signalling point, the
	   remote SCCP and each subsystem at the remote signalling point. */
	/* 3) Discontinues all subsystem status tests (including SSN = 1) */

	/* 4) local broadcast of "user-out-of-service" for each SSN at that dest
	 * [this would require us to track SSNs at each PC, which we don't] */

	/* 5) local broadcast of "signaling point inaccessible" */
	/* 6) local broadcast of "remote SCCP unavailable" */
	pcstate = (struct osmo_scu_pcstate_param) {
		.affected_pc = dpc,
		.restricted_importance_level = 0,
		.sp_status = OSMO_SCCP_SP_S_INACCESSIBLE,
		.remote_sccp_status = OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN,
	};
	sccp_lbcs_local_bcast_pcstate(inst, &pcstate);
}

/*! brief MTP -> SNM (MTP-RESUME.ind) - ability of providing the MTP service Q.714 5.2.3 */
void sccp_scmg_rx_mtp_resume(struct osmo_sccp_instance *inst, uint32_t dpc)
{
	struct osmo_scu_pcstate_param pcstate;
	/* 1) Sets the congestion state of that signalling point */
	/* 2) Instructs the translation function to update the translation tables. */
	/* 3) Marks as "allowed" the status of that destination, and the SCCP */
	/* 4) - not applicable */
	/* 5) Marks as "allowed" the status of remote subsystems */

	/* 6) local broadcast of "signalling point accessible" */
	/* 7) local broadcast of "remote SCCP accessible" */
	pcstate = (struct osmo_scu_pcstate_param) {
		.affected_pc = dpc,
		.restricted_importance_level = 0,
		.sp_status = OSMO_SCCP_SP_S_ACCESSIBLE,
		.remote_sccp_status = OSMO_SCCP_REM_SCCP_S_AVAILABLE,
	};
	sccp_lbcs_local_bcast_pcstate(inst, &pcstate);

	/* 8) local broadcast of "user-in-service"
	 * [this would require us to track SSNs at each PC, which we don't] */
}
