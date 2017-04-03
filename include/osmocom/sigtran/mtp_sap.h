#pragma once

/* MTP User SAP description in accordance with ITU Q.701 */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
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
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/sigtran_sap.h>

enum osmo_mtp_prim_type {
	OSMO_MTP_PRIM_TRANSFER,
	OSMO_MTP_PRIM_PAUSE,
	OSMO_MTP_PRIM_RESUME,
	OSMO_MTP_PRIM_STATUS,
};

#define MTP_SIO(service, net_ind)	(((net_ind & 0xF) << 4) | (service & 0xF))

struct osmo_mtp_transfer_param {
	uint32_t opc;
	uint32_t dpc;
	uint8_t sls;
	uint8_t sio;
};

struct osmo_mtp_pause_param {
	uint32_t affected_dpc;
};

struct osmo_mtp_resume_param {
	uint32_t affected_dpc;
};

struct osmo_mtp_status_param {
	uint32_t affected_dpc;
	uint32_t cause;
};

struct osmo_mtp_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_mtp_transfer_param transfer;
		struct osmo_mtp_pause_param pause;
		struct osmo_mtp_resume_param resume;
		struct osmo_mtp_status_param status;
	} u;
};

#define msgb_mtp_prim(msg) ((struct osmo_mtp_prim *)(msg)->l1h)

char *osmo_mtp_prim_name(struct osmo_prim_hdr *oph);
