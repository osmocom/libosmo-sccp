/* Core SS7 Instance/Linkset/Link/AS/ASP VTY Interface */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "xua_internal.h"
#include "sccp_internal.h"

static void show_user(struct vty *vty, struct osmo_sccp_user *user)
{
	struct osmo_sccp_instance *sccp = user->inst;

	if (osmo_ss7_pc_is_valid(user->pc))
		vty_out(vty, "SSN %3u %7s : %s%s", user->ssn,
			osmo_ss7_pointcode_print(sccp->ss7, user->pc),
			user->name, VTY_NEWLINE);
	else
		vty_out(vty, "SSN %3u ANY     : %s%s", user->ssn, user->name, VTY_NEWLINE);
}

DEFUN(show_sccp_users, show_sccp_users_cmd,
	"show cs7 instance <0-15> sccp users",
	SHOW_STR CS7_STR INST_STR INST_STR SCCP_STR
	"Show List of SCCP Users registered\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *scu;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	sccp = inst->sccp;
	if (!sccp) {
		vty_out(vty, "SS7 instance %d has no SCCP%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	};

	llist_for_each_entry(scu, &sccp->users, list)
		show_user(vty, scu);

	return CMD_SUCCESS;
}

DEFUN(show_sccp_user_ssn, show_sccp_user_ssn_cmd,
	"show cs7 instance <0-15> sccp ssn <0-65535>",
	SHOW_STR CS7_STR INST_STR INST_STR SCCP_STR
	"Show List of SCCP Users registered\n")
{
	int id = atoi(argv[0]);
	int ssn = atoi(argv[1]);
	struct osmo_ss7_instance *inst;
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *scu;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	sccp = inst->sccp;
	if (!sccp) {
		vty_out(vty, "SS7 instance %d has no SCCP%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	};

	scu = sccp_user_find(sccp, ssn, 0);
	if (!scu) {
		vty_out(vty, "Can't find SCCP User in instance %d%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	show_user(vty, scu);

	return CMD_SUCCESS;
}

DEFUN(show_sccp_connections, show_sccp_connections_cmd,
	"show cs7 instance <0-15> sccp connections",
	SHOW_STR CS7_STR INST_STR INST_STR SCCP_STR
	"Show List of SCCP Users registered\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;
	struct osmo_sccp_instance *sccp;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	sccp = inst->sccp;
	if (!sccp) {
		vty_out(vty, "SS7 instance %d has no SCCP%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	};

	sccp_scoc_show_connections(vty, sccp);

	return CMD_SUCCESS;
}

void osmo_sccp_vty_init(void)
{
	install_element_ve(&show_sccp_users_cmd);
	install_element_ve(&show_sccp_user_ssn_cmd);
	install_element_ve(&show_sccp_connections_cmd);
}
