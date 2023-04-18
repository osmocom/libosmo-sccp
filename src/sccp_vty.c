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

#include <osmocom/sccp/sccp_types.h>

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
	"Find an SCCP User registered for the given SSN\n"
	"Subsystem Number (SSN)\n")
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
	"Show List of active SCCP connections\n")
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

/* sccp-timer <name> <1-999999>
 * (cmdstr and doc are dynamically generated from osmo_sccp_timer_names.) */
DEFUN_ATTR(sccp_timer, sccp_timer_cmd,
	   NULL, NULL, CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *ss7 = vty->index;
	enum osmo_sccp_timer timer = get_string_value(osmo_sccp_timer_names, argv[0]);
	struct osmo_sccp_timer_val set_val = { .s = atoi(argv[1]) };

	if (timer < 0 || timer >= OSMO_SCCP_TIMERS_COUNT) {
		vty_out(vty, "%% Invalid timer: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_ss7_ensure_sccp(ss7);
	if (!ss7->sccp) {
		vty_out(vty, "%% Error: cannot instantiate SCCP instance%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ss7->sccp->timers[timer] = set_val;
	return CMD_SUCCESS;
}

DEFUN_ATTR(sccp_max_optional_data, sccp_max_optional_data_cmd,
	   "sccp max-optional-data (<0-999999>|standard)",
	   "Configure SCCP behavior\n"
	   "Adjust the upper bound for the optional data length (the payload) for CR, CC, CREF and RLSD messages."
	   " For any Optional Data part larger than this value in octets, send CR, CC, CREF and RLSD"
	   " messages without any payload, and send the data payload in a separate Data Form 1 message."
	   " ITU-T Q.713 sections 4.2 thru 4.5 define a limit of 130 bytes for the 'Data' parameter. This limit can be"
	   " adjusted here. May be useful for interop with nonstandard SCCP peers.\n"
	   "Set a non-standard maximum allowed number of bytes\n"
	   "Use the ITU-T Q.713 4.2 to 4.5 standard value of 130\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *ss7 = vty->index;
	int val;

	if (!strcmp(argv[0], "standard"))
		val = SCCP_MAX_OPTIONAL_DATA;
	else
		val = atoi(argv[0]);

	osmo_ss7_ensure_sccp(ss7);
	if (!ss7->sccp) {
		vty_out(vty, "%% Error: cannot instantiate SCCP instance%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ss7->sccp->max_optional_data = val;
	return CMD_SUCCESS;
}

static const char *osmo_sccp_timer_val_name(const struct osmo_sccp_timer_val *val)
{
	static char buf[16];

	snprintf(buf, sizeof(buf), "%u", val->s);
	return buf;
}

static void gen_sccp_timer_cmd_strs(struct cmd_element *cmd)
{
	int i;
	char *cmd_str = NULL;
	char *doc_str = NULL;

	OSMO_ASSERT(cmd->string == NULL);
	OSMO_ASSERT(cmd->doc == NULL);

	osmo_talloc_asprintf(tall_vty_ctx, cmd_str, "sccp-timer (");
	osmo_talloc_asprintf(tall_vty_ctx, doc_str,
			     "Configure SCCP timer values, see ITU-T Q.714\n");

	for (i = 0; osmo_sccp_timer_names[i].str; i++) {
		const struct osmo_sccp_timer_val *def;
		enum osmo_sccp_timer timer;

		timer = osmo_sccp_timer_names[i].value;
		def = &osmo_sccp_timer_defaults[timer];
		OSMO_ASSERT(timer >= 0 && timer < OSMO_SCCP_TIMERS_COUNT);

		osmo_talloc_asprintf(tall_vty_ctx, cmd_str, "%s%s",
				     i ? "|" : "",
				     osmo_sccp_timer_name(timer));
		osmo_talloc_asprintf(tall_vty_ctx, doc_str, "%s (default: %s)\n",
				     osmo_sccp_timer_description(timer),
				     osmo_sccp_timer_val_name(def));
	}

	osmo_talloc_asprintf(tall_vty_ctx, cmd_str, ") <1-999999>");
	osmo_talloc_asprintf(tall_vty_ctx, doc_str,
			     "Timer value, in seconds\n");

	cmd->string = cmd_str;
	cmd->doc = doc_str;
}

static void write_sccp_timers(struct vty *vty, const char *indent,
			      struct osmo_sccp_instance *inst, bool default_if_unset)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(inst->timers); i++) {
		const struct osmo_sccp_timer_val *val = osmo_sccp_timer_get(inst, i, default_if_unset);
		if (!val)
			continue;
		vty_out(vty, "%ssccp-timer %s %s%s", indent, osmo_sccp_timer_name(i),
			osmo_sccp_timer_val_name(val), VTY_NEWLINE);
	}
}

void osmo_sccp_vty_write_cs7_node(struct vty *vty, const char *indent, struct osmo_sccp_instance *inst)
{
	write_sccp_timers(vty, indent, inst, false);
	if (inst->max_optional_data != SCCP_MAX_OPTIONAL_DATA)
		vty_out(vty, "%ssccp max-optional-data %u%s", indent, inst->max_optional_data, VTY_NEWLINE);
}

DEFUN(show_sccp_timers, show_sccp_timers_cmd,
	"show cs7 instance <0-15> sccp timers",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Signaling Connection Control Part\n"
	"Show List of SCCP timers\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_ss7_instance_find(id);
	if (!ss7) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!ss7->sccp) {
		vty_out(vty, "SS7 instance %d has no SCCP initialized%s", id, VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	write_sccp_timers(vty, "", ss7->sccp, true);
	return CMD_SUCCESS;
}

void osmo_sccp_vty_init(void)
{
	install_lib_element_ve(&show_sccp_users_cmd);
	install_lib_element_ve(&show_sccp_user_ssn_cmd);
	install_lib_element_ve(&show_sccp_connections_cmd);

	install_lib_element_ve(&show_sccp_timers_cmd);
	gen_sccp_timer_cmd_strs(&sccp_timer_cmd);
	install_lib_element(L_CS7_NODE, &sccp_timer_cmd);
	install_lib_element(L_CS7_NODE, &sccp_max_optional_data_cmd);
}
