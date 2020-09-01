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

#include <netdb.h>
#include <arpa/inet.h>

#include <osmocom/core/sockaddr_str.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "xua_internal.h"
#include <osmocom/sigtran/sccp_sap.h>
#include "sccp_internal.h"

#include "sccp_internal.h"

#define XUA_VAR_STR	"(sua|m3ua|ipa)"

#define XUA_VAR_HELP_STR		\
	"SCCP User Adaptation\n"	 \
	"MTP3 User Adaptation\n"	\
	"IPA Multiplex (SCCP Lite)\n"


/***********************************************************************
 * Core CS7 Configuration
 ***********************************************************************/

enum cs7_role_t {CS7_ROLE_SG, CS7_ROLE_ASP};
static enum cs7_role_t cs7_role;
static void *g_ctx;

static struct cmd_node cs7_node = {
	L_CS7_NODE,
	"%s(config-cs7)# ",
	1,
};

DEFUN(cs7_instance, cs7_instance_cmd,
	"cs7 instance <0-15>",
	CS7_STR "Configure a SS7 Instance\n" INST_STR
	"Number of the instance\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;

	inst = osmo_ss7_instance_find_or_create(g_ctx, id);
	if (!inst) {
		vty_out(vty, "Unable to create SS7 Instance %d%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = L_CS7_NODE;
	vty->index = inst;
	vty->index_sub = &inst->cfg.description;

	return CMD_SUCCESS;
}

static const struct value_string ss7_network_indicator_vals[] = {
	{ 0,	"international" },
	{ 1,	"spare" },
	{ 2,	"national" },
	{ 3,	"reserved" },
	{ 0,	NULL }
};

/* cs7 network-indicator */
DEFUN(cs7_net_ind, cs7_net_ind_cmd,
	"network-indicator (international | national | reserved | spare)",
	"Configure the Network Indicator\n"
	"International Network\n"
	"National Network\n"
	"Reserved Network\n"
	"Spare Network\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	int ni = get_string_value(ss7_network_indicator_vals, argv[0]);

	inst->cfg.network_indicator = ni;
	return CMD_SUCCESS;
}

/* TODO: cs7 point-code format */
DEFUN(cs7_pc_format, cs7_pc_format_cmd,
	"point-code format <1-24> [<1-23>] [<1-22>]",
	PC_STR "Configure Point Code Format\n"
	"Length of first PC component\n"
	"Length of second PC component\n"
	"Length of third PC component\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	int argind = 0;

	inst->cfg.pc_fmt.component_len[0] = atoi(argv[argind++]);

	if (argc >= 2)
		inst->cfg.pc_fmt.component_len[1] = atoi(argv[argind++]);
	else
		inst->cfg.pc_fmt.component_len[1] = 0;

	if (argc >= 3)
		inst->cfg.pc_fmt.component_len[2] = atoi(argv[argind++]);
	else
		inst->cfg.pc_fmt.component_len[2] = 0;

	return CMD_SUCCESS;
}

DEFUN(cs7_pc_format_def, cs7_pc_format_def_cmd,
	"point-code format default",
	PC_STR "Configure Point Code Format\n"
	"Default Point Code Format (3.8.3)\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	inst->cfg.pc_fmt.component_len[0] = 3;
	inst->cfg.pc_fmt.component_len[1] = 8;
	inst->cfg.pc_fmt.component_len[2] = 3;
	return CMD_SUCCESS;
}


/* cs7 point-code delimiter */
DEFUN(cs7_pc_delimiter, cs7_pc_delimiter_cmd,
	"point-code delimiter (default|dash)",
	PC_STR "Configure Point Code Delimiter\n"
	"Use dot as delimiter\n"
	"User dash as delimiter\n")
{
	struct osmo_ss7_instance *inst = vty->index;

	if (!strcmp(argv[0], "dash"))
		inst->cfg.pc_fmt.delimiter = '-';
	else
		inst->cfg.pc_fmt.delimiter = '.';

	return CMD_SUCCESS;
}

DEFUN(cs7_point_code, cs7_point_code_cmd,
	"point-code POINT_CODE",
	"Configure the local Point Code\n"
	"Point Code\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	int pc = osmo_ss7_pointcode_parse(inst, argv[0]);
	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	inst->cfg.primary_pc = pc;
	return CMD_SUCCESS;
}

/* TODO: cs7 secondary-pc */
/* TODO: cs7 capability-pc */

DEFUN(cs7_permit_dyn_rkm, cs7_permit_dyn_rkm_cmd,
	"xua rkm routing-key-allocation (static-only|dynamic-permitted)",
	"SIGTRAN xxxUA related\n" "Routing Key Management\n"
	"Routing Key Management Allocation Policy\n"
	"Only static (pre-confgured) Routing Keys permitted\n"
	"Dynamically allocate Routing Keys for what ASPs request\n")
{
	struct osmo_ss7_instance *inst = vty->index;

	if (!strcmp(argv[0], "dynamic-permitted"))
		inst->cfg.permit_dyn_rkm_alloc = true;
	else
		inst->cfg.permit_dyn_rkm_alloc = false;

	return CMD_SUCCESS;
}

static void write_one_cs7(struct vty *vty, struct osmo_ss7_instance *inst, bool show_dyn_config);

static int write_all_cs7(struct vty *vty, bool show_dyn_config)
{
	struct osmo_ss7_instance *inst;

	llist_for_each_entry(inst, &osmo_ss7_instances, list)
		write_one_cs7(vty, inst, show_dyn_config);

	return 0;
}

static int config_write_cs7(struct vty *vty)
{
	return write_all_cs7(vty, false);
}

DEFUN(show_cs7_user, show_cs7_user_cmd,
	"show cs7 instance <0-15> users",
	SHOW_STR CS7_STR INST_STR INST_STR "User Table\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;
	unsigned int i;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (i = 0; i < ARRAY_SIZE(inst->user); i++) {
		const struct osmo_ss7_user *user = inst->user[i];
		if (!user)
			continue;
		vty_out(vty, "SI %u: %s%s", i, user->name, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/* TODO: Links + Linksets */

/***********************************************************************
 * Routing Table Configuration
 ***********************************************************************/

static struct cmd_node rtable_node = {
	L_CS7_RTABLE_NODE,
	"%s(config-cs7-rt)# ",
	1,
};

DEFUN(cs7_route_table, cs7_route_table_cmd,
	"route-table system",
	"Specify the name of the route table\n"
	"Name of the route table\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_ss7_route_table *rtable;

	rtable = inst->rtable_system;
	vty->node = L_CS7_RTABLE_NODE;
	vty->index = rtable;
	vty->index_sub = &rtable->cfg.description;

	return CMD_SUCCESS;
}

DEFUN(cs7_rt_upd, cs7_rt_upd_cmd,
	"update route POINT_CODE MASK linkset LS_NAME [priority PRIO] [qos-class (CLASS|default)]",
	"Update the Route\n"
	"Update the Route\n"
	"Destination Point Code\n"
	"Point Code Mask\n"
	"Point Code Length\n"
	"Specify Destination Linkset\n"
	"Linkset Name\n"
	"Specify Priority\n"
	"Priority\n"
	"Specify QoS Class\n"
	"QoS Class\n"
	"Default QoS Class\n")
{
	struct osmo_ss7_route_table *rtable = vty->index;
	struct osmo_ss7_route *rt;
	int dpc = osmo_ss7_pointcode_parse(rtable->inst, argv[0]);
	int mask = osmo_ss7_pointcode_parse_mask_or_len(rtable->inst, argv[1]);
	const char *ls_name = argv[2];
	unsigned int argind;

	if (dpc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mask < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rt = osmo_ss7_route_create(rtable, dpc, mask, ls_name);
	if (!rt) {
		vty_out(vty, "cannot create route %s/%s to %s%s",
			argv[0], argv[1], argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	argind = 3;
	if (argc > argind && !strcmp(argv[argind], "priority")) {
		argind++;
		rt->cfg.priority = atoi(argv[argind++]);
	}

	if (argc > argind && !strcmp(argv[argind], "qos-class")) {
		argind++;
		rt->cfg.qos_class = atoi(argv[argind++]);
	}

	return CMD_SUCCESS;
}

DEFUN(cs7_rt_rem, cs7_rt_rem_cmd,
	"remove route POINT_CODE MASK",
	"Remove a Route\n"
	"Remove a Route\n"
	"Destination Point Code\n"
	"Point Code Mask\n"
	"Point Code Length\n")
{
	struct osmo_ss7_route_table *rtable = vty->index;
	struct osmo_ss7_route *rt;
	int dpc = osmo_ss7_pointcode_parse(rtable->inst, argv[0]);
	int mask = osmo_ss7_pointcode_parse_mask_or_len(rtable->inst, argv[1]);

	if (dpc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mask < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rt = osmo_ss7_route_find_dpc_mask(rtable, dpc, mask);
	if (!rt) {
		vty_out(vty, "cannot find route to be deleted%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_ss7_route_destroy(rt);
	return CMD_SUCCESS;
}

static void write_one_rtable(struct vty *vty, struct osmo_ss7_route_table *rtable)
{
	struct osmo_ss7_route *rt;

	vty_out(vty, " route-table %s%s", rtable->cfg.name, VTY_NEWLINE);
	if (rtable->cfg.description)
		vty_out(vty, "  description %s%s", rtable->cfg.description, VTY_NEWLINE);
	llist_for_each_entry(rt, &rtable->routes, list) {
		vty_out(vty, "  update route %s %s linkset %s",
			osmo_ss7_pointcode_print(rtable->inst, rt->cfg.pc),
			osmo_ss7_pointcode_print2(rtable->inst, rt->cfg.mask),
			rt->cfg.linkset_name);
		if (rt->cfg.priority)
			vty_out(vty, " priority %u", rt->cfg.priority);
		if (rt->cfg.qos_class)
			vty_out(vty, " qos-class %u", rt->cfg.qos_class);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

static void vty_dump_rtable(struct vty *vty, struct osmo_ss7_route_table *rtbl)
{
	struct osmo_ss7_route *rt;

	vty_out(vty, "Routing table = %s%s", rtbl->cfg.name, VTY_NEWLINE);
	vty_out(vty, "C=Cong Q=QoS P=Prio%s", VTY_NEWLINE);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "Destination            C Q P Linkset Name        Linkset Non-adj Route%s", VTY_NEWLINE);
	vty_out(vty, "---------------------- - - - ------------------- ------- ------- -------%s", VTY_NEWLINE);

	llist_for_each_entry(rt, &rtbl->routes, list) {
		vty_out(vty, "%-22s %c %c %u %-19s %-7s %-7s %-7s%s",
			osmo_ss7_route_print(rt),
			' ', ' ', rt->cfg.priority, rt->cfg.linkset_name, "?", "?", "?", VTY_NEWLINE);
	}
}

DEFUN(show_cs7_route, show_cs7_route_cmd,
	"show cs7 instance <0-15> route",
	SHOW_STR CS7_STR INST_STR INST_STR "Routing Table\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_dump_rtable(vty, inst->rtable_system);
	return CMD_SUCCESS;
}

/***********************************************************************
 * xUA Listener Configuration (SG)
 ***********************************************************************/

static enum osmo_ss7_asp_protocol parse_asp_proto(const char *protocol)
{
	return get_string_value(osmo_ss7_asp_protocol_vals, protocol);
}

static struct cmd_node xua_node = {
	L_CS7_XUA_NODE,
	"%s(config-cs7-listen)# ",
	1,
};

DEFUN(cs7_xua, cs7_xua_cmd,
	"listen " XUA_VAR_STR " <0-65534>",
	"Configure/Enable xUA Listener\n"
	XUA_VAR_HELP_STR "SCTP Port number\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);
	uint16_t port = atoi(argv[1]);

	xs = osmo_ss7_xua_server_find(inst, proto, port);
	if (!xs) {
		xs = osmo_ss7_xua_server_create(inst, proto, port, NULL);
		if (!xs)
			return CMD_SUCCESS;
		/* Drop first dummy address created automatically by _create(): */
		osmo_ss7_xua_server_set_local_hosts(xs, NULL, 0);
	}

	vty->node = L_CS7_XUA_NODE;
	vty->index = xs;
	return CMD_SUCCESS;
}

DEFUN(no_cs7_xua, no_cs7_xua_cmd,
	"no listen " XUA_VAR_STR " <0-65534>",
	NO_STR "Disable xUA Listener on given SCTP Port\n"
	XUA_VAR_HELP_STR "SCTP Port number\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);
	uint16_t port = atoi(argv[1]);

	xs = osmo_ss7_xua_server_find(inst, proto, port);
	if (!xs) {
		vty_out(vty, "No xUA server for port %u found%s", port, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_xua_server_destroy(xs);
	return CMD_SUCCESS;
}

DEFUN(xua_local_ip, xua_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Configure the Local IP Address for xUA\n"
	"IPv4 Address to use for XUA\n"
	"IPv6 Address to use for XUA\n")
{
	struct osmo_xua_server *xs = vty->index;

	osmo_ss7_xua_server_add_local_host(xs, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(xua_accept_dyn_asp, xua_accept_dyn_asp_cmd,
	"accept-asp-connections (pre-configured|dynamic-permitted)",
	"Define what kind of ASP connections to accept\n"
	"Accept only pre-confiugred ASPs (source IP/prt)\n"
	"Accept any connection and dynamically create an ASP definition\n")
{
	struct osmo_xua_server *xs = vty->index;

	if (!strcmp(argv[0], "dynamic-permitted"))
		xs->cfg.accept_dyn_reg = true;
	else
		xs->cfg.accept_dyn_reg = false;

	return CMD_SUCCESS;
}

static void write_one_xua(struct vty *vty, struct osmo_xua_server *xs)
{
	int i;
	vty_out(vty, " listen %s %u%s",
		get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto),
		xs->cfg.local.port, VTY_NEWLINE);

	for (i = 0; i < xs->cfg.local.host_cnt; i++) {
		if (xs->cfg.local.host[i])
			vty_out(vty, "  local-ip %s%s", xs->cfg.local.host[i], VTY_NEWLINE);
	}
	if (xs->cfg.accept_dyn_reg)
		vty_out(vty, "  accept-asp-connections dynamic-permitted%s", VTY_NEWLINE);
}

static void vty_dump_xua_server(struct vty *vty, struct osmo_xua_server *xs)
{
	char buf[512];
	const char *proto = get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto);
	if (osmo_ss7_asp_peer_snprintf(buf, sizeof(buf), &xs->cfg.local) < 0)
		snprintf(buf, sizeof(buf), "<error>");
	vty_out(vty, "xUA server for %s on %s%s", proto, buf, VTY_NEWLINE);
}

DEFUN(show_cs7_xua, show_cs7_xua_cmd,
      "show cs7 "XUA_VAR_STR" [<0-65534>]",
      SHOW_STR CS7_STR XUA_VAR_HELP_STR "Port Number")
{
	struct osmo_ss7_instance *inst;
	struct osmo_xua_server *xs;
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);

	llist_for_each_entry(inst, &osmo_ss7_instances, list) {
		if (argc > 1) {
			int port = atoi(argv[1]);
			xs = osmo_ss7_xua_server_find(inst, proto, port);
			if (!xs) {
				vty_out(vty, "%% No matching server found%s", VTY_NEWLINE);
				return CMD_WARNING;
			}
			vty_dump_xua_server(vty, xs);
		} else {
			llist_for_each_entry(xs, &inst->xua_servers, list) {
				if (xs->cfg.proto == proto)
					vty_dump_xua_server(vty, xs);
			}
		}
	}
	return CMD_SUCCESS;
}

DEFUN(show_cs7_config, show_cs7_config_cmd,
      "show cs7 config",
      SHOW_STR CS7_STR "Currently running cs7 configuration")
{
	write_all_cs7(vty, true);
	return CMD_SUCCESS;
}


/***********************************************************************
 * Application Server Process
 ***********************************************************************/

static struct cmd_node asp_node = {
	L_CS7_ASP_NODE,
	"%s(config-cs7-asp)# ",
	1,
};

DEFUN(cs7_asp, cs7_asp_cmd,
	"asp NAME <0-65535> <0-65535> " XUA_VAR_STR,
	"Configure Application Server Process\n"
	"Name of ASP\n"
	"Remote SCTP port number\n"
	"Local SCTP port number\n"
	XUA_VAR_HELP_STR)
{
	struct osmo_ss7_instance *inst = vty->index;
	const char *name = argv[0];
	uint16_t remote_port = atoi(argv[1]);
	uint16_t local_port = atoi(argv[2]);
	enum osmo_ss7_asp_protocol protocol = parse_asp_proto(argv[3]);
	struct osmo_ss7_asp *asp;

	if (protocol == OSMO_SS7_ASP_PROT_NONE) {
		vty_out(vty, "invalid protocol '%s'%s", argv[3], VTY_NEWLINE);
		return CMD_WARNING;
	}

	asp = osmo_ss7_asp_find(inst, name, remote_port, local_port, protocol);
	if (!asp) {
		asp = osmo_ss7_asp_find_or_create(inst, name, remote_port, local_port, protocol);
		if (!asp) {
			vty_out(vty, "cannot create ASP '%s'%s", name, VTY_NEWLINE);
			return CMD_WARNING;
		}
		asp->cfg.is_server = true;
		asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
	}

	vty->node = L_CS7_ASP_NODE;
	vty->index = asp;
	vty->index_sub = &asp->cfg.description;
	return CMD_SUCCESS;
}

DEFUN(no_cs7_asp, no_cs7_asp_cmd,
	"no asp NAME",
	NO_STR "Disable Application Server Process\n"
	"Name of ASP\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	const char *name = argv[0];
	struct osmo_ss7_asp *asp;

	asp = osmo_ss7_asp_find_by_name(inst, name);
	if (!asp) {
		vty_out(vty, "No ASP named '%s' found%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_asp_destroy(asp);
	return CMD_SUCCESS;
}

DEFUN(asp_local_ip, asp_local_ip_cmd,
	"local-ip " VTY_IPV46_CMD,
	"Specify Local IP Address from which to contact ASP\n"
	"Local IPv4 Address from which to contact of ASP\n"
	"Local IPv6 Address from which to contact of ASP\n")
{
	struct osmo_ss7_asp *asp = vty->index;
	if (osmo_ss7_asp_peer_add_host(&asp->cfg.local, asp, argv[0]) != 0) {
		vty_out(vty, "%% Failed adding host '%s' to set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(asp_remote_ip, asp_remote_ip_cmd,
	"remote-ip " VTY_IPV46_CMD,
	"Specify Remote IP Address of ASP\n"
	"Remote IPv4 Address of ASP\n"
	"Remote IPv6 Address of ASP\n")
{
	struct osmo_ss7_asp *asp = vty->index;
	if (osmo_ss7_asp_peer_add_host(&asp->cfg.remote, asp, argv[0]) != 0) {
		vty_out(vty, "%% Failed adding host '%s' to set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(asp_qos_clas, asp_qos_class_cmd,
	"qos-class <0-255>",
	"Specify QoS Class of ASP\n"
	"QoS Class of ASP\n")
{
	struct osmo_ss7_asp *asp = vty->index;
	asp->cfg.qos_class = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(asp_role, asp_role_cmd,
	"role (sg|asp|ipsp)",
	"Specify the xUA role for this ASP\n"
	"SG (Signaling Gateway)\n"
	"ASP (Application Server Process)\n"
	"IPSP (IP Signalling Point)\n")
{
	struct osmo_ss7_asp *asp = vty->index;

	if (!strcmp(argv[0], "sg")) {
		asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
	} else if (!strcmp(argv[0], "asp")) {
		asp->cfg.role = OSMO_SS7_ASP_ROLE_ASP;
	} else if (!strcmp(argv[0], "ipsp")) {
		vty_out(vty, "IPSP role isn't supported yet%s", VTY_NEWLINE);
		return CMD_WARNING;
	} else
		OSMO_ASSERT(0);

	asp->cfg.role_set_by_vty = true;
	return CMD_SUCCESS;
}

DEFUN(sctp_role, asp_sctp_role_cmd,
	"sctp-role (client|server)",
	"Specify the SCTP role for this ASP\n"
	"Operate as SCTP client; connect to a server\n"
	"Operate as SCTP server; wait for client connections\n")
{
	struct osmo_ss7_asp *asp = vty->index;

	if (!strcmp(argv[0], "client"))
		asp->cfg.is_server = false;
	else if (!strcmp(argv[0], "server"))
		asp->cfg.is_server = true;
	else
		OSMO_ASSERT(0);

	return CMD_SUCCESS;
}

DEFUN(asp_block, asp_block_cmd,
	"block",
	"Allows a SCTP Association with ASP, but doesn't let it become active\n")
{
	/* TODO */
	vty_out(vty, "Not supported yet%s", VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(asp_shutdown, asp_shutdown_cmd,
	"shutdown",
	"Terminates SCTP association; New associations will be rejected\n")
{
	/* TODO */
	vty_out(vty, "Not supported yet%s", VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(show_cs7_asp, show_cs7_asp_cmd,
	"show cs7 instance <0-15> asp",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server Process (ASP)\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_asp *asp;
	char buf[512];
	int id = atoi(argv[0]);

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "                                                          Effect Primary%s", VTY_NEWLINE);
	vty_out(vty, "ASP Name      AS Name       State          Type Remote IP Addr:Rmt Port SCTP%s", VTY_NEWLINE);
	vty_out(vty, "------------  ------------  -------------  ---- ----------------------- ----------%s", VTY_NEWLINE);

	llist_for_each_entry(asp, &inst->asp_list, list) {
		osmo_ss7_asp_peer_snprintf(buf, sizeof(buf), &asp->cfg.remote);
		vty_out(vty, "%-12s  %-12s  %-13s  %-4s  %-14s  %-10s%s",
			asp->cfg.name, "?",
			asp->fi? osmo_fsm_inst_state_name(asp->fi) : "uninitialized",
			get_value_string(osmo_ss7_asp_protocol_vals, asp->cfg.proto),
			buf, "", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static void write_one_asp(struct vty *vty, struct osmo_ss7_asp *asp, bool show_dyn_config)
{
	int i;
	/* skip any dynamically created ASPs (e.g. auto-created at connect time) */
	if ((asp->dyn_allocated || asp->simple_client_allocated)
	    && !show_dyn_config)
		return;

	vty_out(vty, " asp %s %u %u %s%s",
		asp->cfg.name, asp->cfg.remote.port, asp->cfg.local.port,
		osmo_ss7_asp_protocol_name(asp->cfg.proto), VTY_NEWLINE);
	if (asp->cfg.description)
		vty_out(vty, "  description %s%s", asp->cfg.description, VTY_NEWLINE);
	for (i = 0; i < asp->cfg.local.host_cnt; i++) {
		if (asp->cfg.local.host[i])
			vty_out(vty, "  local-ip %s%s", asp->cfg.local.host[i], VTY_NEWLINE);
	}
	for (i = 0; i < asp->cfg.remote.host_cnt; i++) {
		if (asp->cfg.remote.host[i])
			vty_out(vty, "  remote-ip %s%s", asp->cfg.remote.host[i], VTY_NEWLINE);
	}
	if (asp->cfg.qos_class)
		vty_out(vty, "  qos-class %u%s", asp->cfg.qos_class, VTY_NEWLINE);
	if (asp->cfg.role_set_by_vty) {
		vty_out(vty, "  role %s%s", osmo_str_tolower(get_value_string(osmo_ss7_asp_role_names, asp->cfg.role)),
			VTY_NEWLINE);
	}
	if (!asp->cfg.is_server)
		vty_out(vty, "  sctp-role client%s", VTY_NEWLINE);
}


/***********************************************************************
 * Application Server
 ***********************************************************************/

static struct cmd_node as_node = {
	L_CS7_AS_NODE,
	"%s(config-cs7-as)# ",
	1,
};

DEFUN(cs7_as, cs7_as_cmd,
	"as NAME " XUA_VAR_STR,
	"Configure an Application Server\n"
	"Name of the Application Server\n"
	XUA_VAR_HELP_STR)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_ss7_as *as;
	const char *name = argv[0];
	enum osmo_ss7_asp_protocol protocol = parse_asp_proto(argv[1]);

	if (protocol == OSMO_SS7_ASP_PROT_NONE) {
		vty_out(vty, "invalid protocol '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	as = osmo_ss7_as_find_or_create(inst, name, protocol);
	if (!as) {
		vty_out(vty, "cannot create AS '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	as->cfg.name = talloc_strdup(as, name);

	vty->node = L_CS7_AS_NODE;
	vty->index = as;
	vty->index_sub = &as->cfg.description;

	return CMD_SUCCESS;
}

DEFUN(no_cs7_as, no_cs7_as_cmd,
	"no as NAME",
	NO_STR "Disable Application Server\n"
	"Name of AS\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	const char *name = argv[0];
	struct osmo_ss7_as *as;

	as = osmo_ss7_as_find_by_name(inst, name);
	if (!as) {
		vty_out(vty, "No AS named '%s' found%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_as_destroy(as);
	return CMD_SUCCESS;
}

/* TODO: routing-key */
DEFUN(as_asp, as_asp_cmd,
	"asp NAME",
	"Specify that a given ASP is part of this AS\n"
	"Name of ASP to be added to AS\n")
{
	struct osmo_ss7_as *as = vty->index;

	if (osmo_ss7_as_add_asp(as, argv[0])) {
		vty_out(vty, "cannot find ASP '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(as_no_asp, as_no_asp_cmd,
	"no asp NAME",
	NO_STR "Specify ASP to be removed from this AS\n"
	"Name of ASP to be removed\n")
{
	struct osmo_ss7_as *as = vty->index;

	if (osmo_ss7_as_del_asp(as, argv[0])) {
		vty_out(vty, "cannot find ASP '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(as_traf_mode, as_traf_mode_cmd,
	"traffic-mode (broadcast | loadshare | roundrobin | override)",
	"Specifies traffic mode of operation of the ASP within the AS\n"
	"Broadcast to all ASP within AS\n"
	"Share Load among all ASP within AS\n"
	"Round-Robin between all ASP within AS\n"
	"Override\n")
{
	struct osmo_ss7_as *as = vty->index;

	as->cfg.mode = get_string_value(osmo_ss7_as_traffic_mode_vals, argv[0]);
	as->cfg.mode_set_by_vty = true;
	return CMD_SUCCESS;
}

DEFUN(as_no_traf_mode, as_no_traf_mode_cmd,
	"no traffic-mode",
	NO_STR "Remove explicit traffic mode of operation of this AS\n")
{
	struct osmo_ss7_as *as = vty->index;

	as->cfg.mode = 0;
	as->cfg.mode_set_by_vty = false;
	return CMD_SUCCESS;
}

DEFUN(as_recov_tout, as_recov_tout_cmd,
	"recovery-timeout <1-2000>",
	"Specifies the recovery timeout value in milliseconds\n"
	"Recovery Timeout in Milliseconds\n")
{
	struct osmo_ss7_as *as = vty->index;
	as->cfg.recovery_timeout_msec = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(as_qos_clas, as_qos_class_cmd,
	"qos-class <0-255>",
	"Specity QoS Class of AS\n"
	"QoS Class of AS\n")
{
	struct osmo_ss7_as *as = vty->index;
	as->cfg.qos_class = atoi(argv[0]);
	return CMD_SUCCESS;
}

const struct value_string mtp_si_vals[] = {
	{ MTP_SI_SCCP,		"sccp" },
	{ MTP_SI_TUP,		"tup" },
	{ MTP_SI_ISUP,		"isup" },
	{ MTP_SI_DUP,		"dup" },
	{ MTP_SI_TESTING,	"testing" },
	{ MTP_SI_B_ISUP,	"b-isup" },
	{ MTP_SI_SAT_ISUP,	"sat-isup" },
	{ MTP_SI_AAL2_SIG,	"aal2" },
	{ MTP_SI_BICC,		"bicc" },
	{ MTP_SI_GCP,		"h248" },
	{ 0, NULL }
};

#define ROUTING_KEY_CMD "routing-key RCONTEXT DPC"
#define ROUTING_KEY_CMD_STRS \
	"Define a routing key\n" \
	"Routing context number\n" \
	"Destination Point Code\n"
#define ROUTING_KEY_SI_ARG " si (aal2|bicc|b-isup|h248|isup|sat-isup|sccp|tup)"
#define ROUTING_KEY_SI_ARG_STRS \
	"Match on Service Indicator\n" \
	"ATM Adaption Layer 2\n" \
	"Bearer Independent Call Control\n" \
	"Broadband ISDN User Part\n" \
	"H.248\n" \
	"ISDN User Part\n" \
	"Sattelite ISDN User Part\n" \
	"Signalling Connection Control Part\n" \
	"Telephony User Part\n"
#define ROUTING_KEY_SSN_ARG " ssn SSN"
#define ROUTING_KEY_SSN_ARG_STRS \
	"Match on Sub-System Number\n" \
	"Sub-System Number to match on\n"

static int _rout_key(struct vty *vty,
		     const char *rcontext, const char *dpc,
		     const char *si, const char *ssn)
{
	struct osmo_ss7_as *as = vty->index;
	struct osmo_ss7_routing_key *rkey = &as->cfg.routing_key;
	int pc;

	if (as->cfg.proto == OSMO_SS7_ASP_PROT_IPA && atoi(rcontext) != 0) {
		vty_out(vty, "IPA doesn't support routing contexts; only permitted routing context "
			"is 0\n");
		return CMD_WARNING;
	}

	pc = osmo_ss7_pointcode_parse(as->inst, dpc);
	if (pc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", dpc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	rkey->pc = pc;

	rkey->context = atoi(rcontext);				/* FIXME: input validation */
	rkey->si = si ? get_string_value(mtp_si_vals, si) : 0;	/* FIXME: input validation */
	rkey->ssn = ssn ? atoi(ssn) : 0;			/* FIXME: input validation */

	return CMD_SUCCESS;
}

DEFUN(as_rout_key, as_rout_key_cmd,
      ROUTING_KEY_CMD,
      ROUTING_KEY_CMD_STRS)
{
	return _rout_key(vty, argv[0], argv[1], NULL, NULL);
}

DEFUN(as_rout_key_si, as_rout_key_si_cmd,
      ROUTING_KEY_CMD      ROUTING_KEY_SI_ARG,
      ROUTING_KEY_CMD_STRS ROUTING_KEY_SI_ARG_STRS)
{
	return _rout_key(vty, argv[0], argv[1], argv[2], NULL);
}

DEFUN(as_rout_key_ssn, as_rout_key_ssn_cmd,
      ROUTING_KEY_CMD      ROUTING_KEY_SSN_ARG,
      ROUTING_KEY_CMD_STRS ROUTING_KEY_SSN_ARG_STRS)
{
	return _rout_key(vty, argv[0], argv[1], NULL, argv[2]);
}

DEFUN(as_rout_key_si_ssn, as_rout_key_si_ssn_cmd,
      ROUTING_KEY_CMD      ROUTING_KEY_SI_ARG      ROUTING_KEY_SSN_ARG,
      ROUTING_KEY_CMD_STRS ROUTING_KEY_SI_ARG_STRS ROUTING_KEY_SSN_ARG_STRS)
{
	return _rout_key(vty, argv[0], argv[1], argv[2], argv[3]);
}

DEFUN(as_pc_override, as_pc_override_cmd,
	"point-code override dpc PC",
	"Point Code Specific Features\n"
	"Override (force) a point-code to hard-coded value\n"
	"Override Source Point Code\n"
	"Override Destination Point Code\n"
	"New Point Code\n")
{
	struct osmo_ss7_as *as = vty->index;
	int pc = osmo_ss7_pointcode_parse(as->inst, argv[0]);
	if (pc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (as->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		vty_out(vty, "Only IPA type AS support point-code override. "
			"Be happy that you don't need it!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	as->cfg.pc_override.dpc = pc;

	return CMD_SUCCESS;
}

DEFUN(as_pc_patch_sccp, as_pc_patch_sccp_cmd,
	"point-code override patch-sccp (disabled|both)",
	"Point Code Specific Features\n"
	"Override (force) a point-code to hard-coded value\n"
	"Patch point code values into SCCP called/calling address\n"
	"Don't patch any point codes into SCCP called/calling address\n"
	"Patch both origin and destination point codes into SCCP called/calling address\n")
{
	struct osmo_ss7_as *as = vty->index;

	if (as->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		vty_out(vty, "Only IPA type AS support point-code patch-into-sccp. "
			"Be happy that you don't need it!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "disabled"))
		as->cfg.pc_override.sccp_mode = OSMO_SS7_PATCH_NONE;
	else
		as->cfg.pc_override.sccp_mode = OSMO_SS7_PATCH_BOTH;

	return CMD_SUCCESS;
}

static void write_one_as(struct vty *vty, struct osmo_ss7_as *as, bool show_dyn_config)
{
	struct osmo_ss7_routing_key *rkey;
	unsigned int i;

	/* skip any dynamically allocated AS definitions */
	if ((as->rkm_dyn_allocated || as->simple_client_allocated)
	    && !show_dyn_config)
		return;

	vty_out(vty, " as %s %s%s", as->cfg.name,
		osmo_ss7_asp_protocol_name(as->cfg.proto), VTY_NEWLINE);
	if (as->cfg.description)
		vty_out(vty, "  description %s%s", as->cfg.description, VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;
		/* skip any dynamically created ASPs (e.g. auto-created at connect time) */
		if ((asp->dyn_allocated || asp->simple_client_allocated)
		    && !show_dyn_config)
			continue;
		vty_out(vty, "  asp %s%s", asp->cfg.name, VTY_NEWLINE);
	}
	if (as->cfg.mode_set_by_vty)
		vty_out(vty, "  traffic-mode %s%s",
			osmo_ss7_as_traffic_mode_name(as->cfg.mode), VTY_NEWLINE);
	if (as->cfg.recovery_timeout_msec != 2000) {
		vty_out(vty, "  recovery-timeout %u%s",
			as->cfg.recovery_timeout_msec, VTY_NEWLINE);
	}
	if (as->cfg.qos_class)
		vty_out(vty, "  qos-class %u%s", as->cfg.qos_class, VTY_NEWLINE);
	rkey = &as->cfg.routing_key;
	vty_out(vty, "  routing-key %u %s", rkey->context,
		osmo_ss7_pointcode_print(as->inst, rkey->pc));
	if (rkey->si)
		vty_out(vty, " si %s",
			get_value_string(mtp_si_vals, rkey->si));
	if (rkey->ssn)
		vty_out(vty, " ssn %u", rkey->ssn);
	vty_out(vty, "%s", VTY_NEWLINE);

	if (as->cfg.pc_override.dpc)
		vty_out(vty, "  point-code override dpc %s%s",
			osmo_ss7_pointcode_print(as->inst, as->cfg.pc_override.dpc), VTY_NEWLINE);

	if (as->cfg.pc_override.sccp_mode)
		vty_out(vty, "  point-code override patch-sccp both%s", VTY_NEWLINE);
}

DEFUN(show_cs7_as, show_cs7_as_cmd,
	"show cs7 instance <0-15> as (active|all|m3ua|sua)",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server (AS)\n"
	"Display all active ASs\n"
	"Display all ASs (default)\n"
	"Display all m3ua ASs\n"
	"Display all SUA ASs\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_as *as;
	const char *filter = argv[1];
	int id = atoi(argv[0]);

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "                          Routing    Routing Key                          Cic   Cic   Traffic%s", VTY_NEWLINE);
	vty_out(vty, "AS Name      State        Context    Dpc           Si   Opc           Ssn Min   Max   Mode%s", VTY_NEWLINE);
	vty_out(vty, "------------ ------------ ---------- ------------- ---- ------------- --- ----- ----- -------%s", VTY_NEWLINE);

	llist_for_each_entry(as, &inst->as_list, list) {
		if (filter && !strcmp(filter, "m3ua") && as->cfg.proto != OSMO_SS7_ASP_PROT_M3UA)
			continue;
		if (filter && !strcmp(filter, "sua") && as->cfg.proto != OSMO_SS7_ASP_PROT_SUA)
			continue;
		if (filter && !strcmp(filter, "active") && !osmo_ss7_as_active(as))
			continue;
		vty_out(vty, "%-12s %-12s %-10u %-13s %4s %13s %3s %5s %4s %10s%s",
			as->cfg.name, osmo_fsm_inst_state_name(as->fi), as->cfg.routing_key.context,
			osmo_ss7_pointcode_print(as->inst, as->cfg.routing_key.pc),
			"", "", "", "", "", osmo_ss7_as_traffic_mode_name(as->cfg.mode),
			VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/***********************************************************************
 * SCCP addressbook handling
 ***********************************************************************/

/* SCCP addressbook */
struct osmo_sccp_addr_entry {
	struct llist_head list;
	struct llist_head list_global;
	struct osmo_ss7_instance *inst;
	char name[32];
	struct osmo_sccp_addr addr;
};

static struct cmd_node sccpaddr_node = {
	L_CS7_SCCPADDR_NODE,
	"%s(config-cs7-sccpaddr)# ",
	1,
};

static struct cmd_node sccpaddr_gt_node = {
	L_CS7_SCCPADDR_GT_NODE,
	"%s(config-cs7-sccpaddr-gt)# ",
	1,
};

/* A global list that holds all addressbook entries at once
 * (see also .cfg in struct osmo_ss7_instance) */
LLIST_HEAD(sccp_address_book_global);

/* Pick an SCCP address entry from the addressbook list by its name */
static struct osmo_sccp_addr_entry
*addr_entry_by_name_local(const char *name,
			  const struct osmo_ss7_instance *inst)
{
	struct osmo_sccp_addr_entry *entry;

	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		if (strcmp(entry->name, name) == 0) {
			OSMO_ASSERT(entry->inst == inst);
			return entry;
		}
	}

	return NULL;
}

/* Pick an SCCP address entry from the global addressbook
 * list by its name */
static struct osmo_sccp_addr_entry
*addr_entry_by_name_global(const char *name)
{
	struct osmo_sccp_addr_entry *entry;

	llist_for_each_entry(entry, &sccp_address_book_global,
			     list_global) {
		if (strcmp(entry->name, name) == 0)
			return entry;
	}

	return NULL;
}

/*! \brief Lookup an SCCP address from the addressbook by its name.
 *  \param[out] dest_addr pointer to output the resulting sccp-address;
 *		(set to NULL if not interested)
 *  \param[in] name of the address to lookup
 *  \returns SS7 instance; NULL on error */
struct osmo_ss7_instance *
osmo_sccp_addr_by_name(struct osmo_sccp_addr *dest_addr,
		       const char *name)
{
	struct osmo_sccp_addr_entry *entry;

	entry = addr_entry_by_name_global(name);
	if (!entry)
		return NULL;

	if (dest_addr)
		*dest_addr = entry->addr;

	return entry->inst;
}

/*! \brief Reverse lookup the lookup-name of a specified SCCP address.
 *  \param[in] name of the address to lookup
 *  \returns char pointer to the lookup-name; NULL on error */
const char *osmo_sccp_name_by_addr(const struct osmo_sccp_addr *addr)
{
	struct osmo_sccp_addr_entry *entry;

	llist_for_each_entry(entry, &sccp_address_book_global, list_global) {
		if (memcmp(&entry->addr, addr, sizeof(*addr)) == 0)
			return entry->name;
	}

	return NULL;
}

/* Generate VTY configuration file snippet */
static void write_sccp_addressbook(struct vty *vty,
				   const struct osmo_ss7_instance *inst)
{
	struct osmo_sccp_addr_entry *entry;

	if (llist_empty(&inst->cfg.sccp_address_book))
		return;

	/* FIXME: Add code to write IP-Addresses */

	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		vty_out(vty, " sccp-address %s%s", entry->name, VTY_NEWLINE);
		switch (entry->addr.ri) {
		case OSMO_SCCP_RI_GT:
			vty_out(vty, "  routing-indicator GT%s", VTY_NEWLINE);
			break;
		case OSMO_SCCP_RI_SSN_PC:
			vty_out(vty, "  routing-indicator PC%s", VTY_NEWLINE);
			break;
		case OSMO_SCCP_RI_SSN_IP:
			vty_out(vty, "  routing-indicator IP%s", VTY_NEWLINE);
			break;
		case OSMO_SCCP_RI_NONE:
			break;
		default:
			vty_out(vty, "  ! invalid routing-indicator value: %u%s", entry->addr.ri, VTY_NEWLINE);
			break;
		}
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_PC)
			vty_out(vty, "  point-code %s%s",
				osmo_ss7_pointcode_print(entry->inst,
							 entry->addr.pc),
				VTY_NEWLINE);
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_SSN)
			vty_out(vty, "  subsystem-number %u%s", entry->addr.ssn,
				VTY_NEWLINE);
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_GT) {
			vty_out(vty, "  global-title%s", VTY_NEWLINE);
			vty_out(vty, "   global-title-indicator %u%s",
				entry->addr.gt.gti, VTY_NEWLINE);
			vty_out(vty, "   translation-type %u%s",
				entry->addr.gt.tt, VTY_NEWLINE);
			vty_out(vty, "   numbering-plan-indicator %u%s",
				entry->addr.gt.npi, VTY_NEWLINE);
			vty_out(vty, "   nature-of-address-indicator %u%s",
				entry->addr.gt.nai, VTY_NEWLINE);
			if (strlen(entry->addr.gt.digits))
				vty_out(vty, "   digits %s%s",
					entry->addr.gt.digits, VTY_NEWLINE);
		}
	}
}

/* List all addressbook entries */
DEFUN(cs7_show_sccpaddr, cs7_show_sccpaddr_cmd,
      "show cs7 instance <0-15> sccp addressbook",
      SHOW_STR CS7_STR INST_STR INST_STR SCCP_STR
      "List all SCCP addressbook entries\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_sccp_addr_entry *entry;
	int id = atoi(argv[0]);
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	char ip_addr_str[INET6_ADDRSTRLEN];
#endif

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (inst->cfg.description)
		vty_out(vty, "  description %s%s", inst->cfg.description,
			VTY_NEWLINE);

	if (llist_empty(&inst->cfg.sccp_address_book)) {
		vty_out(vty, "SCCP addressbook empty!%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	vty_out(vty, "%s", VTY_NEWLINE);

	vty_out(vty, "Name         ");
	vty_out(vty, "RI: ");
	vty_out(vty, "PC:       ");
	vty_out(vty, "SSN:       ");
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	vty_out(vty, "IP-Address:                            ");
#endif
	vty_out(vty, "GT:");
	vty_out(vty, "%s", VTY_NEWLINE);

	vty_out(vty, "------------ ");
	vty_out(vty, "--- ");
	vty_out(vty, "--------- ");
	vty_out(vty, "---------- ");
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	vty_out(vty, "--------------------------------------- ");
#endif
	vty_out(vty, "--------------------------------------- ");
	vty_out(vty, "%s", VTY_NEWLINE);

	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		vty_out(vty, "%-12s ", entry->name);

		/* RI */
		switch (entry->addr.ri) {
		case OSMO_SCCP_RI_GT:
			vty_out(vty, "GT  ");
			break;
		case OSMO_SCCP_RI_SSN_PC:
			vty_out(vty, "PC  ");
			break;
		case OSMO_SCCP_RI_SSN_IP:
			vty_out(vty, "IP  ");
			break;
		default:
			vty_out(vty, "ERR ");
			break;
		}

		/* PC */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_PC)
			vty_out(vty, "%-9s ",
				osmo_ss7_pointcode_print(entry->inst,
							 entry->addr.pc));
		else
			vty_out(vty, "(none)    ");

		/* SSN */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_SSN)
			vty_out(vty, "%-10u ", entry->addr.ssn);
		else
			vty_out(vty, "(none)     ");
#if 0
		/* FIXME: IP-Address based SCCP-Routing is currently not
		 * supported, so we leave the related VTY options out for now */
		/* IP-Address */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_IPv4) {
			inet_ntop(AF_INET, &entry->addr.ip.v4, ip_addr_str,
				  INET6_ADDRSTRLEN);
			vty_out(vty, "%-39s ", ip_addr_str);
		} else if (entry->addr.presence & OSMO_SCCP_ADDR_T_IPv6) {
			inet_ntop(AF_INET6, &entry->addr.ip.v6, ip_addr_str,
				  INET6_ADDRSTRLEN);
			vty_out(vty, "%-39s ", ip_addr_str);
		} else
			vty_out(vty, "(none)              ");
#endif
		/* GT */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_GT) {
			vty_out(vty, "GTI:%u ", entry->addr.gt.gti);
			vty_out(vty, "TT:%u ", entry->addr.gt.tt);
			vty_out(vty, "NPI:%u ", entry->addr.gt.npi);
			vty_out(vty, "NAI:%u ", entry->addr.gt.nai);
			if (strlen(entry->addr.gt.digits))
				vty_out(vty, "%s ", entry->addr.gt.digits);
		} else
			vty_out(vty, "(none)");
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/* Create a new addressbook entry and switch nodes */
DEFUN(cs7_sccpaddr, cs7_sccpaddr_cmd,
      "sccp-address NAME",
      "Create/Modify an SCCP addressbook entry\n" "Name of the SCCP Address\n")
{
	struct osmo_ss7_instance *inst = (struct osmo_ss7_instance *)vty->index;
	struct osmo_sccp_addr_entry *entry;
	const char *name = argv[0];

	if (strlen(name) >= sizeof(entry->name)) {
		vty_out(vty, "Error: SCCP address name too long: '%s'%s",
			name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Ensure that we do not use address names that
	 * are already used in other ss7 instances. */
	entry = addr_entry_by_name_global(name);
	if (entry != NULL) {
		vty_out(vty,
			"Error: SCCP address name already used in cs7 instance %u: '%s'%s",
			entry->inst->cfg.id, entry->name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	entry = addr_entry_by_name_local(name, inst);

	/* Create a new addressbook entry if we can not find an
	 * already existing entry */
	if (!entry) {
		entry = talloc_zero(inst, struct osmo_sccp_addr_entry);
		osmo_strlcpy(entry->name, name, sizeof(entry->name));
		llist_add_tail(&entry->list, &inst->cfg.sccp_address_book);
		llist_add_tail(&entry->list_global, &sccp_address_book_global);
		entry->addr.ri = OSMO_SCCP_RI_SSN_PC;
	}

	entry->inst = (struct osmo_ss7_instance *)vty->index;
	vty->node = L_CS7_SCCPADDR_NODE;
	vty->index = entry;

	return CMD_SUCCESS;
}

DEFUN(cs7_sccpaddr_del, cs7_sccpaddr_del_cmd,
      "no sccp-address NAME",
      NO_STR "Delete an SCCP addressbook entry\n" "Name of the SCCP Address\n")
{
	struct osmo_ss7_instance *inst = (struct osmo_ss7_instance *)vty->index;
	struct osmo_sccp_addr_entry *entry;
	const char *name = argv[0];

	entry = addr_entry_by_name_local(name, inst);
	if (entry) {
		llist_del(&entry->list);
		llist_del(&entry->list_global);
		talloc_free(entry);
	} else {
		vty_out(vty, "Addressbook entry not found!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* Set routing indicator of sccp address */
DEFUN(cs7_sccpaddr_ri, cs7_sccpaddr_ri_cmd,
      "routing-indicator (GT|PC|IP)",
      "Add Routing Indicator\n"
      "by global-title\n" "by point-code\n" "by ip-address\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	switch (argv[0][0]) {
	case 'G':
		entry->addr.ri = OSMO_SCCP_RI_GT;
		break;
	case 'P':
		entry->addr.ri = OSMO_SCCP_RI_SSN_PC;
		break;
	case 'I':
		entry->addr.ri = OSMO_SCCP_RI_SSN_IP;
		break;
	}
	return CMD_SUCCESS;
}

/* Set point-code number of sccp address */
DEFUN(cs7_sccpaddr_pc, cs7_sccpaddr_pc_cmd,
      "point-code POINT_CODE", "Add point-code Number\n" "PC\n")
{
	int pc;
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);

	pc = osmo_ss7_pointcode_parse(entry->inst, argv[0]);
	if (pc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	entry->addr.presence |= OSMO_SCCP_ADDR_T_PC;
	entry->addr.pc = pc;
	if (entry->addr.ri == OSMO_SCCP_RI_NONE)
		entry->addr.ri = OSMO_SCCP_RI_SSN_PC;
	return CMD_SUCCESS;
}

/* Remove point-code number from sccp address */
DEFUN(cs7_sccpaddr_pc_del, cs7_sccpaddr_pc_del_cmd,
      "no point-code", NO_STR "Remove point-code Number\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_PC;
	entry->addr.pc = 0;
	return CMD_SUCCESS;
}

/* Set subsystem number of sccp address */
DEFUN(cs7_sccpaddr_ssn, cs7_sccpaddr_ssn_cmd,
      "subsystem-number <0-4294967295>", "Add Subsystem Number\n" "SSN\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence |= OSMO_SCCP_ADDR_T_SSN;
	entry->addr.ssn = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Remove subsystem number from sccp address */
DEFUN(cs7_sccpaddr_ssn_del, cs7_sccpaddr_ssn_del_cmd,
      "no subsystem-number", NO_STR "Remove Subsystem Number\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_SSN;
	entry->addr.ssn = 0;
	return CMD_SUCCESS;
}

#if 0
/* FIXME: IP-Address based SCCP-Routing is currently not supported,
 * so we leave the related VTY options out for now */

/* Set IP Address (V4) of sccp address */
DEFUN(cs7_sccpaddr_ipv4, cs7_sccpaddr_ipv4_cmd,
      "ip-address V4 A.B.C.D",
      "Add IP-Address\n" "Protocol version 4\n" "IP-Address digits\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	unsigned int rc;
	uint8_t ip_addr_backup[sizeof(entry->addr.ip)];
	OSMO_ASSERT(entry);

	/* Create a backup of the existing IP-Address setting */
	memcpy(ip_addr_backup, &entry->addr.ip, sizeof(entry->addr.ip));

	entry->addr.presence |= OSMO_SCCP_ADDR_T_IPv4;
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;
	rc = inet_pton(AF_INET, argv[1], &entry->addr.ip.v4);
	if (rc <= 0) {
		vty_out(vty, "Invalid IP-Address format!%s", VTY_NEWLINE);
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;

		/* In case of failure, make sure the previous IP-Address
		 * configuration is restored */
		memcpy(&entry->addr.ip, ip_addr_backup, sizeof(entry->addr.ip));
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

/* Set IP Address (V6) of sccp address */
DEFUN(cs7_sccpaddr_ipv6, cs7_sccpaddr_ipv6_cmd,
      "ip-address V6 A:B:C:D:E:F:G:H",
      "Add IP-Address\n" "Protocol version 6\n" "IP-Address digits\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	unsigned int rc;
	uint8_t ip_addr_backup[sizeof(entry->addr.ip)];
	OSMO_ASSERT(entry);

	/* Create a backup of the existing IP-Address setting */
	memcpy(ip_addr_backup, &entry->addr.ip, sizeof(entry->addr.ip));

	entry->addr.presence |= OSMO_SCCP_ADDR_T_IPv6;
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
	rc = inet_pton(AF_INET6, argv[1], &entry->addr.ip.v4);
	if (rc <= 0) {
		vty_out(vty, "Invalid IP-Address format!%s", VTY_NEWLINE);
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;

		/* In case of failure, make sure the previous IP-Address
		 * configuration is restored */
		memcpy(&entry->addr.ip, ip_addr_backup, sizeof(entry->addr.ip));
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

/* Remove IP Address from sccp address */
DEFUN(cs7_sccpaddr_ip_del, cs7_sccpaddr_ip_del_cmd,
      "no ip-address", NO_STR "Remove IP-Address\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;
	memset(&entry->addr.ip, 0, sizeof(entry->addr.ip));
	return CMD_SUCCESS;
}
#endif

/* Configure global title and switch nodes */
DEFUN(cs7_sccpaddr_gt, cs7_sccpaddr_gt_cmd,
      "global-title", "Add/Modify Global Title\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	entry->addr.presence |= OSMO_SCCP_ADDR_T_GT;
	vty->node = L_CS7_SCCPADDR_GT_NODE;
	return CMD_SUCCESS;
}

/* Remove global title from sccp address */
DEFUN(cs7_sccpaddr_gt_del, cs7_sccpaddr_gt_del_cmd,
      "no global-title", NO_STR "Remove Global Title\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_GT;
	entry->addr.gt = (struct osmo_sccp_gt) {};
	return CMD_SUCCESS;
}

/* Set global title inicator of the sccp address gt */
DEFUN(cs7_sccpaddr_gt_gti, cs7_sccpaddr_gt_gti_cmd,
      "global-title-indicator <0-15>", "Set Global Title Indicator\n" "GTI\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.gti = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title translation type of the sccp address gt */
DEFUN(cs7_sccpaddr_gt_tt, cs7_sccpaddr_gt_tt_cmd,
      "translation-type <0-255>", "Set Global Title Translation Type\n" "TT\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.tt = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title numbering plan indicator of the sccp address gt */
DEFUN(cs7_sccpaddr_gt_npi, cs7_sccpaddr_gt_npi_cmd,
      "numbering-plan-indicator <0-15>",
      "Set Global Title Numbering Plan Indicator\n" "NPI\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.npi = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title nature of address indicator of the sccp address gt */
DEFUN(cs7_sccpaddr_gt_nai, cs7_sccpaddr_gt_nai_cmd,
      "nature-of-address-indicator <0-127>",
      "Set Global Title Nature of Address Indicator\n" "NAI\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.nai = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title digits of the sccp address gt */
DEFUN(cs7_sccpaddr_gt_digits, cs7_sccpaddr_gt_digits_cmd,
      "digits DIGITS", "Set Global Title Digits\n" "Number digits\n")
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);

	if (strlen(argv[0]) > sizeof(entry->addr.gt.digits)) {
		vty_out(vty, "Number too long!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	memset(entry->addr.gt.digits, 0, sizeof(entry->addr.gt.digits));

	osmo_strlcpy(entry->addr.gt.digits, argv[0],
		     sizeof(entry->addr.gt.digits));
	return CMD_SUCCESS;
}

/***********************************************************************
 * Common
 ***********************************************************************/

static void write_one_cs7(struct vty *vty, struct osmo_ss7_instance *inst, bool show_dyn_config)
{
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route_table *rtable;
	struct osmo_xua_server *oxs;

	vty_out(vty, "cs7 instance %u%s", inst->cfg.id, VTY_NEWLINE);
	if (inst->cfg.description)
		vty_out(vty, " description %s%s", inst->cfg.description, VTY_NEWLINE);
	if (inst->cfg.network_indicator)
		vty_out(vty, " network-indicator %s%s",
			get_value_string(ss7_network_indicator_vals,
					 inst->cfg.network_indicator),
			VTY_NEWLINE);

	if (inst->cfg.pc_fmt.component_len[0] != 3 ||
	    inst->cfg.pc_fmt.component_len[1] != 8 ||
	    inst->cfg.pc_fmt.component_len[2] != 3) {
		vty_out(vty, " point-code format %u",
			inst->cfg.pc_fmt.component_len[0]);
		if (inst->cfg.pc_fmt.component_len[1])
			vty_out(vty, " %u", inst->cfg.pc_fmt.component_len[1]);
		if (inst->cfg.pc_fmt.component_len[2])
			vty_out(vty, " %u", inst->cfg.pc_fmt.component_len[2]);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (inst->cfg.pc_fmt.delimiter != '.')
		vty_out(vty, " point-code delimiter dash%s", VTY_NEWLINE);

	if (osmo_ss7_pc_is_valid(inst->cfg.primary_pc))
		vty_out(vty, " point-code %s%s",
			osmo_ss7_pointcode_print(inst, inst->cfg.primary_pc),
			VTY_NEWLINE);

	if (inst->cfg.permit_dyn_rkm_alloc)
		vty_out(vty, " xua rkm routing-key-allocation dynamic-permitted%s", VTY_NEWLINE);

	/* first dump ASPs, as ASs reference them */
	llist_for_each_entry(asp, &inst->asp_list, list)
		write_one_asp(vty, asp, show_dyn_config);

	/* then dump ASPs, as routes reference them */
	llist_for_each_entry(as, &inst->as_list, list)
		write_one_as(vty, as, show_dyn_config);

	/* now dump everything that is relevent for the SG role */
	if (cs7_role == CS7_ROLE_SG) {

		/* dump routes, as their target ASs exist */
		llist_for_each_entry(rtable, &inst->rtable_list, list)
			write_one_rtable(vty, rtable);

		llist_for_each_entry(oxs, &inst->xua_servers, list)
			write_one_xua(vty, oxs);
	}

	/* Append SCCP Addressbook */
	write_sccp_addressbook(vty, inst);

	if (inst->sccp)
		osmo_sccp_vty_write_cs7_node(vty, " ", inst->sccp);
}

static bool ipv6_sctp_supported(const char *host, bool bind)
{
	int rc;
	struct addrinfo hints;
	struct addrinfo *result;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_protocol = 0; /* Any protocol */

	if (bind)  /* For wildcard IP address */
		hints.ai_flags |= AI_PASSIVE;

	/* man getaddrinfo: Either node or service, but not both, may be NULL. */
	OSMO_ASSERT(host);
	rc = getaddrinfo(host, NULL, &hints, &result);
	if (rc != 0) {
		LOGP(DLSS7, LOGL_NOTICE, "Default IPv6 address %s not supported: %s\n",
		     host, gai_strerror(rc));
		return false;
	} else {
		freeaddrinfo(result);
		return true;
	}
}

int osmo_ss7_vty_go_parent(struct vty *vty)
{
	struct osmo_ss7_as *as;
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_route_table *rtbl;
	struct osmo_xua_server *oxs;
	struct osmo_sccp_addr_entry *entry;

	switch (vty->node) {
	case L_CS7_ASP_NODE:
		asp = vty->index;
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
			if (ipv6_sctp_supported("::", true) && !(rem_has_v4 && !rem_has_v6))
				osmo_ss7_asp_peer_add_host(&asp->cfg.local, asp, "::");
			else
				osmo_ss7_asp_peer_add_host(&asp->cfg.local, asp, "0.0.0.0");
		}
		/* If no remote addr was set */
		if (!asp->cfg.remote.host_cnt) {
			osmo_ss7_asp_peer_add_host(&asp->cfg.remote, asp, "127.0.0.1");
			if (ipv6_sctp_supported("::1", false))
				osmo_ss7_asp_peer_add_host(&asp->cfg.remote, asp, "::1");
		}
		osmo_ss7_asp_restart(asp);
		vty->node = L_CS7_NODE;
		vty->index = asp->inst;
		break;
	case L_CS7_RTABLE_NODE:
		rtbl = vty->index;
		vty->node = L_CS7_NODE;
		vty->index = rtbl->inst;
		break;
	case L_CS7_AS_NODE:
		as = vty->index;
		vty->node = L_CS7_NODE;
		vty->index = as->inst;
		break;
	case L_CS7_XUA_NODE:
		oxs = vty->index;
		/* If no local addr was set, or erased after _create(): */
		if (!oxs->cfg.local.host_cnt) {
			/* "::" Covers both IPv4 and IPv6 */
			if (ipv6_sctp_supported("::", true))
				osmo_ss7_xua_server_set_local_host(oxs, "::");
			else
				osmo_ss7_xua_server_set_local_host(oxs, "0.0.0.0");
		}
		if (osmo_ss7_xua_server_bind(oxs) < 0)
			vty_out(vty, "%% Unable to bind xUA server to IP(s)%s", VTY_NEWLINE);
		vty->node = L_CS7_NODE;
		vty->index = oxs->inst;
		break;
	case L_CS7_SCCPADDR_NODE:
		entry = vty->index;
		vty->node = L_CS7_NODE;
		vty->index = entry->inst;
		break;
	case L_CS7_SCCPADDR_GT_NODE:
		vty->node = L_CS7_SCCPADDR_NODE;
		vty->index = NULL;
		break;
	case L_CS7_NODE:
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	}
	return 0;
}

int osmo_ss7_is_config_node(struct vty *vty, int node)
{
	switch (node) {
	case L_CS7_NODE:
	case L_CS7_ASP_NODE:
	case L_CS7_RTABLE_NODE:
	case L_CS7_XUA_NODE:
	case L_CS7_AS_NODE:
	case L_CS7_SCCPADDR_NODE:
	case L_CS7_SCCPADDR_GT_NODE:
		return 1;
	default:
		return 0;
	}
}

/* Commands for SCCP-Addressbook */
static void vty_init_addr(void)
{
	install_node(&sccpaddr_node, NULL);
	install_element_ve(&cs7_show_sccpaddr_cmd);
	install_element(L_CS7_NODE, &cs7_sccpaddr_cmd);
	install_element(L_CS7_NODE, &cs7_sccpaddr_del_cmd);
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_pc_del_cmd);
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ssn_del_cmd);
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ip_del_cmd);
#endif
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_gt_del_cmd);
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ri_cmd);
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_pc_cmd);
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ssn_cmd);
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ipv4_cmd);
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ipv6_cmd);
#endif
	install_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_gt_cmd);
	install_node(&sccpaddr_gt_node, NULL);
	install_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_gti_cmd);
	install_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_tt_cmd);
	install_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_npi_cmd);
	install_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_nai_cmd);
	install_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_digits_cmd);
}

static void vty_init_shared(void *ctx)
{
	g_ctx = ctx;

	install_element_ve(&show_cs7_user_cmd);
	install_element_ve(&show_cs7_xua_cmd);
	install_element_ve(&show_cs7_config_cmd);

	/* the mother of all VTY config nodes */
	install_element(CONFIG_NODE, &cs7_instance_cmd);

	install_node(&cs7_node, config_write_cs7);
	install_element(L_CS7_NODE, &cfg_description_cmd);
	install_element(L_CS7_NODE, &cs7_net_ind_cmd);
	install_element(L_CS7_NODE, &cs7_point_code_cmd);
	install_element(L_CS7_NODE, &cs7_pc_format_cmd);
	install_element(L_CS7_NODE, &cs7_pc_format_def_cmd);
	install_element(L_CS7_NODE, &cs7_pc_delimiter_cmd);
	install_element(L_CS7_NODE, &cs7_permit_dyn_rkm_cmd);

	install_node(&asp_node, NULL);
	install_element_ve(&show_cs7_asp_cmd);
	install_element(L_CS7_NODE, &cs7_asp_cmd);
	install_element(L_CS7_NODE, &no_cs7_asp_cmd);
	install_element(L_CS7_ASP_NODE, &cfg_description_cmd);
	install_element(L_CS7_ASP_NODE, &asp_remote_ip_cmd);
	install_element(L_CS7_ASP_NODE, &asp_local_ip_cmd);
	install_element(L_CS7_ASP_NODE, &asp_qos_class_cmd);
	install_element(L_CS7_ASP_NODE, &asp_role_cmd);
	install_element(L_CS7_ASP_NODE, &asp_sctp_role_cmd);
	install_element(L_CS7_ASP_NODE, &asp_block_cmd);
	install_element(L_CS7_ASP_NODE, &asp_shutdown_cmd);

	install_node(&as_node, NULL);
	install_element_ve(&show_cs7_as_cmd);
	install_element(L_CS7_NODE, &cs7_as_cmd);
	install_element(L_CS7_NODE, &no_cs7_as_cmd);
	install_element(L_CS7_AS_NODE, &cfg_description_cmd);
	install_element(L_CS7_AS_NODE, &as_asp_cmd);
	install_element(L_CS7_AS_NODE, &as_no_asp_cmd);
	install_element(L_CS7_AS_NODE, &as_traf_mode_cmd);
	install_element(L_CS7_AS_NODE, &as_no_traf_mode_cmd);
	install_element(L_CS7_AS_NODE, &as_recov_tout_cmd);
	install_element(L_CS7_AS_NODE, &as_qos_class_cmd);
	install_element(L_CS7_AS_NODE, &as_rout_key_cmd);
	install_element(L_CS7_AS_NODE, &as_rout_key_si_cmd);
	install_element(L_CS7_AS_NODE, &as_rout_key_ssn_cmd);
	install_element(L_CS7_AS_NODE, &as_rout_key_si_ssn_cmd);
	install_element(L_CS7_AS_NODE, &as_pc_override_cmd);
	install_element(L_CS7_AS_NODE, &as_pc_patch_sccp_cmd);

	vty_init_addr();
}

void osmo_ss7_vty_init_asp(void *ctx)
{
	cs7_role = CS7_ROLE_ASP;
	vty_init_shared(ctx);
}

void osmo_ss7_vty_init_sg(void *ctx)
{
	cs7_role = CS7_ROLE_SG;
	vty_init_shared(ctx);

	install_node(&rtable_node, NULL);
	install_element_ve(&show_cs7_route_cmd);
	install_element(L_CS7_NODE, &cs7_route_table_cmd);
	install_element(L_CS7_RTABLE_NODE, &cfg_description_cmd);
	install_element(L_CS7_RTABLE_NODE, &cs7_rt_upd_cmd);
	install_element(L_CS7_RTABLE_NODE, &cs7_rt_rem_cmd);

	install_node(&xua_node, NULL);
	install_element(L_CS7_NODE, &cs7_xua_cmd);
	install_element(L_CS7_NODE, &no_cs7_xua_cmd);
	install_element(L_CS7_XUA_NODE, &xua_local_ip_cmd);
	install_element(L_CS7_XUA_NODE, &xua_accept_dyn_asp_cmd);
}
