/* Core SS7 Instance/Linkset/Link/AS/ASP VTY Interface */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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

#include "internal.h"

#define CS7_STR	"ITU-T Signaling System 7\n"
#define PC_STR	"Point Code\n"

/***********************************************************************
 * Core CS7 Configuration
 ***********************************************************************/

static void *g_ctx;

static struct cmd_node cs7_node = {
	L_CS7_NODE,
	"%s(config-cs7)# ",
	1,
};

DEFUN(cs7_instance, cs7_instance_cmd,
	"cs7 instance <0-15>",
	CS7_STR "Configure a SS7 Instance\n"
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
	uint32_t pc = osmo_ss7_pointcode_parse(inst, argv[0]);

	inst->cfg.primary_pc = pc;
	return CMD_SUCCESS;
}
/* TODO: cs7 secondary-pc */
/* TODO: cs7 capability-pc */

static void write_one_cs7(struct vty *vty, struct osmo_ss7_instance *inst);

static int config_write_cs7(struct vty *vty)
{
	struct osmo_ss7_instance *inst;

	llist_for_each_entry(inst, &osmo_ss7_instances, list)
		write_one_cs7(vty, inst);

	return 0;
}

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
	"Specity Priority\n"
	"Priority\n"
	"Specify QoS Class\n"
	"QoS Class\n"
	"Default QoS Class\n")
{
	struct osmo_ss7_route_table *rtable = vty->index;
	struct osmo_ss7_route *rt;
	uint32_t dpc = osmo_ss7_pointcode_parse(rtable->inst, argv[0]);
	uint32_t mask = osmo_ss7_pointcode_parse_mask_or_len(rtable->inst, argv[1]);
	const char *ls_name = argv[2];
	unsigned int argind;

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
	uint32_t dpc = osmo_ss7_pointcode_parse(rtable->inst, argv[0]);
	uint32_t mask = osmo_ss7_pointcode_parse_mask_or_len(rtable->inst, argv[1]);

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
			osmo_ss7_pointcode_print(rtable->inst, rt->cfg.mask),
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
			osmo_ss7_pointcode_print(rtbl->inst, rt->cfg.mask),
			' ', ' ', rt->cfg.priority, rt->cfg.linkset_name, "?", "?", "?", VTY_NEWLINE);
	}
}

DEFUN(show_cs7_route, show_cs7_route_cmd,
	"show cs7 route [instance <0-15>]",
	SHOW_STR CS7_STR "Routing Table\n")
{
	int id = 0;
	struct osmo_ss7_instance *inst;

	if (argc > 0)
		id = atoi(argv[0]);
	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_dump_rtable(vty, inst->rtable_system);
	return CMD_SUCCESS;
}

/***********************************************************************
 * SUA Configuration (SG)
 ***********************************************************************/

static struct cmd_node sua_node = {
	L_CS7_SUA_NODE,
	"%s(config-cs7-sua)# ",
	1,
};

DEFUN(cs7_sua, cs7_sua_cmd,
	"sua <0-65534>",
	"Configure/Enable SUA\n"
	"SCTP Port number for SUA\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	uint16_t port = atoi(argv[0]);

	xs = osmo_ss7_xua_server_find(inst, OSMO_SS7_ASP_PROT_SUA, port);
	if (!xs) {
		xs = osmo_ss7_xua_server_create(inst, OSMO_SS7_ASP_PROT_SUA, port, NULL);
		if (!xs)
			return CMD_SUCCESS;
	}

	vty->node = L_CS7_SUA_NODE;
	vty->index = xs;
	return CMD_SUCCESS;
}

DEFUN(no_cs7_sua, no_cs7_sua_cmd,
	"no sua <0-65534>",
	NO_STR "Disable SUA on given SCTP Port\n"
	"SCTP Port number for SUA\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	uint16_t port = atoi(argv[0]);

	xs = osmo_ss7_xua_server_find(inst, OSMO_SS7_ASP_PROT_SUA, port);
	if (!xs) {
		vty_out(vty, "No SUA server for port %u found%s", port, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_xua_server_destroy(xs);
	return CMD_SUCCESS;
}

DEFUN(sua_local_ip, sua_local_ip_cmd,
	"local-ip A.B.C.D",
	"Configure the Local IP Address for SUA\n"
	"IP Address to use for SUA\n")
{
	struct osmo_xua_server *xs = vty->index;

	osmo_ss7_xua_server_set_local_host(xs, argv[0]);
	return CMD_SUCCESS;
}

enum osmo_ss7_asp_protocol parse_asp_proto(const char *protocol)
{
	return get_string_value(osmo_ss7_asp_protocol_vals, protocol);
}

static void write_one_sua(struct vty *vty, struct osmo_xua_server *xs)
{
	vty_out(vty, " %s %u%s",
		get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto),
		xs->cfg.local.port, VTY_NEWLINE);
	vty_out(vty, "  local-ip %s%s", xs->cfg.local.host, VTY_NEWLINE);
}


/***********************************************************************
 * M3UA Configuration (SG)
 ***********************************************************************/

static struct cmd_node m3ua_node = {
	L_CS7_M3UA_NODE,
	"%s(config-cs7-m3ua)# ",
	1,
};

DEFUN(cs7_m3ua, cs7_m3ua_cmd,
	"m3ua <0-65534>",
	"Configure/Enable M3UA\n"
	"SCTP Port number for M3UA\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	uint16_t port = atoi(argv[0]);

	xs = osmo_ss7_xua_server_find(inst, OSMO_SS7_ASP_PROT_M3UA, port);
	if (!xs) {
		xs = osmo_ss7_xua_server_create(inst, OSMO_SS7_ASP_PROT_M3UA, port, NULL);
		if (!xs)
			return CMD_SUCCESS;
	}

	vty->node = L_CS7_M3UA_NODE;
	vty->index = xs;
	return CMD_SUCCESS;
}

DEFUN(no_cs7_m3ua, no_cs7_m3ua_cmd,
	"no m3ua <0-65534>",
	NO_STR "Disable M3UA on given SCTP Port\n"
	"SCTP Port number for M3UA\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	uint16_t port = atoi(argv[0]);

	xs = osmo_ss7_xua_server_find(inst, OSMO_SS7_ASP_PROT_M3UA, port);
	if (!xs) {
		vty_out(vty, "No M3UA server for port %u found%s", port, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_xua_server_destroy(xs);
	return CMD_SUCCESS;
}

DEFUN(m3ua_local_ip, m3ua_local_ip_cmd,
	"local-ip A.B.C.D",
	"Configure the Local IP Address for M3UA\n"
	"IP Address to use for M3UA\n")
{
	struct osmo_xua_server *xs = vty->index;

	osmo_ss7_xua_server_set_local_host(xs, argv[0]);
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
	"asp NAME <0-65535> <0-65535> (m3ua|sua)",
	"Configure Application Server Process\n"
	"Name of ASP\n"
	"Remote SCTP port number\n"
	"Local SCTP port number\n"
	"M3UA Protocol\n"
	"SUA Protocol\n")
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

	asp = osmo_ss7_asp_find_or_create(inst, name, remote_port, local_port, protocol);
	if (!asp) {
		vty_out(vty, "cannot create ASP '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	asp->cfg.is_server = true;

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

DEFUN(asp_remote_ip, asp_remote_ip_cmd,
	"remote-ip A.B.C.D",
	"Specify Remote IP Address of ASP\n"
	"Remote IP Address of ASP\n")
{
	struct osmo_ss7_asp *asp = vty->index;
	osmo_talloc_replace_string(asp, &asp->cfg.remote.host, argv[0]);
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
	"show cs7 asp [instance <0-15>]",
	SHOW_STR CS7_STR "Application Server Process (ASP)\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_asp *asp;
	int id = 0;

	if (argc > 0)
		id = atoi(argv[0]);
	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "                                                     Effect Primary%s", VTY_NEWLINE);
	vty_out(vty, "ASP Name      AS Name       State     Type  Rmt Port Remote IP Addr  SCTP%s", VTY_NEWLINE);
	vty_out(vty, "------------  ------------  --------  ----  -------- --------------- ----------%s", VTY_NEWLINE);

	llist_for_each_entry(asp, &inst->asp_list, list) {
		vty_out(vty, "%-12s  %-12s  %-8s  %-4s  %-8u %-15s %-10s%s",
			asp->cfg.name, "?", "?",
			get_value_string(osmo_ss7_asp_protocol_vals, asp->cfg.proto),
			asp->cfg.remote.port, asp->cfg.remote.host, "", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static void write_one_asp(struct vty *vty, struct osmo_ss7_asp *asp)
{
	vty_out(vty, " asp %s %u %u %s%s",
		asp->cfg.name, asp->cfg.remote.port, asp->cfg.local.port,
		osmo_ss7_asp_protocol_name(asp->cfg.proto), VTY_NEWLINE);
	if (asp->cfg.description)
		vty_out(vty, "  description %s%s", asp->cfg.description, VTY_NEWLINE);
	vty_out(vty, "  remote-ip %s%s", asp->cfg.remote.host, VTY_NEWLINE);
	if (asp->cfg.qos_class)
		vty_out(vty, "  qos-class %u%s", asp->cfg.qos_class, VTY_NEWLINE);
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
	"as NAME (m3ua|sua)",
	"Configure an Application Server\n"
	"Name of the Application Server\n"
	"M3UA Application Server\n"
	"SUA Application Server\n")
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_ss7_as *as;
	const char *name = argv[0];
	enum osmo_ss7_asp_protocol protocol = parse_asp_proto(argv[1]);

	if (protocol == OSMO_SS7_ASP_PROT_NONE) {
		vty_out(vty, "invalid protocol '%s'%s", argv[3], VTY_NEWLINE);
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

DEFUN(as_rout_key, as_rout_key_cmd,
	"routing-key RCONTEXT DPC [si (aal2|bicc|b-isup|h248|isup|sat-isup|sccp|tup)] [ssn SSN]}",
	"Define a routing key\n"
	"Routing context number\n"
	"Destination Point Code\n"
	"Optional Match on Service Indicator\n"
	"ATM Adaption Layer 2\n"
	"Bearer Independent Call Control\n"
	"Broadband ISDN User Part\n"
	"H.248\n"
	"ISDN User Part\n"
	"Sattelite ISDN User Part\n"
	"Signalling Connection Control Part\n"
	"Telephony User Part\n"
	"Optional Match on Sub-System Number\n"
	"Sub-System Number to match on\n")
{
	struct osmo_ss7_as *as = vty->index;
	struct osmo_ss7_routing_key *rkey = &as->cfg.routing_key;
	int argind;

	rkey->context = atoi(argv[0]);
	rkey->pc = osmo_ss7_pointcode_parse(as->inst, argv[1]);
	argind = 2;

	if (argind < argc && !strcmp(argv[argind], "si")) {
		const char *si_str;
		argind++;
		si_str = argv[argind++];
		/* parse numeric SI from string */
		rkey->si = get_string_value(mtp_si_vals, si_str);
	}
	if (argind < argc && !strcmp(argv[argind], "ssn")) {
		argind++;
		rkey->ssn = atoi(argv[argind]);
	}

	return CMD_SUCCESS;
}

static void write_one_as(struct vty *vty, struct osmo_ss7_as *as)
{
	struct osmo_ss7_routing_key *rkey;
	unsigned int i;

	vty_out(vty, " as %s %s%s", as->cfg.name,
		osmo_ss7_asp_protocol_name(as->cfg.proto), VTY_NEWLINE);
	if (as->cfg.description)
		vty_out(vty, "  description %s%s", as->cfg.description, VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;
		vty_out(vty, "  asp %s%s", asp->cfg.name, VTY_NEWLINE);
	}
	if (as->cfg.mode != OSMO_SS7_AS_TMOD_LOADSHARE)
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
}

DEFUN(show_cs7_as, show_cs7_as_cmd,
	"show cs7 as (active|all|m3ua|sua) [instance <0-15>]",
	SHOW_STR CS7_STR "Application Server (AS)\n"
	"Display all active ASs\n"
	"Display all ASs (default)\n"
	"Display all m3ua ASs\n"
	"Display all SUA ASs\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_as *as;
	const char *filter = NULL;
	int id = 0;

	if (argc)
		filter = argv[0];

	if (argc > 1)
		id = atoi(argv[1]);
	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "                    Routing    Routing Key                          Cic   Cic%s", VTY_NEWLINE);
	vty_out(vty, "AS Name      State  Context    Dpc           Si   Opc           Ssn Min   Max%s", VTY_NEWLINE);
	vty_out(vty, "------------ ------ ---------- ------------- ---- ------------- --- ----- -----%s", VTY_NEWLINE);

	llist_for_each_entry(as, &inst->as_list, list) {
		if (filter && !strcmp(filter, "m3ua") && as->cfg.proto != OSMO_SS7_ASP_PROT_M3UA)
			continue;
		if (filter && !strcmp(filter, "sua") && as->cfg.proto != OSMO_SS7_ASP_PROT_SUA)
			continue;
		/* FIXME: active filter */
		vty_out(vty, "%-12s %-6s %-10u %-13s %4s %13s %3s %5s %4s%s",
			as->cfg.name, "fixme", as->cfg.routing_key.context,
			osmo_ss7_pointcode_print(as->inst, as->cfg.routing_key.pc),
			"", "", "", "", "", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static void write_one_cs7(struct vty *vty, struct osmo_ss7_instance *inst)
{
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route_table *rtable;
	struct osmo_xua_server *oxs;

	vty_out(vty, "cs7 instance %u%s", inst->cfg.id, VTY_NEWLINE);
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

	if (inst->cfg.primary_pc)
		vty_out(vty, " point-code %s%s",
			osmo_ss7_pointcode_print(inst, inst->cfg.primary_pc),
			VTY_NEWLINE);

	/* first dump ASPs, as ASs reference them */
	llist_for_each_entry(asp, &inst->asp_list, list)
		write_one_asp(vty, asp);

	/* then dump ASPs, as routes reference them */
	llist_for_each_entry(as, &inst->as_list, list)
		write_one_as(vty, as);

	/* now dump routes, as their target ASs exist */
	llist_for_each_entry(rtable, &inst->rtable_list, list)
		write_one_rtable(vty, rtable);

	llist_for_each_entry(oxs, &osmo_ss7_xua_servers, list)
		write_one_sua(vty, oxs);
}


int osmo_ss7_vty_go_parent(struct vty *vty)
{
	struct osmo_ss7_as *as;
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_route_table *rtbl;
	struct osmo_xua_server *oxs;

	switch (vty->node) {
	case L_CS7_ASP_NODE:
		asp = vty->index;
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
	case L_CS7_SUA_NODE:
	case L_CS7_M3UA_NODE:
		oxs = vty->index;
		vty->node = L_CS7_NODE;
		vty->index = oxs->inst;
		break;
	case L_CS7_NODE:
	default:
		vty->node = CONFIG_NODE;
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
	case L_CS7_SUA_NODE:
	case L_CS7_M3UA_NODE:
	case L_CS7_AS_NODE:
		return 1;
	default:
		return 0;
	}
}

static void vty_init_shared(void)
{
	/* the mother of all VTY config nodes */
	install_element(CONFIG_NODE, &cs7_instance_cmd);

	install_node(&cs7_node, config_write_cs7);
	vty_install_default(L_CS7_NODE);
	install_element(L_CS7_NODE, &cs7_net_ind_cmd);
	install_element(L_CS7_NODE, &cs7_point_code_cmd);
	install_element(L_CS7_NODE, &cs7_pc_format_cmd);
	install_element(L_CS7_NODE, &cs7_pc_format_def_cmd);
	install_element(L_CS7_NODE, &cs7_pc_delimiter_cmd);

	install_node(&asp_node, NULL);
	vty_install_default(L_CS7_ASP_NODE);
	install_element_ve(&show_cs7_asp_cmd);
	install_element(L_CS7_NODE, &cs7_asp_cmd);
	install_element(L_CS7_NODE, &no_cs7_asp_cmd);
	install_element(L_CS7_ASP_NODE, &cfg_description_cmd);
	install_element(L_CS7_ASP_NODE, &asp_remote_ip_cmd);
	install_element(L_CS7_ASP_NODE, &asp_qos_class_cmd);
	install_element(L_CS7_ASP_NODE, &asp_block_cmd);
	install_element(L_CS7_ASP_NODE, &asp_shutdown_cmd);

	install_node(&as_node, NULL);
	vty_install_default(L_CS7_AS_NODE);
	install_element_ve(&show_cs7_as_cmd);
	install_element(L_CS7_NODE, &cs7_as_cmd);
	install_element(L_CS7_NODE, &no_cs7_as_cmd);
	install_element(L_CS7_AS_NODE, &cfg_description_cmd);
	install_element(L_CS7_AS_NODE, &as_asp_cmd);
	install_element(L_CS7_AS_NODE, &as_no_asp_cmd);
	install_element(L_CS7_AS_NODE, &as_traf_mode_cmd);
	install_element(L_CS7_AS_NODE, &as_recov_tout_cmd);
	install_element(L_CS7_AS_NODE, &as_qos_class_cmd);
	install_element(L_CS7_AS_NODE, &as_rout_key_cmd);
}

void osmo_ss7_vty_init_asp(void)
{
	vty_init_shared();
}

void osmo_ss7_vty_init_sg(void)
{
	vty_init_shared();

	install_node(&rtable_node, NULL);
	vty_install_default(L_CS7_RTABLE_NODE);
	install_element_ve(&show_cs7_route_cmd);
	install_element(L_CS7_NODE, &cs7_route_table_cmd);
	install_element(L_CS7_RTABLE_NODE, &cfg_description_cmd);
	install_element(L_CS7_RTABLE_NODE, &cs7_rt_upd_cmd);
	install_element(L_CS7_RTABLE_NODE, &cs7_rt_rem_cmd);

	install_node(&sua_node, NULL);
	vty_install_default(L_CS7_SUA_NODE);
	install_element(L_CS7_NODE, &cs7_sua_cmd);
	install_element(L_CS7_NODE, &no_cs7_sua_cmd);
	install_element(L_CS7_SUA_NODE, &sua_local_ip_cmd);

	install_node(&m3ua_node, NULL);
	vty_install_default(L_CS7_M3UA_NODE);
	install_element(L_CS7_NODE, &cs7_m3ua_cmd);
	install_element(L_CS7_NODE, &no_cs7_m3ua_cmd);
	install_element(L_CS7_M3UA_NODE, &m3ua_local_ip_cmd);
}

void osmo_ss7_set_vty_alloc_ctx(void *ctx)
{
	g_ctx = ctx;
};
