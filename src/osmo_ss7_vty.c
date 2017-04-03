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

#define CS7_STR	"ITU-T Signaling System 7\n"
#define PC_STR	"Point Code\n"

/***********************************************************************
 * Core CS7 Configuration
 ***********************************************************************/

static const struct value_string ss7_network_indicator_vals[] = {
	{ 0,	"international" },
	{ 1,	"spare" },
	{ 2,	"national" },
	{ 3,	"reserved" },
	{ 0,	NULL }
};

/* cs7 network-indicator */
DEFUN(cs7_net_ind, cs7_net_ind_cmd,
	"cs7 network-indicator (international | national | reserved | spare)",
	CS7_STR "Configure the Network Indicator\n"
	"International Network\n"
	"National Network\n"
	"Reserved Network\n"
	"Spare Network\n")
{
	struct osmo_ss7_instance *inst = FIXME;
	int ni = get_string_value(ss7_network_indicator_vals, argv[0]);

	inst->cfg.network_indicator = ni;
	return CMD_SUCCESS;
}

/* TODO: cs7 point-code format */
DEFUN(cs7_pc_format, cs7_pc_format_cmd,
	"cs7 point-code format <1-24> [<1-23> [<1-22>]]",
	CS7_STR PC_STR "Configure Point Code Format\n"
	"Length of first PC component\n"
	"Length of second PC component\n"
	"Length of third PC component\n")
{
	struct osmo_ss7_instance *inst = FIXME;
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
	"cs7 point-code format default",
	CS7_STR PC_STR "Configure Point Code Format\n"
	"Default Point Code Format (3.8.3)\n")
{
	struct osmo_ss7_instance *inst = FIXME;
	inst->cfg.pc_fmt.component_len[0] = 3;
	inst->cfg.pc_fmt.component_len[1] = 8;
	inst->cfg.pc_fmt.component_len[2] = 3;
	return CMD_SUCCESS;
}


/* cs7 point-code delimiter */
DEFUN(cs7_pc_delimiter, cs7_pc_delimiter_cmd,
	"cs7 point-code delimiter (default|dash)",
	CS7_STR PC_STR "Configure Point Code Delimiter\n"
	"Use dot as delimiter\n"
	"User dash as delimiter\n")
{
	struct osmo_ss7_instance *inst = FIXME;

	if (!strcmp(argv[0], "dash"))
		inst->cfg.pc_fmt.delimiter = '-';
	else
		inst->cfg.pc_fmt.delimiter = '.';

	return CMD_SUCCESS;
}

DEFUN(cs7_point_code, cs7_point_code_cmd,
	"cs7 point-code POINT_CODE",
	CS7_STR "Configure the local Point Code\n"
	"Point Code\n")
{
	struct osmo_ss7_instance *inst = FIXME;
	uint32_t pc = osmo_ss7_pointcode_parse(inst, argv[0]);

	inst->cfg.primary_pc = pc;
	return CMD_SUCCESS;
}
/* TODO: cs7 secondary-pc */
/* TODO: cs7 capability-pc */


/***********************************************************************
 * Routing Table Configuration
 ***********************************************************************/

static struct cmd_node rtable_node = {
	L_CS7_RTABLE_NODE,
	"%s(config-cs7-rt)# ",
	1,
};

DEFUN(cs7_route_table, cs7_route_table_cmd,
	"cs7 route-table system",
	CS7_STR "Specify the name of the route table\n"
	"Name of the route table\n")
{
	struct osmo_ss7_instance *inst = FIXME;
	struct osmo_ss7_route_table *rtable;

	rtable = inst->rtable_system;
	vty->node = L_CS7_RTABLE_NODE;
	vty->index = rtable;
	vty->index_sub = &rtable->cfg.description;

	return CMD_SUCCESS;
}

DEFUN(cs7_rt_upd, cs7_rt_upd_cmd,
	"update route POINT_CODE [MASK | LENGTH] linkset LS_NAME [priority PRIO] [qos-class (CLASS | default",
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
	if (!rt)
		return CMD_WARNING;

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
	"remove route POINT_CODE [MASK | LENGTH]",
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
	if (!rt)
		return CMD_WARNING;

	osmo_ss7_route_destroy(rt);
	return CMD_SUCCESS;
}

static int config_write_rtable(struct vty *vty)
{
	struct osmo_ss7_route_table *rtable = vty->index;
	struct osmo_ss7_route *rt;

	vty_out(vty, "cs7 route-table %s%s", rtable->cfg.name, VTY_NEWLINE);
	llist_for_each_entry(rt, &rtable->routes, list) {
		vty_out(vty, " update route %s %s linkset %s",
			osmo_ss7_pointcode_print(rtable->inst, rt->cfg.pc),
			osmo_ss7_pointcode_print(rtable->inst, rt->cfg.mask),
			rt->cfg.linkset_name);
		if (rt->cfg.priority)
			vty_out(vty, " priority %u", rt->cfg.priority);
		if (rt->cfg.qos_class)
			vty_out(vty, " qos-class %u", rt->cfg.qos_class);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	return 0;
}

/***********************************************************************
 * SUA Configuration
 ***********************************************************************/

static struct cmd_node sua_node = {
	L_CS7_SUA_NODE,
	"%s(config-cs7-sua)# ",
	1,
};

DEFUN(cs7_sua, cs7_sua_cmd,
	"cs7 sua <0-65534>",
	CS7_STR
	"Configure/Enable SUA\n"
	"SCTP Port number for SUA\n")
{
	struct osmo_ss7_instance *inst = FIXME;
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

static int config_write_sua(struct vty *vty)
{
	struct osmo_xua_server *xs = vty->index;

	vty_out(vty, "cs7 sua %u%s", xs->cfg.local.port, VTY_NEWLINE);
	vty_out(vty, " local-ip %s%s", xs->cfg.local.host, VTY_NEWLINE);
	return 0;
}

/***********************************************************************
 * M3UA Configuration
 ***********************************************************************/

static struct cmd_node m3ua_node = {
	L_CS7_M3UA_NODE,
	"%s(config-cs7-m3ua)# ",
	1,
};

DEFUN(cs7_m3ua, cs7_m3ua_cmd,
	"cs7 m3ua <0-65534>",
	CS7_STR
	"Configure/Enable M3UA\n"
	"SCTP Port number for M3UA\n")
{
	struct osmo_ss7_instance *inst = FIXME;
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

DEFUN(m3ua_local_ip, m3ua_local_ip_cmd,
	"local-ip A.B.C.D",
	"Configure the Local IP Address for M3UA\n"
	"IP Address to use for M3UA\n")
{
	struct osmo_xua_server *xs = vty->index;

	osmo_ss7_xua_server_set_local_host(xs, argv[0]);
	return CMD_SUCCESS;
}

static int config_write_m3ua(struct vty *vty)
{
	struct osmo_xua_server *xs = vty->index;

	vty_out(vty, "cs7 m3ua %u%s", xs->cfg.local.port, VTY_NEWLINE);
	vty_out(vty, " local-ip %s%s", xs->cfg.local.host, VTY_NEWLINE);
	return 0;
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
	"cs7 asp NAME <0-65535> <0-65535> [m3ua | sua]",
	CS7_STR
	"Configure Application Server Process\n"
	"Name of ASP\n"
	"Remote SCTP port number\n"
	"Local SCTP port number\n"
	"M3UA Protocol\n"
	"SUA Protocol\n")
{
	struct osmo_ss7_instance *inst = FIXME;
	const char *name = argv[0];
	uint16_t remote_port = atoi(argv[1]);
	uint16_t local_port = atoi(argv[2]);
	enum osmo_ss7_asp_protocol protocol = parse_asp_proto(argv[3]);
	struct osmo_ss7_asp *asp;

	if (protocol == OSMO_SS7_ASP_PROT_NONE)
		return CMD_WARNING;

	asp = osmo_ss7_asp_find_or_create(inst, name, remote_port, local_port, protocol);
	if (!asp)
		return CMD_WARNING;

	vty->node = L_CS7_ASP_NODE;
	vty->index = asp;
	vty->index_sub = &asp->cfg.description;
	return CMD_SUCCESS;
}

DEFUN(asp_remote_ip, asp_remote_ip_cmd,
	"remote-ip A.B.C.D",
	"Specity Remote IP Address of ASP\n"
	"Remote IP Address of ASP\n")
{
	struct osmo_ss7_asp *asp = vty->index;
	osmo_talloc_replace_string(asp, &asp->cfg.remote.host, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(asp_qos_clas, asp_qos_class_cmd,
	"qos-class <0-255>",
	"Specity QoS Class of ASP\n"
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
	struct osmo_ss7_asp *asp = vty->index;
	vty_out(vty, "Not supported yet\n");
	return CMD_WARNING;
}

DEFUN(asp_shutdown, asp_shutdown_cmd,
	"shutdown",
	"Terminates SCTP association; New associations will be rejected\n")
{
	struct osmo_ss7_asp *asp = vty->index;
	vty_out(vty, "Not supported yet\n");
	return CMD_WARNING;
}

static int config_write_asp(struct vty *vty)
{
	struct osmo_ss7_asp *asp = vty->index;

	vty_out(vty, "cs7 asp %s %u %u %s%s",
		asp->cfg.name, asp->cfg.remote.port, asp->cfg.local.port,
		osmo_ss7_asp_protocol_name(asp->cfg.proto), VTY_NEWLINE);
	vty_out(vty, " remote-ip %s%s", asp->cfg.remote.host, VTY_NEWLINE);
	if (asp->cfg.qos_class)
		vty_out(vty, " qos-class %u%s", asp->cfg.qos_class, VTY_NEWLINE);
	return 0;
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
	"cs7 as NAME [m3ua | sua]",
	CS7_STR
	"Configure an Application Server\n"
	"Name of the Application Server\n"
	"M3UA Application Server\n"
	"SUA Application Server\n")
{
	struct osmo_ss7_as *as;
	const char *name = argv[0];
	enum osmo_ss7_asp_protocol protocol = parse_asp_proto(argv[1]);

	if (protocol == OSMO_SS7_ASP_PROT_NONE)
		return CMD_WARNING;

	/* FIXME */
	as->cfg.name = talloc_strdup(as, name);

	vty->node = L_CS7_AS_NODE;
	vty->index = as;
	vty->index_sub = &as->cfg.description;

	return CMD_SUCCESS;
}

/* TODO: routing-key */
DEFUN(as_asp, as_asp_cmd,
	"asp NAME",
	"Specify that a given ASP is part of this AS\n"
	"Name of ASP to be added to AS\n")
{
	struct osmo_ss7_as *as = vty->index;

	if (osmo_ss7_as_add_asp(as, argv[0]))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(as_no_asp, as_no_asp_cmd,
	"no asp NAME",
	NO_STR "Specify ASP to be removed from this AS\n"
	"Name of ASP to be removed\n")
{
	struct osmo_ss7_as *as = vty->index;

	if (osmo_ss7_as_del_asp(as, argv[0]))
		return CMD_WARNING;

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
	return CMD_WARNING;
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
	"routing-key RCONTEXT DPC [si {aal2 | bicc | b-isup | h248 | isup | sat-isup | sccp | tup }] [ssn SSN]}",
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
	uint32_t key = atoi(argv[0]);
	struct osmo_ss7_routing_key *rkey;
	int argind;

	rkey = osmo_ss7_rkey_find_or_create(as, key);
	if (!rkey)
		return CMD_WARNING;

	rkey->pc = osmo_ss7_pointcode_parse(as->inst, argv[1]);
	argind = 2;

	if (!strcmp(argv[argind], "si")) {
		const char *si_str;
		argind++;
		si_str = argv[argind++];
		/* parse numeric SI from string */
		rkey->si = get_string_value(mtp_si_vals, si_str);
	}
	if (!strcmp(argv[argind], "ssn")) {
		argind++;
		rkey->ssn = atoi(argv[argind]);
	}

	return CMD_SUCCESS;
}

static int config_write_as(struct vty *vty)
{
	struct osmo_ss7_as *as = vty->index;
	struct osmo_ss7_routing_key *rkey;
	unsigned int i;

	vty_out(vty, "cs7 as %s %s%s", as->cfg.name,
		osmo_ss7_asp_protocol_name(as->cfg.proto), VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;
		vty_out(vty, " asp %s%s", asp->cfg.name, VTY_NEWLINE);
	}
	if (as->cfg.mode != OSMO_SS7_AS_TMOD_LOADSHARE)
		vty_out(vty, " traffic-mode %s%s",
			osmo_ss7_as_traffic_mode_name(as->cfg.mode), VTY_NEWLINE);
	if (as->cfg.recovery_timeout_msec != 2000) {
		vty_out(vty, " recovery-timeout %u%s",
			as->cfg.recovery_timeout_msec, VTY_NEWLINE);
	}
	vty_out(vty, " qos-class %u%s", as->cfg.qos_class, VTY_NEWLINE);
	rkey = &as->cfg.routing_key;
	vty_out(vty, " routing-key %u %s", rkey->context,
		osmo_ss7_pointcode_print(as->inst, rkey->pc));
	if (rkey->si)
		vty_out(vty, " si %s",
			get_value_string(mtp_si_vals, rkey->si));
	if (rkey->ssn)
		vty_out(vty, " ssn %u", rkey->ssn);
	vty_out(vty, "%s", VTY_NEWLINE);

	return 0;
}

int osmo_ss7_vty_init(void)
{
	install_element(CONFIG_NODE, &cs7_net_ind_cmd);
	install_element(CONFIG_NODE, &cs7_point_code_cmd);
	install_element(CONFIG_NODE, &cs7_pc_format_cmd);
	install_element(CONFIG_NODE, &cs7_pc_format_def_cmd);
	install_element(CONFIG_NODE, &cs7_pc_delimiter_cmd);

	install_node(&rtable_node, config_write_rtable);
	vty_install_default(L_CS7_RTABLE_NODE);
	install_element(CONFIG_NODE, &cs7_route_table_cmd);
	install_element(L_CS7_RTABLE_NODE, &cfg_description_cmd);
	install_element(L_CS7_RTABLE_NODE, &cs7_rt_upd_cmd);
	install_element(L_CS7_RTABLE_NODE, &cs7_rt_rem_cmd);

	install_node(&sua_node, config_write_sua);
	vty_install_default(L_CS7_SUA_NODE);
	install_element(CONFIG_NODE, &cs7_sua_cmd);
	install_element(L_CS7_SUA_NODE, &sua_local_ip_cmd);

	install_node(&m3ua_node, config_write_m3ua);
	vty_install_default(L_CS7_M3UA_NODE);
	install_element(CONFIG_NODE, &cs7_m3ua_cmd);
	install_element(L_CS7_M3UA_NODE, &m3ua_local_ip_cmd);

	install_node(&asp_node, config_write_asp);
	vty_install_default(L_CS7_ASP_NODE);
	install_element(CONFIG_NODE, &cs7_asp_cmd);
	install_element(L_CS7_ASP_NODE, &cfg_description_cmd);
	install_element(L_CS7_ASP_NODE, &asp_remote_ip_cmd);
	install_element(L_CS7_ASP_NODE, &asp_qos_class_cmd);
	install_element(L_CS7_ASP_NODE, &asp_block_cmd);
	install_element(L_CS7_ASP_NODE, &asp_shutdown_cmd);

	install_node(&as_node, config_write_as);
	vty_install_default(L_CS7_AS_NODE);
	install_element(CONFIG_NODE, &cs7_as_cmd);
	install_element(L_CS7_AS_NODE, &cfg_description_cmd);
	install_element(L_CS7_AS_NODE, &as_asp_cmd);
	install_element(L_CS7_AS_NODE, &as_no_asp_cmd);
	install_element(L_CS7_AS_NODE, &as_traf_mode_cmd);
	install_element(L_CS7_AS_NODE, &as_recov_tout_cmd);
	install_element(L_CS7_AS_NODE, &as_qos_class_cmd);
	install_element(L_CS7_AS_NODE, &as_rout_key_cmd);

	return 0;
}
