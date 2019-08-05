/* Osmocom STP (Signal Transfer Point) */

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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/select.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

static void *tall_stp_ctx;

/* we only use logging sub-systems of the various libraries so far */
static const struct log_info_cat log_info_cat[] = {
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

static const char stp_copyright[] =
	"Copyright (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>\r\n"
	"Contributions by Holger Freyther, Neels Hofmeyr\r\n"
	"License GPLv2+: GNU GPL Version 2 or later <http://gnu.org/licenses/gpl-2.0.html>\r\n"
	"This is free software: you are free ot change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n\r\n"
	"Free Software lives by contribution.  If you use this, please contribute!\r\n";

static struct vty_app_info vty_info = {
	.name	= "OsmoSTP",
	.copyright = stp_copyright,
	.version = PACKAGE_VERSION,
	.go_parent_cb = osmo_ss7_vty_go_parent,
	.is_config_node = osmo_ss7_is_config_node,
};

static struct {
	bool daemonize;
	const char *config_file;
} cmdline_config = {
	.daemonize = false,
	.config_file = "osmo-stp.cfg",
};

static void print_help(void)
{
	printf("  -h --help			This text.\n");
	printf("  -D --daemonize		Fork the process into a background daemon\n");
	printf("  -c --config-file filename	The config file to use. Default: ./osmo-stp.cfg\n");
	printf("  -V --version			Print the version of OsmoSTP\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ NULL, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hDc:V", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'D':
			cmdline_config.daemonize = true;
			break;
		case 'c':
			cmdline_config.config_file = optarg;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			fprintf(stderr, "Error in command line options. Exiting\n");
			exit(1);
			break;
		}
	}
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		/* FIXME: handle the signal somewhere else and gracefully shut down
		 * SIGTRAN links
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1); */
		exit(0);
		break;
	case SIGABRT:
		osmo_generate_backtrace();
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_stp_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

int main(int argc, char **argv)
{
	int rc;

	tall_stp_ctx = talloc_named_const(NULL, 1, "osmo-stp");
	msgb_talloc_ctx_init(tall_stp_ctx, 0);
	osmo_init_logging2(tall_stp_ctx, &log_info);
	osmo_stats_init(tall_stp_ctx);

	vty_info.tall_ctx = tall_stp_ctx;
	vty_init(&vty_info);

	handle_options(argc, argv);

	fputs(stp_copyright, stdout);
	fputs("\n", stdout);

	osmo_ss7_init();
	osmo_fsm_log_addr(false);
	logging_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_ss7_vty_init_sg(tall_stp_ctx);
	osmo_sccp_vty_init();
	osmo_fsm_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	rc = vty_read_config_file(cmdline_config.config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file '%s'\n",
			cmdline_config.config_file);
		exit(1);
	}

	osmo_ss7_bind_all_instances();

	rc = telnet_init_dynif(tall_stp_ctx, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_STP);
	if (rc < 0) {
		perror("Error binding VTY port\n");
		exit(1);
	}

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	if (cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}
}
