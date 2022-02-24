
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "internal.h"

static const char *config_file;

static struct osmo_sccp_instance *g_sccp;

static struct osmo_sccp_instance *sua_server_helper(enum osmo_ss7_asp_protocol protocol,
						    int local_port, const char *local_address, int local_pc,
						    int remote_port, const char *remote_address, int remote_pc)
{
	struct osmo_sccp_instance *sccp;

	sccp = osmo_sccp_simple_server(NULL, local_pc, protocol, local_port, local_address);
	if (sccp == NULL)
		return NULL;

	osmo_sccp_simple_server_add_clnt(sccp, protocol, "client", remote_pc, local_port,
					 remote_port, remote_address);

	return sccp;
}

/***********************************************************************
 * Initialization
 ***********************************************************************/

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %d received\n", signal);

	switch (signal) {
	case SIGUSR1:
		talloc_report_full(osmo_sccp_get_ss7(g_sccp), stderr);
		break;
	case SIGUSR2:
		talloc_report_full(NULL, stderr);
		break;
	}
}

static const struct log_info_cat log_info_cat[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "sccp_demo_user specific logging",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

static void init_logging(void *tall_ctx)
{
	const int log_cats[] = { DLSS7, DLSUA, DLM3UA, DLSCCP, DLINP };
	unsigned int i;
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &log_info);
	log_set_print_category(osmo_stderr_target, true);
	log_set_print_category_hex(osmo_stderr_target, false);

	for (i = 0; i < ARRAY_SIZE(log_cats); i++)
		log_set_category_filter(osmo_stderr_target, log_cats[i], 1, LOGL_DEBUG);
}

static struct vty_app_info vty_info = {
	.name	= "SccpDemoUser",
	.version = 0,
};

#define DEFAULT_LOCAL_ADDRESS_SERVER	"127.0.0.1"
#define DEFAULT_LOCAL_ADDRESS_CLIENT	"127.0.0.2"
#define DEFAULT_REMOTE_ADDRESS_CLIENT	DEFAULT_LOCAL_ADDRESS_SERVER
#define DEFAULT_REMOTE_ADDRESS_SERVER	DEFAULT_LOCAL_ADDRESS_CLIENT
#define DEFAULT_LOCAL_PORT_SERVER	M3UA_PORT
#define DEFAULT_LOCAL_PORT_CLIENT	M3UA_PORT
#define DEFAULT_REMOTE_PORT_CLIENT	DEFAULT_LOCAL_PORT_SERVER
#define DEFAULT_REMOTE_PORT_SERVER	DEFAULT_LOCAL_PORT_CLIENT
#define DEFAULT_REMOTE_PORT_SERVER_STR	DEFAULT_LOCAL_PORT_CLIENT_STR
#define DEFAULT_PC_SERVER	1
#define DEFAULT_PC_CLIENT	23

static void usage(void) {
	fprintf(stderr, "sccp_demo_user [-c] [-l LOCAL_ADDRESS[:LOCAL_PORT]]\n"
			"             [-r REMOTE_ADDRESS[:REMOTE_PORT]]\n"
			"             [-L LOCAL_POINT_CODE] [-R REMOTE_POINT_CODE]\n"
			"Options:\n"
			"  -p: protocol to use (m3ua, sua, ipa; default is ipa)\n"
			"  -c: Run in client mode (default is server mode)\n"
			"  -l: local IP address and SCTP port (default is %s:%d in server mode,\n"
			"                                       %s:%d in client mode)\n"
			"  -r: remote IP address and SCTP port (default is %s:%d in server mode,\n"
			"                                       %s:%d in client mode)\n"
			"  -L: local point code (default is %d in server mode, %d in client mode)\n"
			"  -R: remote point code (default is %d in server mode, %d in client mode)\n",
			DEFAULT_LOCAL_ADDRESS_SERVER, DEFAULT_LOCAL_PORT_SERVER,
			DEFAULT_LOCAL_ADDRESS_CLIENT, DEFAULT_LOCAL_PORT_CLIENT,
			DEFAULT_REMOTE_ADDRESS_SERVER, DEFAULT_REMOTE_PORT_SERVER,
			DEFAULT_REMOTE_ADDRESS_CLIENT, DEFAULT_REMOTE_PORT_CLIENT,
			DEFAULT_PC_SERVER, DEFAULT_PC_CLIENT,
			DEFAULT_PC_CLIENT, DEFAULT_PC_SERVER);
	exit(1);
}

static int is_decimal_string(const char *s)
{
	const char *p = s;

	if (*p == '\0')
		return 0;

	while (*p) {
		if (!isdigit(*p++))
			return 0;
	}
	return 1;
}

static int parse_address_port(char **address, int *port, const char *arg)
{
	char *s, *colon;

	s = strdup(arg);
	OSMO_ASSERT(s);

	colon = strrchr(s, ':');
	if (colon) {
		char *portstr = colon + 1;
		*colon = '\0';
		if (*portstr == '\0') {
			fprintf(stderr, "missing port number after : in '%s'\n", arg);
			free(s);
			return 1;
		}
		if (!is_decimal_string(portstr)) {
			fprintf(stderr, "invalid port number: '%s'\n", portstr);
			free(s);
			return 1;
		}
		*port = atoi(portstr);
	}

	*address = s;
	return 0;
}

int main(int argc, char **argv)
{
	bool client = false;
	int rc, ch;
	char *local_address = DEFAULT_LOCAL_ADDRESS_SERVER;
	int local_port = DEFAULT_LOCAL_PORT_SERVER;
	int local_pc = DEFAULT_PC_SERVER;
	char *remote_address = DEFAULT_REMOTE_ADDRESS_SERVER;
	int remote_port = DEFAULT_REMOTE_PORT_SERVER;
	int remote_pc = DEFAULT_PC_CLIENT;
	bool lflag = false, rflag = false, Lflag = false, Rflag = false;
	enum osmo_ss7_asp_protocol protocol = OSMO_SS7_ASP_PROT_M3UA;

	while ((ch = getopt(argc, argv, "p:cl:r:L:R:C:")) != -1) {
		switch (ch) {
		case 'p':
			rc = get_string_value(osmo_ss7_asp_protocol_vals, optarg);
			if (rc < 0)
				exit(1);
			protocol = rc;
			break;
		case 'c':
			client = true;

			/* Set client-mode defaults unless already overridden during option parsing. */
			if (!lflag) {
				local_address = DEFAULT_LOCAL_ADDRESS_CLIENT;
				local_port = DEFAULT_LOCAL_PORT_CLIENT;
			}
			if (!Lflag)
				local_pc = DEFAULT_PC_CLIENT;
			if (!rflag) {
				remote_address = DEFAULT_REMOTE_ADDRESS_CLIENT;
				remote_port = DEFAULT_REMOTE_PORT_CLIENT;
			}
			if (!Rflag)
				remote_pc = DEFAULT_PC_SERVER;
			break;
		case 'l':
			if (parse_address_port(&local_address, &local_port, optarg))
				exit(1);
			lflag = true;
			break;
		case 'r':
			if (parse_address_port(&remote_address, &remote_port, optarg))
				exit(1);
			rflag = true;
			break;
		case 'L':
			if (!is_decimal_string(optarg)) {
				fprintf(stderr, "invalid decimal point code: '%s'\n", optarg);
				exit(1);
			}
			local_pc = atoi(optarg);
			Lflag = true;
			break;
		case 'R':
			if (!is_decimal_string(optarg)) {
				fprintf(stderr, "invalid decimal point code: '%s'\n", optarg);
				exit(1);
			}
			remote_pc = atoi(optarg);
			Rflag = true;
			break;
		case 'C':
			config_file = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	talloc_enable_leak_report_full();

	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	void *tall_ctx = talloc_named_const(NULL, 1, "sccp_demo_user");
	init_logging(tall_ctx);
	OSMO_ASSERT(osmo_ss7_init() == 0);
	osmo_fsm_log_addr(false);
	vty_info.tall_ctx = tall_ctx;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	osmo_fsm_vty_add_cmds();
	osmo_ss7_vty_init_asp(NULL);
	osmo_sccp_vty_init();

	/* Read the config if requested with -C */
	if (config_file) {
		rc = vty_read_config_file(config_file, NULL);
		if (rc < 0) {
			LOGP(DMAIN, LOGL_FATAL, "Failed to parse the config file: '%s'\n",
			     config_file);
			exit(1);
		}
	}

	rc = telnet_init_dynif(NULL, NULL, config_file ? vty_get_bind_addr() : local_address,
			       2324+client);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}

	if (client) {
		g_sccp = osmo_sccp_simple_client(NULL, "client", local_pc, protocol,
						 local_port, local_address, remote_port, remote_address);
		if (g_sccp == NULL) {
			perror("Could not create SCCP client");
			exit (1);
		}
		sccp_test_user_vty_install(g_sccp, OSMO_SCCP_SSN_BSSAP);
	} else {
		g_sccp = sua_server_helper(protocol, local_port, local_address, local_pc,
					   remote_port, remote_address, remote_pc);
		if (g_sccp == NULL) {
			perror("Could not create SCCP server");
			exit(1);
		}
		sccp_test_server_init(g_sccp);
	}
	g_calling_addr.pc = local_pc;
	g_called_addr.pc = remote_pc;

	while (1) {
		osmo_select_main(0);
	}
}
