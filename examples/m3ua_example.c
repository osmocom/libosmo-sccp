
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "internal.h"

static struct osmo_sccp_instance *sua_server_helper(void)
{
	struct osmo_sccp_instance *sccp;

	sccp = osmo_sccp_simple_server(NULL, 1, OSMO_SS7_ASP_PROT_M3UA,
					-1, "127.0.0.2");

	osmo_sccp_simple_server_add_clnt(sccp, OSMO_SS7_ASP_PROT_M3UA,
					"23", 23, -1, 0, NULL);

	return sccp;
}

/***********************************************************************
 * Initialization
 ***********************************************************************/

static const struct log_info_cat log_info_cat[] = {
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

static void init_logging(void)
{
	const int log_cats[] = { DLSS7, DLSUA, DLM3UA, DLSCCP, DLINP };
	unsigned int i;

	osmo_init_logging(&log_info);

	for (i = 0; i < ARRAY_SIZE(log_cats); i++)
		log_set_category_filter(osmo_stderr_target, log_cats[i], 1, LOGL_DEBUG);
}

static struct vty_app_info vty_info = {
	.name	= "sccp-test",
	.version = 0,
};

int main(int argc, char **argv)
{
	struct osmo_sccp_instance *sccp;
	bool client;
	int rc;

	init_logging();
	osmo_ss7_init();
	osmo_fsm_log_addr(false);
	vty_init(&vty_info);

	if (argc <= 1)
		client = true;
	else
		client = false;

	rc = telnet_init_dynif(NULL, NULL, vty_get_bind_addr(), 2324+client);
	if (rc < 0) {
		perror("Erro binding VTY port\n");
		exit(1);
	}


	if (client) {
		sccp = osmo_sccp_simple_client(NULL, "client", 23, OSMO_SS7_ASP_PROT_M3UA, 0, M3UA_PORT, "127.0.0.2");
		sccp_test_user_vty_install(sccp, OSMO_SCCP_SSN_BSC_BSSAP);
	} else {
		sccp = sua_server_helper();
		sccp_test_server_init(sccp);
	}

	while (1) {
		osmo_select_main(0);
	}
}
