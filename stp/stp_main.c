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

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "internal.h"

struct osmo_ss7_instance *g_s7i;

static const struct log_info_cat log_info_cat[] = {
};

static const struct log_info log_info = {
	.cat = log_info_cat,
	.num_cat = ARRAY_SIZE(log_info_cat),
};

/* Hack to enable debug logging for all relevant (used?) subsystems */
static void init_logging(void)
{
	const int log_cats[] = { DLSS7, DLSUA, DLM3UA, DLSCCP, DLINP };
	unsigned int i;

	osmo_init_logging(&log_info);

	for (i = 0; i < ARRAY_SIZE(log_cats); i++)
		log_set_category_filter(osmo_stderr_target, log_cats[i], 1, LOGL_DEBUG);
}

static struct vty_app_info vty_info = {
	.name	= "osmo-stp",
	.version = PACKAGE_VERSION,
	.go_parent_cb = osmo_ss7_vty_go_parent,
	.is_config_node = osmo_ss7_is_config_node,
};

int main(int argc, char **argv)
{
	char *config_file = "osmo-stp.cfg";
	int rc;

	init_logging();
	osmo_ss7_init();
	osmo_fsm_log_addr(false);
	vty_init(&vty_info);
	osmo_ss7_vty_init();

	g_s7i = osmo_ss7_instance_find_or_create(NULL, 0);

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file '%s'\n",
			config_file);
		exit(1);
	}

	rc = telnet_init_dynif(NULL, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_STP);
	if (rc < 0) {
		perror("Erro binding VTY port\n");
		exit(1);
	}

	while (1) {
		osmo_select_main(0);
	}
}
