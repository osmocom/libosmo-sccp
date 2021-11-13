
#include <string.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include "internal.h"

#define SCU_NODE 23

static struct osmo_sccp_user *g_scu;

struct osmo_sccp_addr g_calling_addr = {
	.presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC,
	.ri = OSMO_SCCP_RI_SSN_PC,
	.pc = 23,
};

struct osmo_sccp_addr g_called_addr = {
	.presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC,
	.ssn = 1,
	.ri = OSMO_SCCP_RI_SSN_PC,
	.pc = 1,
};

DEFUN(scu_called_ssn, scu_called_ssn_cmd,
	"called-addr-ssn <0-255>",
	"Set SSN of SCCP CalledAddress\n"
	"SSN of SCCP CalledAddress\n")
{
	g_called_addr.ssn = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(scu_conn_req, scu_conn_req_cmd,
	"connect-req <0-16777216> [DATA]",
	"N-CONNECT.req\n"
	"Connection ID\n")
{
	struct osmo_sccp_user *scu = vty->index;
	int conn_id = atoi(argv[0]);
	const char *data = argv[1];

	osmo_sccp_tx_conn_req(scu, conn_id, &g_calling_addr, &g_called_addr,
				(const uint8_t *)data, data ? strlen(data)+1 : 0);
	return CMD_SUCCESS;
}

DEFUN(scu_conn_resp, scu_conn_resp_cmd,
	"connect-resp <0-16777216> [DATA]",
	"N-CONNET.resp\n"
	"Connection ID\n")
{
	struct osmo_sccp_user *scu = vty->index;
	int conn_id = atoi(argv[0]);
	const char *data = argv[1];

	osmo_sccp_tx_conn_resp(scu, conn_id, NULL,
				(const uint8_t *)data, data ? strlen(data)+1 : 0);
	return CMD_SUCCESS;
}

DEFUN(scu_data_req, scu_data_req_cmd,
	"data-req <0-16777216> DATA",
	"N-DATA.req\n"
	"Connection ID\n")
{
	struct osmo_sccp_user *scu = vty->index;
	int conn_id = atoi(argv[0]);
	const char *data = argv[1];

	osmo_sccp_tx_data(scu, conn_id, (const uint8_t *)data, strlen(data)+1);
	return CMD_SUCCESS;
}

DEFUN(scu_unitdata_req, scu_unitdata_req_cmd,
	"unitdata-req DATA",
	"N-UNITDATA.req\n")
{
	struct osmo_sccp_user *scu = vty->index;
	const char *data = argv[0];

	osmo_sccp_tx_unitdata(scu, &g_calling_addr, &g_called_addr,
				(const uint8_t *)data, strlen(data)+1);
	return CMD_SUCCESS;
}

struct load_test_ctx {
	struct osmo_sccp_user *scu;
	struct vty *vty;

	struct osmo_timer_list timer;
	char data[256];

	unsigned int msu_size;
	unsigned int total_num_msu;
	unsigned int sent_msu;
	unsigned int timer_interval_us;
	struct timespec start_time;
};

static struct load_test_ctx g_ltc;

static void load_test_timer_cb(void *ctx)
{
	struct vty *vty = g_ltc.vty;

	osmo_sccp_tx_unitdata(g_ltc.scu, &g_calling_addr, &g_called_addr,
			(const uint8_t *)g_ltc.data, g_ltc.msu_size);
	g_ltc.sent_msu++;
	if (g_ltc.sent_msu >= g_ltc.total_num_msu) {
		struct timespec stop_time, expired_time;
		float expired_timef;
		osmo_clock_gettime(CLOCK_MONOTONIC, &stop_time);
		timespecsub(&stop_time, &g_ltc.start_time, &expired_time);
		expired_timef = expired_time.tv_sec;
		expired_timef += (float) expired_time.tv_nsec / 1000000000.0f;

		vty_out(vty, "SCCP Unitdata load test completed after %5.2f seconds (%5.2f MSU/s)%s", 
			expired_timef, g_ltc.sent_msu / expired_timef, VTY_NEWLINE);
		return;
	}
	/* schedule for the next millisecond */
	osmo_timer_schedule(&g_ltc.timer, 0, g_ltc.timer_interval_us);
}

DEFUN(scu_unitdata_load_test, scu_unitdata_load_test_cmd,
	"unitdata-load-test msu-size <1-255> msu-count <1-4294967295> msu-per-second <1-1000000>",
	"Run loadtest\n")
{
	struct osmo_sccp_user *scu = vty->index;
	unsigned int msu_size = atoi(argv[0]);
	unsigned int msu_count = atoi(argv[1]);
	unsigned int msu_per_second = atoi(argv[2]);

	if (osmo_timer_pending(&g_ltc.timer)) {
		vty_out(vty, "Cannot start load test, it is alrady running%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_ltc.msu_size = msu_size;
	g_ltc.total_num_msu = msu_count;
	g_ltc.timer_interval_us = 1000000/msu_per_second;

	g_ltc.scu = scu;
	g_ltc.vty = vty;
	g_ltc.sent_msu = 0;
	osmo_timer_setup(&g_ltc.timer, load_test_timer_cb, NULL);
	osmo_clock_gettime(CLOCK_MONOTONIC, &g_ltc.start_time);
	load_test_timer_cb(NULL);
	vty_out(vty, "SCCP Unitdata load test started%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(scu_disc_req, scu_disc_req_cmd,
	"disconnect-req <0-16777216>",
	"N-DISCONNT.req\n"
	"Connection ID\n")
{
	struct osmo_sccp_user *scu = vty->index;
	int conn_id = atoi(argv[0]);

	osmo_sccp_tx_disconn(scu, conn_id, NULL, 42);
	return CMD_SUCCESS;
}

static struct cmd_node scu_node = {
	SCU_NODE,
	"%s(sccp-user)# ",
	1,
};

DEFUN(scu, scu_cmd,
	"sccp-user",
	"Enter SCCP User Node\n")
{
	vty->node = SCU_NODE;
	vty->index = g_scu;
	return CMD_SUCCESS;
}

static int testclnt_prim_cb(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu __attribute__((unused)) = _scu;
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *) oph;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
	default:
		break;
	}
	msgb_free(oph->msg);
	return 0;
}


int sccp_test_user_vty_install(struct osmo_sccp_instance *inst, int ssn)
{
	g_scu = osmo_sccp_user_bind(inst, "test_client_vty", testclnt_prim_cb, ssn);
	if (!g_scu)
		return -1;

	g_calling_addr.ssn = ssn;

	install_node(&scu_node, NULL);
	install_element(SCU_NODE, &scu_called_ssn_cmd);
	install_element(SCU_NODE, &scu_conn_req_cmd);
	install_element(SCU_NODE, &scu_conn_resp_cmd);
	install_element(SCU_NODE, &scu_data_req_cmd);
	install_element(SCU_NODE, &scu_unitdata_req_cmd);
	install_element(SCU_NODE, &scu_unitdata_load_test_cmd);
	install_element(SCU_NODE, &scu_disc_req_cmd);

	install_element(ENABLE_NODE, &scu_cmd);

	return 0;
}
