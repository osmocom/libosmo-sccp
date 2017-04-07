
#include <string.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include "internal.h"

#define SCU_NODE 23

static struct osmo_sccp_user *g_scu;

static struct osmo_sccp_addr g_calling_addr = {
	.presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC,
	.ri = OSMO_SCCP_RI_SSN_PC,
	.pc = 23,
};

static struct osmo_sccp_addr g_called_addr = {
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
	struct osmo_sccp_user *scu = _scu;
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
	vty_install_default(SCU_NODE);
	install_element(SCU_NODE, &scu_called_ssn_cmd);
	install_element(SCU_NODE, &scu_conn_req_cmd);
	install_element(SCU_NODE, &scu_conn_resp_cmd);
	install_element(SCU_NODE, &scu_data_req_cmd);
	install_element(SCU_NODE, &scu_unitdata_req_cmd);
	install_element(SCU_NODE, &scu_disc_req_cmd);

	install_element(ENABLE_NODE, &scu_cmd);

	return 0;
}
