#include "sua_test_common.h"

static const struct log_info_cat log_cat[] = {
	[DMAIN] = {
		.name = "DMAIN", .loglevel = LOGL_DEBUG, .enabled = 1,
		.color = "",
		.description = "Main program",
	},
	[DSUA] = {
		.name = "DSUA", .loglevel = LOGL_DEBUG, .enabled = 1,
		.color = "",
		.description = "SCCP User Adaption",
	},
};

const struct log_info test_log_info = {
	.cat = log_cat,
	.num_cat = ARRAY_SIZE(log_cat),
};

int tx_unitdata(struct osmo_sua_link *link)
{
	struct msgb *msg = msgb_alloc(1024, "tx_unitdata");
	struct osmo_scu_prim *prim;
	struct osmo_scu_unitdata_param *param;
	uint8_t *cur;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	param = &prim->u.unitdata;
	param->calling_addr.presence = OSMO_SCCP_ADDR_T_SSN;
	param->called_addr.presence = OSMO_SCCP_ADDR_T_SSN;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST, msg);

	cur = msg->l2h = msgb_put(msg, 3);
	cur[0] = 1; cur[1] = 2; cur[2] = 3;

	return osmo_sua_user_link_down(link, &prim->oph);
}

static void sccp_make_addr_pc_ssn(struct osmo_sccp_addr *addr, uint32_t pc, uint32_t ssn)
{
	addr->presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
	addr->ssn = ssn;
	addr->pc = pc;
}

struct osmo_prim_hdr *make_conn_req(uint32_t conn_id)
{
	struct msgb *msg = msgb_alloc(1024, "conn_req");
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_REQUEST, msg);
	/* Set SSN for calling and called addr */
	sccp_make_addr_pc_ssn(&prim->u.connect.called_addr, 2, OSMO_SCCP_SSN_RANAP);
	sccp_make_addr_pc_ssn(&prim->u.connect.calling_addr, 1, OSMO_SCCP_SSN_RANAP);
	prim->u.connect.sccp_class = 2;
	prim->u.connect.conn_id = conn_id;

	return &prim->oph;
}

int tx_conn_req(struct osmo_sua_link *link, uint32_t conn_id)
{
	struct osmo_prim_hdr *prim = make_conn_req(conn_id);
	return osmo_sua_user_link_down(link, prim);
}

struct osmo_prim_hdr *
make_dt1_req(uint32_t conn_id, const uint8_t *data, unsigned int len)
{
	struct msgb *msg = msgb_alloc(1024, "dt1");
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	prim->u.data.conn_id = conn_id;

	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);

	return &prim->oph;
}
