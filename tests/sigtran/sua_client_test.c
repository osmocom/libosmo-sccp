#include "sua_test_common.h"

struct osmo_sccp_user *g_user;
struct osmo_sccp_link *g_link;

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *link)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_prim_hdr *resp = NULL;
	uint8_t payload[] = { 0xa1, 0xa2, 0xa3 };

	printf("sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		printf("N-CONNECT.ind(%u), issuing DATA.req\n",
			prim->u.connect.conn_id);
		resp = make_dt1_req(prim->u.connect.conn_id, payload, sizeof(payload));
		break;
	}

	if (resp)
		osmo_sua_user_link_down(link, resp);

	msgb_free(oph->msg);
	return 0;
}


int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 1, "root");
	int rc;

	osmo_sua_set_log_area(DSUA);

	osmo_init_logging(&test_log_info);

	g_user = osmo_sua_user_create(ctx, sccp_sap_up, NULL);

	rc = osmo_sua_client_connect(g_user, "127.0.0.1", 2342);
	if (rc < 0) {
		exit(1);
	}

	g_link = osmo_sua_client_get_link(g_user);

	int i = 8000;

	while (1) {
		if (i < 8010)
			tx_conn_req(g_link, i++);
		//tx_unitdata(g_link);
		osmo_select_main(0);
	}
}
