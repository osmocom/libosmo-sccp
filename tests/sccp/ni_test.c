#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include "xua_internal.h"

void *ctx = NULL;

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	int rc = 0;

	printf("%s\n", msgb_hexdump(oph->msg));

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		printf("inbound connection indication\n");
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		printf("incoming connection oriented data\n");
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		printf("Handle inbound UNITDATA\n");
		break;

	default:
		printf("Unhandled SIGTRAN primitive: %u:%u\n", oph->primitive, oph->operation);
		break;
	}

	return rc;
}

static struct msgb *create_msg(void)
{
	struct msgb *msg = msgb_alloc_headroom(128, 128, "test msg");
	OSMO_ASSERT(msg);

	msgb_printf(msg, "test msg");
	msg->l3h = msg->data;

	return msg;
}

static const struct log_info_cat default_categories[] = {
	[0] = {
		.name = "DSCCP",
		.description = "DSCP",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

struct osmo_ss7_asp *asp;
struct osmo_sccp_addr addr1;
struct osmo_ss7_instance *ss7;

/* override, requires '-Wl,--wrap=m3ua_tx_xua_as' */
int __real_m3ua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua);
int __wrap_m3ua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	printf("sio = 0x%02x ==> ni = %u\n", xua->mtp.sio, xua->mtp.sio >> 6);
	/* loopback to self */
	xua->mtp.dpc = ss7->cfg.primary_pc;
	return m3ua_hmdc_rx_from_l2(ss7, xua);
}

int main(void)
{
	struct osmo_ss7_as *as;
	struct osmo_sccp_user *user1;
	struct osmo_sccp_addr addr2;
	osmo_sccp_make_addr_pc_ssn(&addr1, 1, 1);
	osmo_sccp_make_addr_pc_ssn(&addr2, 2, 1);

	int ss7_id = 0;

	osmo_init_logging(&log_info);
	osmo_ss7_init();

	ss7 = osmo_ss7_instance_find_or_create(ctx, ss7_id);
	OSMO_ASSERT(ss7);

	as = osmo_ss7_as_find_or_create(ss7, "as", OSMO_SS7_ASP_PROT_M3UA);
	OSMO_ASSERT(as);

	asp = osmo_ss7_asp_find_or_create(ss7, "asp", 0, 0, OSMO_SS7_ASP_PROT_M3UA);
	OSMO_ASSERT(asp);
	osmo_ss7_as_add_asp(as, asp->cfg.name);

	osmo_ss7_route_create(ss7->rtable_system, 0, 0, as->cfg.name);
	ss7->cfg.primary_pc = addr1.pc;

	asp->cfg.is_server = false;

	ss7->sccp = osmo_sccp_instance_create(ss7, NULL);
	OSMO_ASSERT(ss7->sccp);

	ss7->cfg.network_indicator = 2;

	user1 = osmo_sccp_user_bind(ss7->sccp, "user1", sccp_sap_up, 1);
	osmo_sccp_user_bind(ss7->sccp, "user2", sccp_sap_up, 2);

	osmo_sccp_tx_unitdata_msg(user1, &addr1, &addr2, create_msg());

	osmo_ss7_asp_destroy(asp);
	osmo_ss7_as_destroy(as);
	osmo_ss7_instance_destroy(ss7);

	return 0;
}

