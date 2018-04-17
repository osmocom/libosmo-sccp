#include "../src/xua_internal.h"
#include "../src/xua_asp_fsm.h"

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

static struct osmo_ss7_instance *s7i;

static void test_pc_transcode(uint32_t pc)
{
	const char *pc_str = osmo_ss7_pointcode_print(s7i, pc);
	uint32_t pc_reenc = osmo_ss7_pointcode_parse(s7i, pc_str);

	printf("%s(%u) -> %s -> %u\n", __func__, pc, pc_str, pc_reenc);
	OSMO_ASSERT(pc == pc_reenc);
}

static void test_pc_defaults(void)
{
	/* ensure the default point code format settings apply */
	OSMO_ASSERT(s7i->cfg.pc_fmt.component_len[0] == 3);
	OSMO_ASSERT(s7i->cfg.pc_fmt.component_len[1] == 8);
	OSMO_ASSERT(s7i->cfg.pc_fmt.component_len[2] == 3);
	OSMO_ASSERT(s7i->cfg.pc_fmt.delimiter == '.');
}

static void parse_print_mask(const char *in)
{
	uint32_t mask = osmo_ss7_pointcode_parse_mask_or_len(s7i, in);
	const char *pc_str = osmo_ss7_pointcode_print(s7i, mask);
	printf("mask %s => %u (0x%x) %s\n", in, mask, mask, pc_str);
}

static void test_pc_parser_itu(void)
{
	/* ITU Style */
	printf("Testing ITU-style point code format\n");
	osmo_ss7_instance_set_pc_fmt(s7i, 3, 8, 3);
	test_pc_transcode(0);
	test_pc_transcode(1);
	test_pc_transcode(1 << 3);
	test_pc_transcode(1 << (3+8));
	test_pc_transcode(7 << (3+8));
	test_pc_transcode(100);
	test_pc_transcode(2342);
	test_pc_transcode((1 << 14)-1);

	parse_print_mask("/1");
	parse_print_mask("7.0.0");
	parse_print_mask("/14");
}

static void test_pc_parser_ansi(void)
{
	/* ANSI Style */
	printf("Testing ANSI-style point code format\n");
	osmo_ss7_instance_set_pc_fmt(s7i, 8, 8, 8);
	s7i->cfg.pc_fmt.delimiter = '-';
	test_pc_transcode(0);
	test_pc_transcode(1);
	test_pc_transcode(1 << 8);
	test_pc_transcode(1 << 16);
	test_pc_transcode(1 << (3+8));
	test_pc_transcode((1 << 24)-1);
	test_pc_transcode(100);
	test_pc_transcode(2342);

	parse_print_mask("/1");
	parse_print_mask("/16");
	parse_print_mask("/24");

	/* re-set to default (ITU) */
	osmo_ss7_instance_set_pc_fmt(s7i, 3, 8, 3);
	s7i->cfg.pc_fmt.delimiter = '.';
}

static int test_user_prim_cb(struct osmo_prim_hdr *oph, void *priv)
{
	OSMO_ASSERT(priv == (void *) 0x1234);

	return 23;
}

static void test_user(void)
{
	struct osmo_ss7_user user, user2;
	struct osmo_mtp_prim omp = {
		.oph = {
			.sap = MTP_SAP_USER,
			.primitive = OSMO_MTP_PRIM_TRANSFER,
			.operation = PRIM_OP_INDICATION,
		},
		.u.transfer = {
			.sio = 1,
		},
	};

	printf("Testing SS7 user\n");

	user.name = "testuser";
	user.priv = (void *) 0x1234;
	user.prim_cb = test_user_prim_cb;

	/* registration */
	OSMO_ASSERT(osmo_ss7_user_register(s7i, 1, &user) == 0);
	OSMO_ASSERT(osmo_ss7_user_register(s7i, 1, NULL) == -EBUSY);
	OSMO_ASSERT(osmo_ss7_user_register(s7i, 255, NULL) == -EINVAL);

	/* primitive delivery */
	OSMO_ASSERT(osmo_ss7_mtp_to_user(s7i, &omp) == 23);

	/* cleanup */
	OSMO_ASSERT(osmo_ss7_user_unregister(s7i, 255, NULL) == -EINVAL);
	OSMO_ASSERT(osmo_ss7_user_unregister(s7i, 10, NULL) == -ENODEV);
	OSMO_ASSERT(osmo_ss7_user_unregister(s7i, 1, &user2) == -EINVAL);
	OSMO_ASSERT(osmo_ss7_user_unregister(s7i, 1, &user) == 0);

	/* primitive delivery should fail now */
	OSMO_ASSERT(osmo_ss7_mtp_to_user(s7i, &omp) == -ENODEV);

	/* wrong primitive delivery should also fail */
	omp.oph.primitive = OSMO_MTP_PRIM_PAUSE;
	OSMO_ASSERT(osmo_ss7_mtp_to_user(s7i, &omp) == -EINVAL);
}

static void test_route(void)
{
	struct osmo_ss7_route_table *rtbl;
	struct osmo_ss7_linkset *lset_a, *lset_b;
	struct osmo_ss7_route *rt, *rt12, *rtdef;

	printf("Testing SS7 routing\n");

	/* creation / destruction */
	OSMO_ASSERT(osmo_ss7_route_table_find(s7i, "foobar") == NULL);
	rtbl = osmo_ss7_route_table_find_or_create(s7i, "foobar");
	OSMO_ASSERT(rtbl);
	OSMO_ASSERT(osmo_ss7_route_table_find_or_create(s7i, "foobar") == rtbl);
	osmo_ss7_route_table_destroy(rtbl);
	OSMO_ASSERT(osmo_ss7_route_table_find(s7i, "foobar") == NULL);

	/* we now work with system route table */
	rtbl = osmo_ss7_route_table_find(s7i, "system");
	OSMO_ASSERT(rtbl && rtbl == s7i->rtable_system);

	lset_a = osmo_ss7_linkset_find_or_create(s7i, "a", 100);
	OSMO_ASSERT(lset_a);
	lset_b = osmo_ss7_linkset_find_or_create(s7i, "b", 200);
	OSMO_ASSERT(lset_b);

	/* route with full mask */
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 12) == NULL);
	rt = osmo_ss7_route_create(rtbl, 12, 0xffff, "a");
	OSMO_ASSERT(rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 12) == rt);
	osmo_ss7_route_destroy(rt);

	/* route with partial mask */
	rt = osmo_ss7_route_create(rtbl, 8, 0xfff8, "a");
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 8) == rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 9) == rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 12) == rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 15) == rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 16) == NULL);
	/* insert more specific route for 12, must have higher priority
	 * than existing one */
	rt12 = osmo_ss7_route_create(rtbl, 12, 0xffff, "b");
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 12) == rt12);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 15) == rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 16) == NULL);
	/* add a default route, which should have lowest precedence */
	rtdef = osmo_ss7_route_create(rtbl, 0, 0, "a");
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 12) == rt12);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 15) == rt);
	OSMO_ASSERT(osmo_ss7_route_find_dpc(rtbl, 16) == rtdef);

	osmo_ss7_route_destroy(rtdef);
	osmo_ss7_route_destroy(rt12);
	osmo_ss7_route_destroy(rt);

	osmo_ss7_linkset_destroy(lset_a);
	osmo_ss7_linkset_destroy(lset_b);
}

static void test_linkset(void)
{
	struct osmo_ss7_linkset *lset_a, *lset_b;
	struct osmo_ss7_link *l_a1, *l_a2;

	printf("Testing SS7 linkset/link\n");

	OSMO_ASSERT(osmo_ss7_linkset_find_by_name(s7i, "a") == NULL);
	OSMO_ASSERT(osmo_ss7_linkset_find_by_name(s7i, "b") == NULL);

	lset_a = osmo_ss7_linkset_find_or_create(s7i, "a", 100);
	OSMO_ASSERT(lset_a);
	OSMO_ASSERT(osmo_ss7_linkset_find_by_name(s7i, "a") == lset_a);

	lset_b = osmo_ss7_linkset_find_or_create(s7i, "b", 200);
	OSMO_ASSERT(lset_b);
	OSMO_ASSERT(osmo_ss7_linkset_find_by_name(s7i, "b") == lset_b);

	l_a1 = osmo_ss7_link_find_or_create(lset_a, 1);
	OSMO_ASSERT(l_a1);
	l_a2 = osmo_ss7_link_find_or_create(lset_a, 2);
	OSMO_ASSERT(l_a2);

	/* ID too high */
	OSMO_ASSERT(osmo_ss7_link_find_or_create(lset_a, 1000) == NULL);
	/* already exists */
	OSMO_ASSERT(osmo_ss7_link_find_or_create(lset_a, 1) == l_a1);

	osmo_ss7_link_destroy(l_a1);
	osmo_ss7_link_destroy(l_a2);

	osmo_ss7_linkset_destroy(lset_a);
	osmo_ss7_linkset_destroy(lset_b);
}

static void test_as(void)
{
	struct osmo_ss7_as *as;
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(osmo_ss7_as_find_by_name(s7i, "as1") == NULL);
	as = osmo_ss7_as_find_or_create(s7i, "as1", OSMO_SS7_ASP_PROT_M3UA);
	OSMO_ASSERT(as);
	OSMO_ASSERT(osmo_ss7_as_find_by_name(s7i, "as1") == as);
	OSMO_ASSERT(osmo_ss7_as_find_by_rctx(s7i, 2342) == NULL);
	as->cfg.routing_key.context = 2342;
	OSMO_ASSERT(osmo_ss7_as_find_by_rctx(s7i, 2342) == as);
	OSMO_ASSERT(osmo_ss7_as_add_asp(as, "asp1") == -ENODEV);

	asp = osmo_ss7_asp_find_or_create(s7i, "asp1", 0, M3UA_PORT, OSMO_SS7_ASP_PROT_M3UA);
	OSMO_ASSERT(asp);

	OSMO_ASSERT(osmo_ss7_as_has_asp(as, asp) == false);
	OSMO_ASSERT(osmo_ss7_as_add_asp(as, "asp1") == 0);

	osmo_ss7_asp_restart(asp);

	/* ask FSM to send ASP-UP.req */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_ASPTM_ASPAC_ACK, NULL);

	OSMO_ASSERT(osmo_ss7_as_del_asp(as, "asp1") == 0);
	OSMO_ASSERT(osmo_ss7_as_del_asp(as, "asp2") == -ENODEV);
	OSMO_ASSERT(osmo_ss7_as_del_asp(as, "asp1") == -EINVAL);

	osmo_ss7_asp_destroy(asp);
	osmo_ss7_as_destroy(as);
	OSMO_ASSERT(osmo_ss7_as_find_by_name(s7i, "as1") == NULL);
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
	void *tall_ctx = talloc_named_const(NULL, 1, "example");
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &log_info);

	log_set_print_filename(osmo_stderr_target, 0);

	for (i = 0; i < ARRAY_SIZE(log_cats); i++)
		log_set_category_filter(osmo_stderr_target, log_cats[i], 1, LOGL_DEBUG);
}

int main(int argc, char **argv)
{
	init_logging();
	osmo_fsm_log_addr(false);

	/* init */
	osmo_ss7_init();
	s7i = osmo_ss7_instance_find_or_create(NULL, 0);
	OSMO_ASSERT(osmo_ss7_instance_find(0) == s7i);
	OSMO_ASSERT(osmo_ss7_instance_find(23) == NULL);

	/* test osmo_ss7_pc_is_local() */
	s7i->cfg.primary_pc = 55;
	OSMO_ASSERT(osmo_ss7_pc_is_local(s7i, 55) == true);
	OSMO_ASSERT(osmo_ss7_pc_is_local(s7i, 23) == false);

	/* further tests */
	test_pc_defaults();
	test_pc_parser_itu();
	test_pc_parser_ansi();
	test_user();
	test_route();
	test_linkset();
	test_as();

	/* destroy */
	osmo_ss7_instance_destroy(s7i);
	OSMO_ASSERT(osmo_ss7_instance_find(0) == NULL);

	exit(0);
}
