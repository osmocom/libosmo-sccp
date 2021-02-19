/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "sccp_test_data.h"

#include "../src/xua_internal.h"

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

static void test_isup_parse(void)
{
	const uint8_t party0[] = { 0x10, 0x32, 0x54, 0x76 };
	char digits[23] = "";
	int rc;

	rc = osmo_isup_party_parse(digits, party0, ARRAY_SIZE(party0), false);
	printf("digits='%s' (%d)\n", digits, rc);
	OSMO_ASSERT(rc == 8);
	OSMO_ASSERT(!strcmp(digits, "01234567"));

	rc = osmo_isup_party_parse(digits, party0, ARRAY_SIZE(party0), true);
	printf("digits='%s' (%d)\n", digits, rc);
	OSMO_ASSERT(rc == 7);
	OSMO_ASSERT(!strcmp(digits, "0123456"));
}

/* SCCP Address Parsing */

struct sccp_addr_testcase {
	struct osmo_sccp_addr expected;
	uint8_t *bin;
	unsigned int bin_len;
};

static uint8_t addr_bin0[] = { 0x92, 0x06, 0x00, 0x12, 0x04, 0x19, 0x99, 0x96, 0x76, 0x39, 0x98 };
static uint8_t addr_bin1[] = { 0x12, 0x08, 0x00, 0x12, 0x04, 0x19, 0x89, 0x96, 0x92, 0x99, 0x29 };
static uint8_t addr_bin2[] = { 0x42, 0xfe };

static const struct sccp_addr_testcase sccp_addr_testcases[] = {
	{
		.expected = {
			.presence = OSMO_SCCP_ADDR_T_GT | OSMO_SCCP_ADDR_T_SSN,
			.ri = OSMO_SCCP_RI_GT,
			.gt = {
				.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
				.tt = 0,
				.npi = OSMO_SCCP_NPI_E164_ISDN,
				.nai = OSMO_SCCP_NAI_INTL,
				.digits = "919969679389",
			},
			.ssn = 6,
		},
		.bin = addr_bin0,
		.bin_len = ARRAY_SIZE(addr_bin0),
	}, {
		.expected = {
			.presence = OSMO_SCCP_ADDR_T_GT | OSMO_SCCP_ADDR_T_SSN,
			.ri = OSMO_SCCP_RI_GT,
			.gt = {
				.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
				.tt = 0,
				.npi = OSMO_SCCP_NPI_E164_ISDN,
				.nai = OSMO_SCCP_NAI_INTL,
				.digits = "919869299992",
			},
			.ssn = 8,
		},
		.bin = addr_bin1,
		.bin_len = ARRAY_SIZE(addr_bin1),
	}, {
		.expected = {
			.presence = OSMO_SCCP_ADDR_T_SSN,
			.ri = OSMO_SCCP_RI_SSN_PC,
			.ssn = 254,
		},
		.bin = addr_bin2,
		.bin_len = ARRAY_SIZE(addr_bin2),

	},
};

static int test_sccp_addr_parse(const struct osmo_sccp_addr *cmp,
				const uint8_t *in, unsigned int in_len)
{
	struct osmo_sccp_addr osa;
	int rc;

	memset(&osa, 0, sizeof(osa));
	rc = osmo_sccp_addr_parse(&osa, in, in_len);
	if (rc < 0)
		return rc;

	printf("expected: %s\n", osmo_sccp_addr_dump(cmp));
	printf("parsed:   %s\n", osmo_sccp_addr_dump(&osa));

	if (memcmp(&osa, cmp, sizeof(osa))) {
		fprintf(stderr, "expected: %s\n", osmo_hexdump_nospc((uint8_t *)cmp, sizeof(*cmp)));
		fprintf(stderr, "parsed:   %s\n", osmo_hexdump_nospc((uint8_t *)&osa, sizeof(osa)));
	}

	return 0;
}

static void test_sccp_addr_parser(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sccp_addr_testcases); i++) {
		const struct sccp_addr_testcase *tcase = &sccp_addr_testcases[i];
		printf("sccp_addr_parse test case %u\n", i);
		test_sccp_addr_parse(&tcase->expected, tcase->bin, tcase->bin_len);
	}
}

struct sccp_addr_enc_testcase {
	const char *name;
	struct osmo_sccp_addr addr_in;
	int rc;
	char *exp_out;
};

static const struct sccp_addr_enc_testcase enc_cases[] = {
	{
		.name = "NOGT-PC1024",
		.addr_in = {
			.ri = OSMO_SCCP_RI_SSN_PC,
			.presence = OSMO_SCCP_ADDR_T_PC,
			.pc = 1024,
		},
		.rc = 3,
		.exp_out = "410004",
	}, {
		.name = "NOGT-PC16383",
		.addr_in = {
			.ri = OSMO_SCCP_RI_SSN_PC,
			.presence = OSMO_SCCP_ADDR_T_PC,
			.pc = 16383,
		},
		.rc = 3,
		.exp_out = "41ff3f",
	}, {
		.name = "NOGT-PC16383-SSN90",
		.addr_in = {
			.ri = OSMO_SCCP_RI_SSN_PC,
			.presence = OSMO_SCCP_ADDR_T_PC | OSMO_SCCP_ADDR_T_SSN,
			.pc = 16383,
			.ssn = 0x5A,
		},
		.rc = 4,
		.exp_out = "43ff3f5a",
	}, {
		.name = "GT-PC16383-NAIONLY",
		.addr_in = {
			.ri = OSMO_SCCP_RI_SSN_PC,
			.presence = OSMO_SCCP_ADDR_T_PC | OSMO_SCCP_ADDR_T_GT,
			.pc = 16383,
			.gt.gti = OSMO_SCCP_GTI_NAI_ONLY,
			.gt.nai = 0x7f,
		},
		.rc = 4,
		.exp_out = "45ff3f7f",
	}, {
		.name = "GT-NOPC-NAIONLY",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = OSMO_SCCP_GTI_NAI_ONLY,
			.gt.nai = 0x03,
		},
		.rc = 2,
		.exp_out = "0403",
	}, {
		.name = "GT-NOPC-TTONLY",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = OSMO_SCCP_GTI_TT_ONLY,
			.gt.tt =  0x03,
		},
		.rc = -EINVAL,
	}, {
		.name = "GT-NOPC-TT_NPL_ENC-ODD",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC,
			.gt.tt =  0x03,
			.gt.npi = 1,
			.gt.digits = "123",
		},
		.rc = 5,
		.exp_out = "0c03112103",
	}, {
		.name = "GT-NOPC-TT_NPL_ENC-EVEN",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC,
			.gt.tt =  0x03,
			.gt.npi = 1,
			.gt.digits = "1234",
		},
		.rc = 5,
		.exp_out = "0c03122143",
	}, {
		.name = "GT-NOPC-TT_NPL_ENC_NAI-EVEN",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
			.gt.tt =  0x03,
			.gt.npi = 1,
			.gt.nai = 4,
			.gt.digits = "1234",
		},
		.rc = 6,
		.exp_out = "100312042143",
	}, {
		.name = "GT-NOPC-GTI_INVALID",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = 23,
			.gt.tt =  0x03,
			.gt.npi = 1,
			.gt.nai = 4,
			.gt.digits = "1234",
		},
		.rc = -EINVAL,
	}, {
		.name = "GT-NOPC-TT_NPL_ENC_NAI-EVEN-NONNUM",
		.addr_in = {
			.ri = OSMO_SCCP_RI_GT,
			.presence = OSMO_SCCP_ADDR_T_GT,
			.gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
			.gt.tt =  0x03,
			.gt.npi = 1,
			.gt.nai = 4,
			.gt.digits = "1ABF",
		},
		.rc = 6,
		.exp_out = "10031204a1fb",
	},

};

static void testcase_sccp_addr_encdec(const struct sccp_addr_enc_testcase *tcase)
{
	struct msgb *msg = msgb_alloc(1024, "encdec");
	struct osmo_sccp_addr out;
	char *str;
	int rc;

	printf("\n=> %s\n", tcase->name);

	printf("input addr: %s\n", osmo_sccp_addr_dump(&tcase->addr_in));
	rc = osmo_sccp_addr_encode(msg, &tcase->addr_in);
	printf("rc=%d, expected rc=%d\n", rc, tcase->rc);
	OSMO_ASSERT(rc == tcase->rc);

	if (rc <= 0) {
		msgb_free(msg);
		return;
	}

	str = osmo_hexdump_nospc(msg->data, msg->len);
	printf("encoded  addr: %s\n", str);
	if (tcase->exp_out) {
		printf("expected addr: %s\n", tcase->exp_out);
		OSMO_ASSERT(!strcmp(tcase->exp_out, str));
	}

	rc = osmo_sccp_addr_parse(&out, msg->data, msg->len);
	printf("decod addr: %s\n", osmo_sccp_addr_dump(&out));

	OSMO_ASSERT(!memcmp(&out, &tcase->addr_in, sizeof(out)));

	msgb_free(msg);
}

static void test_sccp_addr_encdec(void)
{
	int i;

	printf("Testing SCCP Address Encode/Decode\n");
	for (i = 0; i < ARRAY_SIZE(enc_cases); i++) {
		testcase_sccp_addr_encdec(&enc_cases[i]);
	}
	printf("\n");
}

/* sccp_addr_testcases[0].expected.gt transcoded into a SUA Global Title IE */
static const uint8_t expected_sua_gt[] = {
	0x80, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x04,
	0x0c, 0x00, 0x01, 0x04, 0x19, 0x99, 0x96, 0x76,
	0x39, 0x98, 0x00, 0x00
};

static void test_helpers(void)
{
	struct msgb *msg = msgb_alloc(1024, "foo");
	const struct osmo_sccp_gt *gt_in = &sccp_addr_testcases[0].expected.gt;
	struct osmo_sccp_gt gt_out = {};

	printf("Testing Decoded GT -> SUA encoding\n");
	printf("IN: %s\n", osmo_sccp_gt_dump(gt_in));
	printf("    %s\n", osmo_hexdump_nospc((const unsigned char*)gt_in, sizeof(struct osmo_sccp_gt)));

	/* encode sccp_addr to SUA GT */
	xua_part_add_gt(msg, gt_in);
	OSMO_ASSERT(msgb_length(msg) == sizeof(expected_sua_gt));
	OSMO_ASSERT(!memcmp(msg->data, expected_sua_gt, sizeof(expected_sua_gt)));

	/* pull the tag+length value */
	msgb_pull(msg, 4);

	/* parse + compare */
	sua_parse_gt(&gt_out, msgb_data(msg), msgb_length(msg));
	printf("OUT:%s\n", osmo_sccp_gt_dump(&gt_out));
	printf("    %s\n", osmo_hexdump_nospc((const unsigned char*)&gt_out, sizeof(struct osmo_sccp_gt)));
	OSMO_ASSERT(!memcmp(gt_in, &gt_out, sizeof(gt_out)));

	msgb_free(msg);
}

/* SCCP Message Transcoding */

struct sccp2sua_testcase {
	const char *name;
	struct {
		const uint8_t *bin;
		unsigned int length;
	} sccp;
	struct {
		struct xua_common_hdr hdr;
		const struct xua_msg_part parts[32];
	} sua;
};

#define PANDSIZ(x)	{ x, ARRAY_SIZE(x) }
#define PARTU32(x, data)	{ .tag = x, .len = 4, .dat = (uint8_t *) data }
#define PARTARR(x, data)	{ .tag = x, .len = ARRAY_SIZE(data), .dat = (uint8_t *) data }
/* GCC-4 errors with 'initializer element is not constant' if using XUA_HDR
 * inside a const struct (OS#5004) */
#define _XUA_HDR(class, type)    { .spare = 0, .msg_class = (class), .msg_type = (type) }

const uint32_t sua_proto_class0 = 0;
const uint32_t sua_proto_class2 = 2;
const uint32_t sua_loc_ref_bsc = 0x10203;
const uint32_t sua_loc_ref_msc = 0x00003;
const uint32_t sua_cause0 = 0x00003;
const uint8_t sua_addr_ssn_bssmap[] = { 0x00, 0x02, 0x00, 0x07, 0x80, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0xfe };
const uint8_t sua_addr_ssn_bssmap_pc1[] = { 0x00, 0x01, 0x00, 0x07, 0x80, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x80, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0xfe };
const uint8_t sua_addr_ssn_bssmap_pc92[] = { 0x00, 0x01, 0x00, 0x07, 0x80, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x5c, 0x80, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0xfe };

static const struct sccp2sua_testcase sccp2sua_testcases[] = {
	{
		.name = "BSSMAP-RESET",
		.sccp = PANDSIZ(bssmap_reset),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT),
			.parts = {
				PARTU32(SUA_IEI_PROTO_CLASS, &sua_proto_class0),
				PARTARR(SUA_IEI_DEST_ADDR, sua_addr_ssn_bssmap),
				PARTARR(SUA_IEI_SRC_ADDR, sua_addr_ssn_bssmap),
			},
		},
	}, {
		.name = "BSSMAP-RESET-ACK",
		.sccp = PANDSIZ(bssmap_reset_ack),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT),
			.parts = {
				PARTU32(SUA_IEI_PROTO_CLASS, &sua_proto_class0),
				PARTARR(SUA_IEI_DEST_ADDR, sua_addr_ssn_bssmap_pc1),
				PARTARR(SUA_IEI_SRC_ADDR, sua_addr_ssn_bssmap_pc92),
			},
		},
	}, {
		.name = "BSSMAP-PAGING",
		.sccp = PANDSIZ(bssmap_paging),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT),
			.parts = {
				PARTU32(SUA_IEI_PROTO_CLASS, &sua_proto_class0),
				PARTARR(SUA_IEI_DEST_ADDR, sua_addr_ssn_bssmap_pc1),
				PARTARR(SUA_IEI_SRC_ADDR, sua_addr_ssn_bssmap_pc92),
			},
		},
	}, {
		.name = "BSSMAP-UDT",
		.sccp = PANDSIZ(bssmap_udt),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT),
			.parts = {
				PARTU32(SUA_IEI_PROTO_CLASS, &sua_proto_class0),
				PARTARR(SUA_IEI_DEST_ADDR, sua_addr_ssn_bssmap),
				PARTARR(SUA_IEI_SRC_ADDR, sua_addr_ssn_bssmap),
			},
		},
	}, {
		.name = "BSSMAP-CR",
		.sccp = PANDSIZ(bssmap_cr),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CO, SUA_CO_CORE),
			.parts = {
				PARTU32(SUA_IEI_PROTO_CLASS, &sua_proto_class2),
				PARTU32(SUA_IEI_SRC_REF, &sua_loc_ref_bsc),
				PARTARR(SUA_IEI_DEST_ADDR, sua_addr_ssn_bssmap),
			},
		},
	}, {
		.name = "BSSMAP-CC",
		.sccp = PANDSIZ(bssmap_cc),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CO, SUA_CO_COAK),
			.parts = {
				PARTU32(SUA_IEI_PROTO_CLASS, &sua_proto_class2),
				PARTU32(SUA_IEI_SRC_REF, &sua_loc_ref_msc),
				PARTARR(SUA_IEI_DEST_ADDR, sua_addr_ssn_bssmap),
			},
		},
	}, {
		.name = "BSSMAP-DTAP",
		.sccp = PANDSIZ(bssmap_dtap),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CO, SUA_CO_CODT),
			.parts = {
				PARTU32(SUA_IEI_SRC_REF, &sua_loc_ref_msc),
			},
		},
	}, {
		.name = "BSSMAP-CLEAR",
		.sccp = PANDSIZ(bssmap_clear),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CO, SUA_CO_CODT),
			.parts = {
				PARTU32(SUA_IEI_SRC_REF, &sua_loc_ref_msc),
			},
		},
	}, {
		.name = "BSSMAP-RELEASED",
		.sccp = PANDSIZ(bssmap_released),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE),
			.parts = {
				PARTU32(SUA_IEI_DEST_REF, &sua_loc_ref_msc),
				PARTU32(SUA_IEI_SRC_REF, &sua_loc_ref_bsc),
				PARTU32(SUA_IEI_CAUSE, &sua_cause0),
			},
		},
	}, {
		.name = "BSSMAP-RELEASE_COMPLETE",
		.sccp = PANDSIZ(bssmap_release_complete),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CO, SUA_CO_RELCO),
			.parts = {
				PARTU32(SUA_IEI_DEST_REF, &sua_loc_ref_bsc),
				PARTU32(SUA_IEI_SRC_REF, &sua_loc_ref_msc),
			},
		},
	}, {
		.name = "TCAP",
		.sccp = PANDSIZ(tcap_global_title),
		.sua = {
			.hdr = _XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT),
			.parts = {
			},
		},
	},
};

static void test_sccp2sua_case(const struct sccp2sua_testcase *tcase)
{
	struct xua_msg *xua;
	struct msgb *msg = msgb_alloc(300, "SCCP2SUA Test Input");
	struct msgb *msg2;

	printf("\n=> %s\n", tcase->name);
	msg->l2h = msgb_put(msg, tcase->sccp.length);
	memcpy(msg->l2h, tcase->sccp.bin, tcase->sccp.length);
	printf("SCCP Input: %s\n", msgb_hexdump(msg));
	printf("Transcoding message SCCP -> XUA\n");
	xua = osmo_sccp_to_xua(msg);
	OSMO_ASSERT(xua);

	printf("Decoded SUA: ");
	printf("%s\n", xua_msg_dump(xua, &xua_dialect_sua));

	printf("Re-Encoding decoded SUA to SCCP\n");
	msg2 = osmo_sua_to_sccp(xua);
	OSMO_ASSERT(msg2);
	/* Re-encode xUA to SCCP */
	printf("SCCP Output: %s\n", msgb_hexdump(msg2));

	if (msgb_length(msg) != msgb_length(msg2) ||
	    memcmp(msgb_data(msg), msgb_data(msg2), msgb_length(msg)))
		printf("Input != re-encoded output!\n");

	/* free related data */
	msgb_free(msg);
	msgb_free(msg2);
	xua_msg_free(xua);
}

static void test_sccp2sua(void)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(sccp2sua_testcases); i++) {
		test_sccp2sua_case(&sccp2sua_testcases[i]);
	}
}

/* M3UA message with RKM-REG contents */
static const uint8_t rkm_reg[] = {
	0x01, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x04, 0x00, 0x0e, 0x4d, 0x33, 0x55, 0x41,
	0x20, 0x72, 0x6f, 0x63, 0x6b, 0x73, 0x00, 0x00, 0x02, 0x07, 0x00, 0x14, 0x02, 0x0a, 0x00, 0x08,
	0x00, 0x00, 0x00, 0x01, 0x02, 0x0b, 0x00, 0x08, 0x00, 0x00, 0x00, 0x17,
};

static void test_rkm(void)
{
	struct xua_msg *xua, *nested;
	struct xua_msg_part *rkey;

	printf("Parsing M3UA Message\n");
	xua = xua_from_msg(M3UA_VERSION, sizeof(rkm_reg), (uint8_t *)rkm_reg);
	OSMO_ASSERT(xua);
	OSMO_ASSERT(xua->hdr.msg_class == M3UA_MSGC_RKM);
	OSMO_ASSERT(xua->hdr.msg_type == M3UA_RKM_REG_REQ);
	OSMO_ASSERT(xua_msg_find_tag(xua, M3UA_IEI_INFO_STRING));
	rkey = xua_msg_find_tag(xua, M3UA_IEI_ROUT_KEY);
	OSMO_ASSERT(rkey);
	OSMO_ASSERT(rkey->len == 16);

	printf("Parsing Nested M3UA Routing Key IE\n");
	nested = xua_from_nested(rkey);
	OSMO_ASSERT(nested);
	OSMO_ASSERT(xua_msg_get_u32(nested, M3UA_IEI_LOC_RKEY_ID) == 1);
	OSMO_ASSERT(xua_msg_get_u32(nested, M3UA_IEI_DEST_PC) == 23);

	talloc_free(nested);
	talloc_free(xua);
}

void test_sccp_addr_cmp()
{
	int ai;
	int bi;
	int rc;

	printf("\n%s()\n", __func__);

	for (ai = 0; ai < ARRAY_SIZE(enc_cases); ai++) {
		for (bi = 0; bi < ARRAY_SIZE(enc_cases); bi++) {
			struct osmo_sccp_addr a = enc_cases[ai].addr_in;
			struct osmo_sccp_addr b = enc_cases[bi].addr_in;

			rc = osmo_sccp_addr_cmp(&a, &b, a.presence);
			rc = OSMO_MIN(1, OSMO_MAX(-1, rc));
			printf(" [%2d] vs. [%2d]: %2d = osmo_sccp_addr_cmp( %s ,", ai, bi, rc, osmo_sccp_addr_dump(&a));
			printf(" %s, 0x%x )\n", osmo_sccp_addr_dump(&b), a.presence);

			rc = osmo_sccp_addr_ri_cmp(&a, &b);
			rc = OSMO_MIN(1, OSMO_MAX(-1, rc));
			printf("                %2d = osmo_sccp_addr_ri_cmp( %s ,", rc, osmo_sccp_addr_dump(&a));
			printf(" %s )\n", osmo_sccp_addr_dump(&b));
		}
	}
};


static const struct log_info_cat default_categories[] = {
	[0] = {
		.name = "DSCCP",
		.description = "DSCP",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	struct log_target *stderr_target;
	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_use_color(stderr_target, 0);
	log_set_print_filename(stderr_target, 0);
	log_set_print_category(stderr_target, 0);
	log_set_print_category_hex(stderr_target, 0);

	test_isup_parse();
	test_sccp_addr_parser();
	test_helpers();
	test_sccp2sua();
	test_rkm();
	test_sccp_addr_encdec();
	test_sccp_addr_cmp();

	printf("All tests passed.\n");
	return 0;
}
