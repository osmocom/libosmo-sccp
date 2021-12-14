/*
 * SCCP testing code
 *
 * (C) 2009,2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009,2011 by On-Waves
 *
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
 */

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <osmocom/sccp/sccp.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

/* BSC -> MSC */
static const uint8_t bssmap_reset[] = {
	0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
	0x02, 0x42, 0xfe, 0x06, 0x00, 0x04, 0x30, 0x04,
	0x01, 0x20,
};

/* MSC -> BSC reset ack */
static const uint8_t bssmap_reset_ack[] = {
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x03,
	0x00, 0x01, 0x31,
};

/* MSC -> BSC paging, connection less */
static const uint8_t bssmap_paging[] = {
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x10,
	0x00, 0x0e, 0x52, 0x08, 0x08, 0x29, 0x47, 0x10,
	0x02, 0x01, 0x31, 0x97, 0x61, 0x1a, 0x01, 0x06,
};

/* MSC -> BSC paging, UDT without PC  */
static const uint8_t bssmap_udt[] = {
	0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
	0x02, 0x42, 0xfe, 0x10, 0x00, 0x0e, 0x52, 0x08,
	0x08, 0x29, 0x47, 0x10, 0x02, 0x01, 0x31, 0x97,
	0x61, 0x1a, 0x01, 0x06,
};

/* BSC -> MSC connection open */
static const uint8_t bssmap_cr[] = {
	0x01, 0x01, 0x02, 0x03, 0x02, 0x02, 0x04, 0x02,
	0x42, 0xfe, 0x0f, 0x1f, 0x00, 0x1d, 0x57, 0x05,
	0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x12, 0xc3,
	0x50, 0x17, 0x10, 0x05, 0x24, 0x11, 0x03, 0x33,
	0x19, 0xa2, 0x08, 0x29, 0x47, 0x10, 0x02, 0x01,
	0x31, 0x97, 0x61, 0x00
};

/* MSC -> BSC connection confirm */
static const uint8_t bssmap_cc[] = {
	0x02, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
};

/* MSC -> BSC DTAP
 *
 * we fake a bit and make it BSC -> MSC... so the
 * payload does not make any sense..
 */
static const uint8_t bssmap_dtap[] = {
	0x06, 0x00, 0x00, 0x03, 0x00, 0x01, 0x0f, 0x01, 0x00, 0x0c,
	0x03, 0x05, 0x5c, 0x08, 0x11, 0x81, 0x33, 0x66, 0x02, 0x13,
	0x45, 0xf4,
};

/* MSC -> BSC clear command */
static const uint8_t bssmap_clear[] = {
	0x06, 0x00, 0x00, 0x03, 0x00, 0x01, 0x06, 0x00, 0x04, 0x20,
	0x04, 0x01, 0x09,
};

/* MSC -> BSC released */
static const uint8_t bssmap_released[] = {
	0x04, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x01, 0x0f,
	0x02, 0x23, 0x42, 0x00,
};

/* BSC -> MSC released */
static const uint8_t bssmap_release_complete[] = {
	0x05, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03
};

/* message with a SCCP global title */
static const uint8_t tcap_global_title[] = {
	0x09,
	0x81, 0x03, 0x0d, 0x18, 0x0a, 0x12, 0x07, 0x00,
	0x12, 0x04, 0x53, 0x84, 0x09, 0x00, 0x17, 0x0b,
	0x12, 0x06, 0x00, 0x12, 0x04, 0x44, 0x87, 0x20,
	0x00, 0x20, 0x65, 0x9a, 0x65, 0x81, 0x97, 0x48,
	0x04, 0x26, 0x00, 0x01, 0x98, 0x49, 0x04, 0x51,
	0x01, 0x03, 0xdf, 0x6c, 0x81, 0x88, 0xa1, 0x81,
	0x85, 0x02, 0x01, 0x44, 0x02, 0x01, 0x07, 0x30,
	0x80, 0xa7, 0x80, 0xa0, 0x80, 0x04, 0x01, 0x2b,
	0x30, 0x80, 0x30, 0x12, 0x83, 0x01, 0x10, 0x84,
	0x01, 0x07, 0x85, 0x07, 0x91, 0x44, 0x57, 0x76,
	0x67, 0x16, 0x97, 0x86, 0x01, 0x20, 0x30, 0x06,
	0x82, 0x01, 0x18, 0x84, 0x01, 0x04, 0x00, 0x00,
	0x00, 0x00, 0xa3, 0x06, 0x04, 0x01, 0x42, 0x84,
	0x01, 0x05, 0xa3, 0x06, 0x04, 0x01, 0x51, 0x84,
	0x01, 0x05, 0xa3, 0x06, 0x04, 0x01, 0x31, 0x84,
	0x01, 0x05, 0xa3, 0x09, 0x04, 0x01, 0x12, 0x84,
	0x01, 0x05, 0x82, 0x01, 0x02, 0xa3, 0x09, 0x04,
	0x01, 0x11, 0x84, 0x01, 0x05, 0x81, 0x01, 0x01,
	0xa3, 0x06, 0x04, 0x01, 0x14, 0x84, 0x01, 0x00,
	0xa3, 0x0b, 0x04, 0x01, 0x41, 0x84, 0x01, 0x04,
	0x30, 0x03, 0x83, 0x01, 0x10, 0xa3, 0x0b, 0x04,
	0x01, 0x41, 0x84, 0x01, 0x04, 0x30, 0x03, 0x82,
	0x01, 0x18, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t tcap_global_dst_gti[] = {
	0x00, 0x12, 0x04, 0x53, 0x84, 0x09, 0x00, 0x17,
};

static const uint8_t tcap_global_src_gti[] = {
	0x00, 0x12, 0x04, 0x44, 0x87, 0x20, 0x00, 0x20, 0x65,
};


struct test_data {
	int length;
	const uint8_t *data;
	int payload_start;
	int payload_length;
	uint8_t first_byte;

        /* in case it should trigger a sccp response */
	int write;
	const uint8_t  *response;
	int response_length;
};

static const struct test_data test_data[] = {
	{
		.length		= ARRAY_SIZE(bssmap_reset),
		.data		= &bssmap_reset[0],
		.payload_start	= 12,
		.payload_length = ARRAY_SIZE(bssmap_reset) - 12,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_reset_ack),
		.data		= &bssmap_reset_ack[0],
		.payload_start	= 16,
		.payload_length = ARRAY_SIZE(bssmap_reset_ack) - 16,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_paging),
		.data		= &bssmap_paging[0],
		.payload_start	= 16,
		.payload_length = ARRAY_SIZE(bssmap_paging) - 16,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_cr),
		.data		= &bssmap_cr[0],
		.payload_start	= 12,
		/* 0x00 is end of optional data, subtract this byte */
		.payload_length = 31,
		.first_byte	= 0x0,

		/* the connection request should trigger a connection confirm */
		.write		= 1,
		.response	= &bssmap_cc[0],
		.response_length= ARRAY_SIZE(bssmap_cc),
	},
	{
		.length		= ARRAY_SIZE(bssmap_dtap),
		.data		= &bssmap_dtap[0],
		.payload_start	= 7,
		.payload_length = 15,
		.first_byte	= 0x01,
	},
	{
		.length		= ARRAY_SIZE(bssmap_clear),
		.data		= &bssmap_clear[0],
		.payload_start	= 7,
		.payload_length = 6,
		.first_byte	= 0x00,
	},
	{
		.length		= ARRAY_SIZE(bssmap_released),
		.data		= &bssmap_released[0],
		.payload_length = 2,
		.payload_start  = 11,
		.first_byte	= 0x23,

		.write		= 1,
		.response	= &bssmap_release_complete[0],
		.response_length= ARRAY_SIZE(bssmap_release_complete),
	},
};

/* we will send UDTs and verify they look like this */
static const struct test_data send_data[] = {
	{
		.length		= ARRAY_SIZE(bssmap_udt),
		.data		= &bssmap_udt[0],
		.payload_start	= 12,
		.payload_length = ARRAY_SIZE(bssmap_udt) - 12,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_reset),
		.data		= &bssmap_reset[0],
		.payload_start	= 12,
		.payload_length = ARRAY_SIZE(bssmap_reset) - 12,
		.first_byte	= 0x0,
	},
};

struct connection_test {
	/* should the connection be refused? */
	int refuse;

	int with_data;

	/* on which side to close the connection? */
	int close_side;
	int close_cause;
};

/* sccp connection handling we want to test */
static const struct connection_test connection_tests[] = {
	{
		.refuse	= 1,
	},
	{
		.refuse	= 1,
		.with_data = 1,
	},
	{
		.refuse = 0,
		.close_side = 0,
		.close_cause = 5,
	},
	{
		.refuse = 0,
		.close_side = 0,
		.close_cause = 5,
		.with_data = 1,
	},
	{
		.refuse = 0,
		.close_side = 1,
		.close_cause = 5,
	},
	{
		.refuse = 0,
		.close_side = 1,
		.close_cause = 5,
		.with_data = 1,
	},
};

struct sccp_parse_header_result {
	/* results */
	int msg_type;
	int wanted_len;
	int src_ssn;
	int dst_ssn;

	int has_src_ref, has_dst_ref;
	struct sccp_source_reference src_ref;
	struct sccp_source_reference dst_ref;

	/* global title len */
	int src_gti_len;
	const uint8_t *src_gti_data;
	int dst_gti_len;
	const uint8_t *dst_gti_data;

	/* the input */
	const uint8_t *input;
	int input_len;
};

static const uint8_t it_test[] = {
0x10, 0x01, 0x07, 
0x94, 0x01, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00 };

static const uint8_t proto_err[] = {
0x0f, 0x0c, 0x04, 0x00, 0x00,
};

static const uint8_t xudt_test_src_gt[] = {
0x00, 0x11, 0x04, 0x26, 0x18, 0x01, 0x30, 0x08,
0x01
};

static const uint8_t xudt_test_dst_gt[] = {
0x00, 0x61, 0x04, 0x15, 0x10, 0x80, 0x21, 0x35,
0x98, 0x55, 0x08
};

static const uint8_t xudt_test[] = {
0x11, 0x81, 0x02, 0x04, 0x11, 0x1C, 0x00, 0x0D,
0x52, 0x06, 0x00, 0x61, 0x04, 0x15, 0x10, 0x80,
0x21, 0x35, 0x98, 0x55, 0x08, 0x0B, 0x12, 0x95,
0x00, 0x11, 0x04, 0x26, 0x18, 0x01, 0x30, 0x08,
0x01, 0x44, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
0x3F, 0x40, 0x41, 0x42, 0x43, 0x44
};

static const struct sccp_parse_header_result parse_result[] = {
	{
		.msg_type	= SCCP_MSG_TYPE_IT,
		.wanted_len	= 0,
		.src_ssn	= -1,
		.dst_ssn	= -1,
		.has_src_ref	= 1,
		.has_dst_ref	= 1,

		.src_ref	= {
			.octet1 = 0x01,
			.octet2 = 0x04,
			.octet3 = 0x00
		},
		.dst_ref	= {
			.octet1 = 0x01,
			.octet2 = 0x07,
			.octet3 = 0x94,
		},

		.input		= it_test,
		.input_len	= sizeof(it_test),
	},
	{
		.msg_type	= SCCP_MSG_TYPE_ERR,
		.wanted_len	= 0,
		.src_ssn	= -1,
		.dst_ssn	= -1,
		.has_src_ref	= 0,
		.has_dst_ref	= 1,
		.dst_ref	= {
			.octet1 = 0x0c,
			.octet2 = 0x04,
			.octet3 = 0x00,
		},
		.input		= proto_err,
		.input_len	= sizeof(proto_err),
	},
	{
		.msg_type	= SCCP_MSG_TYPE_UDT,
		.input		= tcap_global_title,
		.input_len	= sizeof(tcap_global_title),
		.wanted_len	= 154,
		.dst_ssn	= SCCP_SSN_VLR,
		.dst_gti_data	= tcap_global_dst_gti,
		.dst_gti_len	= 8,
		.src_ssn	= SCCP_SSN_HLR,
		.src_gti_data	= tcap_global_src_gti,
		.src_gti_len	= 9,
	},
	{
		.msg_type	= SCCP_MSG_TYPE_XUDT,
		.input		= xudt_test,
		.input_len	= sizeof(xudt_test),
		.wanted_len	= 68,
		.dst_ssn	= 6,
		.dst_gti_data	= xudt_test_dst_gt,
		.dst_gti_len	= 11,
		.src_ssn	= 149,
		.src_gti_data	= xudt_test_src_gt,
		.src_gti_len	= 9,
	},
};


/* testing procedure:
 *	- we will use sccp_write and see what will be set in the
 *	  outgoing callback
 *	- we will call sccp_system_incoming and see which calls
 *	  are made. And then compare it to the ones we expect. We
 *	  want the payload to arrive, or callbacks to be called.
 *	- we will use sccp_connection_socket and sccp_connection_write
 *	  and verify state handling of connections
 */

static int current_test;

/*
 * test state...
 */
static int called  = 0;
static int matched = 0;
static int write_called = 0;

#define FAIL(x, args...) do { \
	printf("FAILURE in %s:%d: " x, __FILE__, __LINE__, ## args); \
	abort(); } while (0)

/*
 * writing these packets and expecting a result
 */
int sccp_read_cb(struct msgb *data, unsigned len, void *gctx)
{
	uint16_t payload_length = test_data[current_test].payload_length;
	const uint8_t *got, *wanted;
	int i;

	called = 1;

	if (msgb_l3len(data) < len) {
		/* this should never be reached */
		FAIL("Something horrible happened.. invalid packet..\n");
	}

	if (len == 0 || len != payload_length) {
		FAIL("length mismatch: got: %d wanted: %d\n", msgb_l3len(data), payload_length);
	}

	if (data->l3h[0] !=  test_data[current_test].first_byte) {
		FAIL("The first bytes of l3 do not match: 0x%x 0x%x\n",
			data->l3h[0], test_data[current_test].first_byte);
	}

	got = &data->l3h[0];
	wanted = test_data[current_test].data + test_data[current_test].payload_start;

	for (i = 0; i < len; ++i) {
		if (got[i] != wanted[i]) {
			FAIL("Failed to compare byte. Got: 0x%x Wanted: 0x%x at %d\n",
			     got[i], wanted[i], i);
		}
	}

	matched = 1;
	return 0;
}

void sccp_write_cb(struct sccp_connection *conn, struct msgb *data, void *gctx, void *ctx)
{
	int i = 0;
	const uint8_t *got, *wanted;

	if (test_data[current_test].response == NULL) {
		FAIL("Didn't expect write callback\n");
	} else if (test_data[current_test].response_length != msgb_l2len(data)) {
		FAIL("Size does not match. Got: %d Wanted: %d\n",
		     msgb_l2len(data), test_data[current_test].response_length);
	}

	got = &data->l2h[0];
	wanted = test_data[current_test].response;

	for (i = 0; i < msgb_l2len(data); ++i) {
		if (got[i] != wanted[i]) {
			FAIL("Failed to compare byte. Got: 0x%x Wanted: 0x%x at %d\n",
			     got[i], wanted[i], i);
		}
	}

	write_called = 1;
	msgb_free(data);
}

void sccp_c_read(struct sccp_connection *connection, struct msgb *msgb, unsigned int len)
{
	sccp_read_cb(msgb, len, connection->data_ctx);
}

void sccp_c_state(struct sccp_connection *connection, int old_state)
{
	if (connection->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE)
		sccp_connection_free(connection);
}

int sccp_accept_cb(struct sccp_connection *connection, void *user_data)
{
	called = 1;
	unsigned int ref = 0;
	ref |= connection->destination_local_reference.octet1 << 24;
	ref |= connection->destination_local_reference.octet2 << 16;
	ref |= connection->destination_local_reference.octet3 <<  8;
	ref = ntohl(ref);

	connection->data_cb = sccp_c_read;
	connection->state_cb = sccp_c_state;

	/* accept this */
	return 0;
}

static void sccp_udt_write_cb(struct sccp_connection *conn, struct msgb *data, void *gtx, void *ctx)
{
	const uint8_t *got, *wanted;
	int i;

	write_called = 1;

	if (send_data[current_test].length != msgb_l2len(data)) {
		FAIL("Size does not match. Got: %d Wanted: %d\n",
		     msgb_l2len(data), send_data[current_test].length);
	}

	got = &data->l2h[0];
	wanted = send_data[current_test].data;

	for (i = 0; i < msgb_l2len(data); ++i) {
		if (got[i] != wanted[i]) {
			FAIL("Failed to compare byte. Got: 0x%x Wanted: 0x%x at %d\n",
			     got[i], wanted[i], i);
		}
	}

	matched = 1;
	msgb_free(data);
}

static void test_sccp_system(void)
{
	printf("Testing SCCP System\n");

	sccp_system_init(sccp_write_cb, NULL);
	sccp_set_read(&sccp_ssn_bssap, sccp_read_cb, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, sccp_accept_cb, NULL);

	for (current_test = 0; current_test < ARRAY_SIZE(test_data); ++current_test) {
		unsigned int length = test_data[current_test].length;
		struct msgb *msg = msgb_alloc_headroom(length + 2, 2, __func__);
		msg->l2h = msgb_put(msg, length);
		memcpy(msg->l2h, test_data[current_test].data, length);

		called = matched = write_called = 0;
		printf("Testing packet: %d\n", current_test);
		sccp_system_incoming(msg);

		if (!called || !matched || (test_data[current_test].write != write_called))
			FAIL("current test: %d called: %d matched: %d write: %d\n",
			     current_test, called, matched, write_called);

		msgb_free(msg);
	}
}

/* test sending of udt */
static void test_sccp_send_udt(void)
{
	printf("Testing send UDT\n");

	sccp_system_init(sccp_udt_write_cb, NULL);
	sccp_set_read(NULL, NULL, NULL);
	sccp_connection_set_incoming(NULL, NULL, NULL);

	for (current_test = 0; current_test < ARRAY_SIZE(send_data); ++current_test) {
		const struct test_data *test = &send_data[current_test];

		struct msgb *msg = msgb_alloc(test->payload_length, __func__);
		msg->l3h = msgb_put(msg, test->payload_length);
		memcpy(msg->l3h, test->data + test->payload_start, test->payload_length);

		matched = write_called = 0;
		printf("Testing packet: %d\n", current_test);
		sccp_write(msg, &sccp_ssn_bssap, &sccp_ssn_bssap, 0, NULL);

		if (!matched || !write_called)
			FAIL("current test: %d matched: %d write: %d\n",
			     current_test, matched, write_called);

		msgb_free(msg);
	}
}

/* send udt from one end to another */
static unsigned int test_value = 0x2442;
static int sccp_udt_read(struct msgb *data, unsigned int len, void *gctx)
{
	unsigned int *val;

	if (len != 4) {
		FAIL("Wrong size: %d\n", msgb_l3len(data));
	}

	val = (unsigned int*)data->l3h;
	matched = test_value == *val;

	return 0;
}

static void sccp_write_loop(struct sccp_connection *conn, struct msgb *data, void *gctx, void *ctx)
{
	/* send it back to us */
	sccp_system_incoming(data);
	msgb_free(data);
}

static void test_sccp_udt_communication(void)
{
	struct msgb *data;
	unsigned int *val;

	printf("Testing UDT Communication.\n");

	sccp_system_init(sccp_write_loop, NULL);
	sccp_set_read(&sccp_ssn_bssap, sccp_udt_read, NULL);
	sccp_connection_set_incoming(NULL, NULL, NULL);


	data = msgb_alloc(4, "test data");
	data->l3h = &data->data[0];
	val = (unsigned int *)msgb_put(data, 4);
	*val = test_value;

	matched = 0;
	sccp_write(data, &sccp_ssn_bssap, &sccp_ssn_bssap, 0, NULL);

	if (!matched)
	    FAIL("Talking with us didn't work\n");

	msgb_free(data);
}


/* connection testing... open, send, close */
static const struct connection_test *current_con_test;
static struct sccp_connection *outgoing_con;
static struct sccp_connection *incoming_con;
static int outgoing_data, incoming_data, incoming_state, outgoing_state;

static struct msgb *test_data1, *test_data2, *test_data3;

static void sccp_conn_in_state(struct sccp_connection *conn, int old_state)
{
	printf("\tincome: %d -> %d\n", old_state, conn->connection_state);
	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		if (conn == incoming_con) {
			sccp_connection_free(conn);
			incoming_con = NULL;
		}
	}
}

static void sccp_conn_in_data(struct sccp_connection *conn, struct msgb *msg, unsigned int len)
{
	/* compare the data */
	++incoming_data;
	printf("\tincoming data: %d\n", len);

	/* compare the data */
	if (len != 4) {
		FAIL("Length of packet is wrong: %u %u\n", msgb_l3len(msg), len);
	}

	if (incoming_data == 1) {
		if (memcmp(msg->l3h, test_data1->l3h, len) != 0) {
			FAIL("Comparing the data failed: %d\n", incoming_data);

		}
	} else if (incoming_data == 2) {
		if (memcmp(msg->l3h, test_data2->l3h, len) != 0) {
			FAIL("Comparing the data failed: %d\n", incoming_data);
		}
	}

	/* sending out data */
	if (incoming_data == 2) {
		printf("\tReturning data3\n");
		sccp_connection_write(conn, test_data3);
	}
}

static int sccp_conn_accept(struct sccp_connection *conn, void *ctx)
{
	printf("\taccept: srcref(%u)\n",
		sccp_src_ref_to_int(&conn->source_local_reference));
	conn->state_cb = sccp_conn_in_state;
	conn->data_cb = sccp_conn_in_data;

	if (current_con_test->refuse)
		return -1;

	incoming_con = conn;
	return 0;
}

/* callbacks for the outgoing side */
static void sccp_conn_out_state(struct sccp_connection *conn, int old_state)
{
	printf("\toutgoing: dstref(%u) %d -> %d\n",
		sccp_src_ref_to_int(&conn->destination_local_reference),
		old_state, conn->connection_state);

	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		if (conn == outgoing_con) {
			sccp_connection_free(conn);
			outgoing_con = NULL;
		}
	}
}

static void sccp_conn_out_data(struct sccp_connection *conn, struct msgb *msg, unsigned int len)
{
	++outgoing_data;
	printf("\toutgoing data: dstref(%u) %d\n",
		sccp_src_ref_to_int(&conn->destination_local_reference), len);

	if (len != 4)
		FAIL("Length of packet is wrong: %u %u\n", msgb_l3len(msg), len);

	if (outgoing_data == 1) {
		if (memcmp(msg->l3h, test_data3->l3h, len) != 0) {
			FAIL("Comparing the data failed\n");
		}
	}
}

static void do_test_sccp_connection(const struct connection_test *test)
{
	int ret;

	current_con_test = test;
	outgoing_con = incoming_con = 0;

	outgoing_con = sccp_connection_socket();
	if (!outgoing_con) {
		FAIL("Connection is NULL\n");
	}

	outgoing_con->state_cb = sccp_conn_out_state;
	outgoing_con->data_cb = sccp_conn_out_data;
	outgoing_data = incoming_data = 0;
	incoming_state = outgoing_state = 1;

	/* start testing */
	if (test->with_data) {
		if (sccp_connection_connect(outgoing_con, &sccp_ssn_bssap, test_data1) != 0)
			FAIL("Binding failed\n");
	} else {
		++incoming_data;
		if (sccp_connection_connect(outgoing_con, &sccp_ssn_bssap, NULL) != 0)
			FAIL("Binding failed\n");
	}

	if (test->refuse) {
		if (outgoing_con)
			FAIL("Outgoing connection should have been refused.\n");
	} else {
		if (!incoming_con)
			FAIL("Creating incoming didn't work.\n");

		printf("\tWriting test data2\n");
		sccp_connection_write(outgoing_con, test_data2);
		sccp_connection_send_it(outgoing_con);

		/* closing connection */
		if (test->close_side == 0)
			ret = sccp_connection_close(outgoing_con, 0);
		else
			ret = sccp_connection_close(incoming_con, 0);

		if (ret != 0)
			FAIL("Closing the connection failed\n");
	}

	/* outgoing should be gone now */
	if (outgoing_con)
		FAIL("Outgoing connection was not properly closed\n");

	if (incoming_con)
		FAIL("Incoming connection was not propery closed.\n");

	if (test->refuse == 0) {
		if (outgoing_data != 1 || incoming_data != 2) {
			FAIL("Data sending failed: %d/%d %d/%d\n",
			     outgoing_data, 1,
			     incoming_data, 2);
		}
	}

	if (!incoming_state || !outgoing_state)
		FAIL("Failure with the state transition. %d %d\n",
		     outgoing_state, incoming_state);
}

static void test_sccp_connection(void)
{
	printf("Testing SCCP connection.\n");

	sccp_system_init(sccp_write_loop, NULL);
	sccp_set_read(NULL, NULL, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, sccp_conn_accept, NULL);

	test_data1 = msgb_alloc(4, "data1");
	test_data1->l3h = msgb_put(test_data1, 4);
	*((unsigned int*)test_data1->l3h) = 0x23421122;

	test_data2 = msgb_alloc(4, "data2");
	test_data2->l3h = msgb_put(test_data2, 4);
	*((unsigned int*)test_data2->l3h) = 0x42232211;

	test_data3 = msgb_alloc(4, "data3");
	test_data3->l3h = msgb_put(test_data3, 4);
	*((unsigned int*)test_data3->l3h) = 0x2323ff55;


	for (current_test = 0; current_test < ARRAY_SIZE(connection_tests); ++current_test) {
		printf("Testing %d refuse: %d with_data: %d\n",
			current_test, connection_tests[current_test].refuse,
			connection_tests[current_test].with_data);
		do_test_sccp_connection(&connection_tests[current_test]);
	}

	msgb_free(test_data1);
	msgb_free(test_data2);
	msgb_free(test_data3);
}

/* invalid input */
static void test_sccp_system_crash(void)
{
	printf("trying to provoke a crash with invalid input\n");
	sccp_set_read(&sccp_ssn_bssap, sccp_read_cb, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, sccp_accept_cb, NULL);

	for (current_test = 0; current_test < ARRAY_SIZE(test_data); ++current_test) {
		int original_length = test_data[current_test].length;
		int length = original_length + 2;
		int i;

		printf("Testing packet: %d\n", current_test);

		for (i = length; i >= 0; --i) {
			unsigned int length = MIN(test_data[current_test].length, i);
			struct msgb *msg = msgb_alloc_headroom(length + 2, 2, __func__);
			msg->l2h = msgb_put(msg, length);
			memcpy(msg->l2h, test_data[current_test].data, length);
			sccp_system_incoming(msg);
			msgb_free(msg);
		}
	}

	printf("survived\n");
}

static void test_sccp_parsing(void)
{
	printf("Test SCCP Parsing.\n");

	for (current_test = 0; current_test < ARRAY_SIZE(parse_result); ++current_test) {
		struct msgb *msg;
		struct sccp_parse_result result;

		msg = msgb_alloc_headroom(1024, 128, "parse-test");
		msgb_put(msg, 1);
		msg->l2h = msgb_put(msg, parse_result[current_test].input_len);
		memcpy(msg->l2h, parse_result[current_test].input, msgb_l2len(msg));

		memset(&result, 0, sizeof(result));
		if (sccp_parse_header(msg, &result) != 0) {
			FAIL("Failed to sccp parse test: %d\n", current_test);
		} else {
			if (parse_result[current_test].wanted_len != result.data_len) {
				FAIL("Unexpected data length. Got: %d\n", result.data_len);
			}

			if (parse_result[current_test].has_src_ref) {
				if (memcmp(result.source_local_reference,
					   &parse_result[current_test].src_ref,
					   sizeof(struct sccp_source_reference)) != 0) {
					FAIL("SRC REF did not match\n");
				}
			}

			if (parse_result[current_test].has_dst_ref) {
				if (memcmp(result.destination_local_reference,
					   &parse_result[current_test].dst_ref,
					   sizeof(struct sccp_source_reference)) != 0) {
					FAIL("DST REF did not match\n");
				}
			}

			if (parse_result[current_test].src_ssn != -1 &&
			    parse_result[current_test].src_ssn != result.calling.ssn) {
				FAIL("Calling SSN is wrong..\n");
			}

			if (parse_result[current_test].dst_ssn != -1 &&
			    parse_result[current_test].dst_ssn != result.called.ssn) {
				FAIL("Called SSN is wrong..\n");
			}

			if (parse_result[current_test].src_gti_len != result.calling.gti_len) {
				FAIL("GTI length is wrong: %d\n", result.calling.gti_len);
			}

			if (parse_result[current_test].dst_gti_len != result.called.gti_len) {
				FAIL("GTI length is wrong: %d\n", result.called.gti_len);
			}

			if (parse_result[current_test].dst_gti_data
			    && memcmp(&parse_result[current_test].dst_gti_data[0],
				      result.called.gti_data, result.called.gti_len) != 0) {
				FAIL("GTI data is wrong: %d '%s'\n",
				     result.called.gti_len,
				     osmo_hexdump(result.called.gti_data, result.called.gti_len));
			}

			if (parse_result[current_test].src_gti_data
			    && memcmp(&parse_result[current_test].src_gti_data[0],
				      result.calling.gti_data, result.calling.gti_len) != 0) {
				FAIL("GTI data is wrong: %d\n", result.calling.gti_len);
			}
		}

		msgb_free(msg);
	}
}

/*
 * Test the creation of SCCP addresses
 */
int sccp_create_sccp_addr(struct msgb *msg, const struct sockaddr_sccp *sock);

struct sccp_addr_tst {
	const struct sockaddr_sccp *addr;

	const uint8_t *output;
	const int output_len;
};

static uint8_t ssn_out[] = {
	0x02, 0x42, 0xfe,
};

const struct sockaddr_sccp sccp_poi_bssap = {
	.sccp_family	= 0,
	.sccp_ssn	= SCCP_SSN_BSSAP,
	.poi            = {0x01, 0x00},
	.use_poi        = 1,
};

static uint8_t poi_out[] = {
	0x04, 0x43, 0x01, 0x00, 0xfe,
};

static uint8_t gti_dat[] = {
	0x00, 0x12, 0x04, 0x53, 0x84, 0x09, 0x00, 0x17,
};

const struct sockaddr_sccp sccp_gti_bssap = {
	.sccp_family	= 0,
	.sccp_ssn	= 7,
	.gti_ind	= 4,
	.gti_len	= ARRAY_SIZE(gti_dat),
	.gti		= gti_dat,
};

static uint8_t gti_out[] = {
	0x0a, 0x12, 0x07, 0x00, 0x12, 0x04, 0x53, 0x84, 0x09, 0x00, 0x17,
};

static struct sccp_addr_tst sccp_addr_tst[] = {
	{
		.addr		= &sccp_ssn_bssap,
		.output		= ssn_out,
		.output_len	= ARRAY_SIZE(ssn_out),
	},
	{
		.addr		= &sccp_poi_bssap,
		.output		= poi_out,
		.output_len	= ARRAY_SIZE(poi_out),
	},
	{
		.addr		= &sccp_gti_bssap,
		.output		= gti_out,
		.output_len	= ARRAY_SIZE(gti_out),
	},
};

static void test_sccp_address(void)
{
	int i, ret;
	struct msgb *msg = msgb_alloc(128, "sccp-addr");

	printf("Test SCCP Address\n");

	for (i = 0; i < ARRAY_SIZE(sccp_addr_tst); ++i) {
		msgb_reset(msg);
		ret = sccp_create_sccp_addr(msg, sccp_addr_tst[i].addr);
		if (ret != sccp_addr_tst[i].output_len) {
			FAIL("Length is from for %d\n", i);
		}

		if (memcmp(msg->data, sccp_addr_tst[i].output, ret) != 0) {
			FAIL("Unexpected data for %d '%s'\n", i,
				osmo_hexdump(msg->data, ret));
		}
	}

	talloc_free(msg);
}

static const struct log_info_cat default_categories[] = {
	[0] = {
		.name = "DSCCP",
		.description = "DSCP",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static int null_flt(const struct log_context *ctx, struct log_target *target)
{
	return 1;
}

const struct log_info log_info = {
	.filter_fn = null_flt,
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	struct log_target *stderr_target;
	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);

	printf("Testing SCCP handling.\n");

	sccp_set_log_area(0);

	test_sccp_system();
	test_sccp_send_udt();
	test_sccp_udt_communication();
	test_sccp_connection();
	test_sccp_system_crash();
	test_sccp_parsing();
	test_sccp_address();
	printf("All tests passed.\n");
	return 0;
}

void db_store_counter(void) {}
