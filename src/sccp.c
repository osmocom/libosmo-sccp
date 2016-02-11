/*
 * SCCP management code
 *
 * (C) 2009, 2010, 2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009, 2010, 2013 by On-Waves
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/tlv.h>

#include <sccp/sccp.h>

// Unassigned debug area
static int DSCCP = 0;

static void *tall_sccp_ctx;
static LLIST_HEAD(sccp_connections);

#define SCCP_MSG_SIZE 4096
#define SCCP_MSG_HEADROOM 128

/* global data */
const struct sockaddr_sccp sccp_ssn_bssap = {
	.sccp_family	= 0,
	.sccp_ssn	= SCCP_SSN_BSSAP,
};

struct sccp_system {
	/* layer3 -> layer2 */
	void (*write_data)(struct sccp_connection *conn, struct msgb *data,
			   void *gctx, void *ctx);
	void *write_context;
};


static struct sccp_system sccp_system = {
	.write_data = NULL,
};

struct sccp_data_callback {
	/* connection based */
	int (*accept_cb)(struct sccp_connection *, void *);
	void *accept_context;

	/* connection less */
	int (*read_cb)(struct msgb *, unsigned int, void *);
	void *read_context;

	uint8_t ssn;
	struct llist_head callback;
};

static LLIST_HEAD(sccp_callbacks);

static struct sccp_data_callback *_find_ssn(uint8_t ssn)
{
	struct sccp_data_callback *cb;

	llist_for_each_entry(cb, &sccp_callbacks, callback) {
		if (cb->ssn == ssn)
			return cb;
	}

	/* need to add one */
	cb = talloc_zero(tall_sccp_ctx, struct sccp_data_callback);
	if (!cb) {
		LOGP(DSCCP, LOGL_ERROR, "Failed to allocate sccp callback.\n");
		return NULL;
	}

	cb->ssn = ssn;
	llist_add_tail(&cb->callback, &sccp_callbacks);
	return cb;
}


static void _send_msg(struct sccp_connection *conn, struct msgb *msg, void *ctx)
{
	sccp_system.write_data(conn, msg, sccp_system.write_context, ctx);
}

/*
 * parsing routines
 */
static int copy_address(struct sccp_address *addr, uint8_t offset, struct msgb *msgb)
{
	struct sccp_called_party_address *party;

	int room = msgb_l2len(msgb) - offset;
	uint8_t read = 0;
	uint8_t length;

	if (room <= 0) {
		LOGP(DSCCP, LOGL_ERROR, "Not enough room for an address: %u\n", room);
		return -1;
	}

	length = msgb->l2h[offset];
	if (room <= length) {
		LOGP(DSCCP, LOGL_ERROR, "Not enough room for optional data %u %u\n", room, length);
		return -1;
	}


	party = (struct sccp_called_party_address *)(msgb->l2h + offset + 1);
	if (party->point_code_indicator) {
		if (length <= read + 2) {
		    LOGP(DSCCP, LOGL_ERROR, "POI does not fit %u\n", length);
		    return -1;
		}


		memcpy(&addr->poi, &party->data[read], 2);
		read += 2;
	}

	if (party->ssn_indicator) {
		if (length <= read + 1) {
		    LOGP(DSCCP, LOGL_ERROR, "SSN does not fit %u\n", length);
		    return -1;
		}

		addr->ssn = party->data[read];
		read += 1;
	}

	/* copy the GTI over */
	if (party->global_title_indicator) {
		addr->gti_len = length - read - 1;
		addr->gti_data = &party->data[read];
	}

	addr->address = *party;
	return 0;
}

static int _sccp_parse_optional_data(const int offset,
				     struct msgb *msgb, struct sccp_optional_data *data)
{
	uint16_t room = msgb_l2len(msgb) - offset;
	uint16_t read = 0;

	while (room > read) {
		uint8_t type = msgb->l2h[offset + read];
		if (type == SCCP_PNC_END_OF_OPTIONAL)
			return 0;

		if (read + 1 >= room) {
			LOGP(DSCCP, LOGL_ERROR, "no place for length\n");
			return 0;
		}

		uint8_t length = msgb->l2h[offset + read + 1];
		read += 2 + length;


		if (room <= read) {
			LOGP(DSCCP, LOGL_ERROR,
			       "no space for the data: type: %d read: %d room: %d l2: %d\n",
			       type, read, room, msgb_l2len(msgb));
			return 0;
		}

		if (type == SCCP_PNC_DATA) {
			data->data_len = length;
			data->data_start = offset + read - length;
		}

	}

	return -1;
}

int _sccp_parse_connection_request(struct msgb *msgb, struct sccp_parse_result *result)
{
	static const uint32_t header_size =
			sizeof(struct sccp_connection_request);
	static const uint32_t optional_offset =
			offsetof(struct sccp_connection_request, optional_start);
	static const uint32_t called_offset =
			offsetof(struct sccp_connection_request, variable_called);

	struct sccp_connection_request *req = (struct sccp_connection_request *)msgb->l2h;
	struct sccp_optional_data optional_data;

	/* header check */
	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %u\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	/* copy out the calling and called address. Add the offset */
	if (copy_address(&result->called, called_offset + req->variable_called, msgb) != 0)
		return -1;

	result->source_local_reference = &req->source_local_reference;

	/*
	 * parse optional data.
	 */
	memset(&optional_data, 0, sizeof(optional_data));
	if (_sccp_parse_optional_data(optional_offset + req->optional_start, msgb, &optional_data) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "parsing of optional data failed.\n");
		return -1;
	}

	if (optional_data.data_len != 0) {
		msgb->l3h = &msgb->l2h[optional_data.data_start];
		result->data_len = optional_data.data_len;
	} else {
		result->data_len = 0;
	}

	return 0;
}

int _sccp_parse_connection_released(struct msgb *msgb, struct sccp_parse_result *result)
{
	static size_t header_size = sizeof(struct sccp_connection_released);
	static size_t optional_offset = offsetof(struct sccp_connection_released, optional_start);

	struct sccp_optional_data optional_data;
	struct sccp_connection_released *rls = (struct sccp_connection_released *) msgb->l2h;

	/* we don't have enough size for the struct */
	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb > header_size %u %zu\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	memset(&optional_data, 0, sizeof(optional_data));
	if (_sccp_parse_optional_data(optional_offset + rls->optional_start, msgb, &optional_data) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "parsing of optional data failed.\n");
		return -1;
	}

	result->source_local_reference = &rls->source_local_reference;
	result->destination_local_reference = &rls->destination_local_reference;

	if (optional_data.data_len != 0) {
		msgb->l3h = &msgb->l2h[optional_data.data_start];
		result->data_len = optional_data.data_len;
	} else {
		result->data_len = 0;
	}

	return 0;
}

int _sccp_parse_connection_refused(struct msgb *msgb, struct sccp_parse_result *result)
{
	static const uint32_t header_size =
			sizeof(struct sccp_connection_refused);
	static int optional_offset = offsetof(struct sccp_connection_refused, optional_start);

	struct sccp_optional_data optional_data;
	struct sccp_connection_refused *ref;

	/* header check */
	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %u\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	ref = (struct sccp_connection_refused *) msgb->l2h;

	result->destination_local_reference = &ref->destination_local_reference;

	memset(&optional_data, 0, sizeof(optional_data));
	if (_sccp_parse_optional_data(optional_offset + ref->optional_start, msgb, &optional_data) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "parsing of optional data failed.\n");
		return -1;
	}

	/* optional data */
	if (optional_data.data_len != 0) {
		msgb->l3h = &msgb->l2h[optional_data.data_start];
		result->data_len = optional_data.data_len;
	} else {
		result->data_len = 0;
	}

	return 0;
}

int _sccp_parse_connection_confirm(struct msgb *msgb, struct sccp_parse_result *result)
{
	static uint32_t header_size =
		    sizeof(struct sccp_connection_confirm);
	static const uint32_t optional_offset =
			offsetof(struct sccp_connection_confirm, optional_start);

	struct sccp_optional_data optional_data;
	struct sccp_connection_confirm *con;

	/* header check */
	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %u\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	con = (struct sccp_connection_confirm *) msgb->l2h;
	result->destination_local_reference = &con->destination_local_reference;
	result->source_local_reference = &con->source_local_reference;

	memset(&optional_data, 0, sizeof(optional_data));
	if (_sccp_parse_optional_data(optional_offset + con->optional_start, msgb, &optional_data) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "parsing of optional data failed.\n");
		return -1;
	}

	if (optional_data.data_len != 0) {
		msgb->l3h = &msgb->l2h[optional_data.data_start];
		result->data_len = optional_data.data_len;
	} else {
		result->data_len = 0;
	}

	return 0;
}

int _sccp_parse_connection_release_complete(struct msgb *msgb, struct sccp_parse_result *result)
{
	static size_t header_size = sizeof(struct sccp_connection_release_complete);

	struct sccp_connection_release_complete *cmpl;

	/* header check */
	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %zu\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	cmpl = (struct sccp_connection_release_complete *) msgb->l2h;
	result->source_local_reference = &cmpl->source_local_reference;
	result->destination_local_reference = &cmpl->destination_local_reference;

	return 0;
}

int _sccp_parse_connection_dt1(struct msgb *msgb, struct sccp_parse_result *result)
{
	static size_t header_size = sizeof(struct sccp_data_form1);
	static size_t variable_offset = offsetof(struct sccp_data_form1, variable_start);

	struct sccp_data_form1 *dt1 = (struct sccp_data_form1 *)msgb->l2h;

	/* we don't have enough size for the struct */
	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb > header_size %u %zu\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	if (dt1->segmenting != 0) {
		LOGP(DSCCP, LOGL_ERROR, "This packet has segmenting, not supported: %d\n", dt1->segmenting);
		return -1;
	}

	result->destination_local_reference = &dt1->destination_local_reference;

	/* some more  size checks in here */
	if (msgb_l2len(msgb) < variable_offset + dt1->variable_start + 1) {
		LOGP(DSCCP, LOGL_ERROR, "Not enough space for variable start: %u %u\n",
			msgb_l2len(msgb), dt1->variable_start);
		return -1;
	}

	result->data_len = msgb->l2h[variable_offset + dt1->variable_start];
	msgb->l3h = &msgb->l2h[dt1->variable_start + variable_offset + 1];

	if (msgb_l3len(msgb) < result->data_len) {
		LOGP(DSCCP, LOGL_ERROR, "Not enough room for the payload: %u %u\n",
			msgb_l3len(msgb), result->data_len);
		return -1;
	}

	return 0;
}

int _sccp_parse_udt(struct msgb *msgb, struct sccp_parse_result *result)
{
	static const uint32_t header_size = sizeof(struct sccp_data_unitdata);
	static const uint32_t called_offset = offsetof(struct sccp_data_unitdata, variable_called);
	static const uint32_t calling_offset = offsetof(struct sccp_data_unitdata, variable_calling);
	static const uint32_t data_offset = offsetof(struct sccp_data_unitdata, variable_data);

	struct sccp_data_unitdata *udt = (struct sccp_data_unitdata *)msgb->l2h;

	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %u\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	/* copy out the calling and called address. Add the off */
	if (copy_address(&result->called, called_offset + udt->variable_called, msgb) != 0)
		return -1;

	if (copy_address(&result->calling, calling_offset + udt->variable_calling, msgb) != 0)
		return -1;

	/* we don't have enough size for the data */
	if (msgb_l2len(msgb) < data_offset + udt->variable_data + 1) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header + offset %u %u %u\n",
			msgb_l2len(msgb), header_size, udt->variable_data);
		return -1;
	}


	msgb->l3h = &udt->data[udt->variable_data];
	result->data_len = msgb_l3len(msgb);

	if (msgb_l3len(msgb) <  msgb->l3h[-1]) {
		LOGP(DSCCP, LOGL_ERROR, "msgb is truncated is: %u should: %u\n",
			msgb_l3len(msgb), msgb->l3h[-1]);
		return -1;
	}

	return 0;
}

static int _sccp_parse_it(struct msgb *msgb, struct sccp_parse_result *result)
{
	static const uint32_t header_size = sizeof(struct sccp_data_it);

	struct sccp_data_it *it;

	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %u\n",
		        msgb_l2len(msgb), header_size);
		return -1;
	}

	it = (struct sccp_data_it *) msgb->l2h;
	result->data_len = 0;
	result->source_local_reference = &it->source_local_reference;
	result->destination_local_reference = &it->destination_local_reference;
	return 0;
}

static int _sccp_parse_err(struct msgb *msgb, struct sccp_parse_result *result)
{
	static const uint32_t header_size = sizeof(struct sccp_proto_err);

	struct sccp_proto_err *err;

	if (msgb_l2len(msgb) < header_size) {
		LOGP(DSCCP, LOGL_ERROR, "msgb < header_size %u %u\n",
		     msgb_l2len(msgb), header_size);
		return -1;
	}

	err = (struct sccp_proto_err *) msgb->l2h;
	result->data_len = 0;
	result->destination_local_reference = &err->destination_local_reference;
	return 0;
}

int sccp_create_sccp_addr(struct msgb *msg, const struct sockaddr_sccp *sock)
{
	uint8_t *len, *ai, *gti;

	len = msgb_put(msg, 1);
	ai = msgb_put(msg, 1);


	if (sock->gti)
		ai[0] = 0 << 6 | (sock->gti_ind & 0x0f) << 2 | 1 << 1;
	else
		ai[0] = 1 << 6 | 1 << 1;

	/* store a point code */
	if (sock->use_poi) {
		uint8_t *poi;

		ai[0] |= 0x01;
		poi = msgb_put(msg, 2);
		poi[0] = sock->poi[0];
		poi[1] = sock->poi[1];
	}

	/* copy the SSN */
	msgb_v_put(msg, sock->sccp_ssn);

	/* copy the gti if it is present */
	gti = msgb_put(msg, sock->gti_len);
	memcpy(gti, sock->gti, sock->gti_len);

	/* update the length now */
	len[0] = msg->tail - len - 1;
	return len[0] + 1;
}

/*
 * Send UDT. Currently we have a fixed address...
 */
struct msgb *sccp_create_udt(int class, const struct sockaddr_sccp *in,
			     const struct sockaddr_sccp *out, uint8_t *in_data, int len)
{
	struct sccp_data_unitdata *udt;
	uint8_t *data;
	int out_len, inp_len;

	if (len > 256) {
		LOGP(DSCCP, LOGL_ERROR, "The payload is too big for one udt\n");
		return NULL;
	}

	struct msgb *msg = msgb_alloc_headroom(SCCP_MSG_SIZE,
					       SCCP_MSG_HEADROOM, "sccp: udt");
	if (!msg)
		return NULL;

	msg->l2h = &msg->data[0];
	udt = (struct sccp_data_unitdata *)msgb_put(msg, sizeof(*udt));

	udt->type = SCCP_MSG_TYPE_UDT;
	udt->proto_class = class;

	/* for variable data we start with a size and the data */
	out_len = sccp_create_sccp_addr(msg, out);
	inp_len = sccp_create_sccp_addr(msg, in);

	/* update the offsets now */
	udt->variable_called = 3;
	udt->variable_calling = 2 + out_len;
	udt->variable_data = 1 + out_len + inp_len;

	/* copy the payload */
	data = msgb_put(msg, 1 + len);
	data[0] = len;
	memcpy(&data[1], in_data, len);

	return msg;
}

static int _sccp_send_data(int class, const struct sockaddr_sccp *in,
			   const struct sockaddr_sccp *out,
			   struct msgb *payload, void *ctx)
{
	struct msgb *msg;

	msg = sccp_create_udt(class, in, out, payload->l3h, msgb_l3len(payload));
	if (!msg)
		return -1;

	_send_msg(NULL, msg, ctx);
	return 0;
}

static int _sccp_handle_read(struct msgb *msgb)
{
	struct sccp_data_callback *cb;
	struct sccp_parse_result result;

	if (_sccp_parse_udt(msgb, &result) != 0)
		return -1;

	cb = _find_ssn(result.called.ssn);
	if (!cb || !cb->read_cb) {
		LOGP(DSCCP, LOGL_ERROR, "No routing for UDT for called SSN: %u\n", result.called.ssn);
		return -1;
	}

	/* sanity check */
	return cb->read_cb(msgb, msgb_l3len(msgb), cb->read_context);
}

/*
 * handle connection orientated methods
 */
static int source_local_reference_is_free(struct sccp_source_reference *reference)
{
	struct sccp_connection *connection;

	llist_for_each_entry(connection, &sccp_connections, list) {
		if (memcmp(reference, &connection->source_local_reference, sizeof(*reference)) == 0)
			return -1;
	}

	return 0;
}

static int destination_local_reference_is_free(struct sccp_source_reference *reference)
{
	struct sccp_connection *connection;

	llist_for_each_entry(connection, &sccp_connections, list) {
		if (memcmp(reference, &connection->destination_local_reference, sizeof(*reference)) == 0)
			return -1;
	}

	return 0;
}

static int assign_source_local_reference(struct sccp_connection *connection)
{
	static uint32_t last_ref = 0x30000;
	int wrapped = 0;

	do {
		struct sccp_source_reference reference;
		reference.octet1 = (last_ref >>  0) & 0xff;
		reference.octet2 = (last_ref >>  8) & 0xff;
		reference.octet3 = (last_ref >> 16) & 0xff;

		++last_ref;
		/* do not use the reversed word and wrap around */
		if ((last_ref & 0x00FFFFFF) == 0x00FFFFFF) {
			LOGP(DSCCP, LOGL_DEBUG, "Wrapped searching for a free code\n");
			last_ref = 0;
			++wrapped;
		}

		if (source_local_reference_is_free(&reference) == 0) {
			connection->source_local_reference = reference;
			return 0;
		}
	} while (wrapped != 2);

	LOGP(DSCCP, LOGL_ERROR, "Finding a free reference failed\n");
	return -1;
}

static void _sccp_set_connection_state(struct sccp_connection *connection, int new_state)
{
	int old_state = connection->connection_state;

	connection->connection_state = new_state;
	if (connection->state_cb)
		connection->state_cb(connection, old_state);
}

struct msgb *sccp_create_refuse(struct sccp_source_reference *src_ref, int cause, uint8_t *inp, int length)
{
	struct msgb *msgb;
	struct sccp_connection_refused *ref;
	uint8_t *data;

	msgb = msgb_alloc_headroom(SCCP_MSG_SIZE,
				   SCCP_MSG_HEADROOM, "sccp ref");
	if (!msgb) {
		LOGP(DSCCP, LOGL_ERROR, "Failed to allocate refusal msg.\n");
		return NULL;
	}

	msgb->l2h = &msgb->data[0];

	ref = (struct sccp_connection_refused *) msgb_put(msgb, sizeof(*ref));
	ref->type = SCCP_MSG_TYPE_CREF;
	memcpy(&ref->destination_local_reference, src_ref,
	       sizeof(struct sccp_source_reference));
	ref->cause = cause;
	ref->optional_start = 1;

	if (inp) {
		data = msgb_put(msgb, 1 + 1 + length);
		data[0] = SCCP_PNC_DATA;
		data[1] = length;
		memcpy(&data[2], inp, length);
	}

	data = msgb_put(msgb, 1);
	data[0] = SCCP_PNC_END_OF_OPTIONAL;
	return msgb;
}

static int _sccp_send_refuse(struct sccp_source_reference *src_ref, int cause, void *ctx)
{
	struct msgb *msgb = sccp_create_refuse(src_ref, cause, NULL, 0);
	if (!msgb)
		return -1;

	_send_msg(NULL, msgb, ctx);
	return 0;
}

struct msgb *sccp_create_cc(struct sccp_source_reference *src_ref,
			    struct sccp_source_reference *dst_ref)
{
	struct msgb *response;
	struct sccp_connection_confirm *confirm;
	uint8_t *optional_data;

	response = msgb_alloc_headroom(SCCP_MSG_SIZE,
				       SCCP_MSG_HEADROOM, "sccp confirm");
	if (!response) {
		LOGP(DSCCP, LOGL_ERROR, "Failed to create SCCP Confirm.\n");
		return NULL;
	}

	response->l2h = &response->data[0];

	confirm = (struct sccp_connection_confirm *) msgb_put(response, sizeof(*confirm));

	confirm->type = SCCP_MSG_TYPE_CC;
	memcpy(&confirm->destination_local_reference,
	       dst_ref, sizeof(*dst_ref));
	memcpy(&confirm->source_local_reference,
	       src_ref, sizeof(*src_ref));
	confirm->proto_class = 2;
	confirm->optional_start = 1;

	optional_data = (uint8_t *) msgb_put(response, 1);
	optional_data[0] = SCCP_PNC_END_OF_OPTIONAL;
	return response;
}

static int _sccp_send_connection_confirm(struct sccp_connection *connection)
{
	struct msgb *response;

	if (assign_source_local_reference(connection) != 0)
		return -1;

	response = sccp_create_cc(&connection->source_local_reference,
				  &connection->destination_local_reference);
	if (!response)
		return -1;

	_send_msg(connection, response, NULL);
	_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_ESTABLISHED);
	return 0;
}

struct msgb *sccp_create_cr(const struct sccp_source_reference *src_ref,
				const struct sockaddr_sccp *called,
				const uint8_t *l3_data, size_t l3_length)
{
	struct msgb *request;
	struct sccp_connection_request *req;
	uint8_t *data;
	uint8_t extra_size = 3 + 1;
	int called_len;

	if (l3_data && (l3_length < 3 || l3_length > 130)) {
		LOGP(DSCCP, LOGL_ERROR, "Invalid amount of data... %zu\n", l3_length);
		return NULL;
	}

	if (l3_data)
		extra_size += 2 + l3_length;
	request = msgb_alloc_headroom(SCCP_MSG_SIZE,
				      SCCP_MSG_HEADROOM, "sccp connection request");
	request->l2h = &request->data[0];
	req = (struct sccp_connection_request *) msgb_put(request, sizeof(*req));

	req->type = SCCP_MSG_TYPE_CR;
	memcpy(&req->source_local_reference, src_ref, sizeof(*src_ref));
	req->proto_class = 2;

	/* write the called party address */
	called_len = sccp_create_sccp_addr(request, called);

	/* update the offsets */
	req->variable_called = 2;
	req->optional_start = 1 + called_len;

	/* write the payload */
	if (l3_data) {
	    data = msgb_put(request, 2 + l3_length);
	    data[0] = SCCP_PNC_DATA;
	    data[1] = l3_length;
	    memcpy(&data[2], l3_data, l3_length);
	}

	data = msgb_put(request, 1);
	data[0] = SCCP_PNC_END_OF_OPTIONAL;

	return request;
}

static int _sccp_send_connection_request(struct sccp_connection *connection,
					 const struct sockaddr_sccp *called, struct msgb *msg)
{
	struct msgb *request;

	/* try to find an id */
	if (assign_source_local_reference(connection) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "Assigning a local reference failed.\n");
		_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_SETUP_ERROR);
		return -1;
	}

	request = sccp_create_cr(&connection->source_local_reference, called,
				msg ? msg->l3h : NULL,
				msg ? msgb_l3len(msg) : 0);
	if (!request) {
		_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_SETUP_ERROR);
		return -1;
	}

	llist_add_tail(&connection->list, &sccp_connections);
	_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_REQUEST);

	_send_msg(connection, request, NULL);
	return 0;
}

struct msgb *sccp_create_dt1(struct sccp_source_reference *dst_ref, uint8_t *inp_data, uint8_t len)
{
	struct msgb *msgb;
	struct sccp_data_form1 *dt1;
	uint8_t *data;

	msgb = msgb_alloc_headroom(SCCP_MSG_SIZE,
				   SCCP_MSG_HEADROOM, "sccp dt1");
	if (!msgb) {
		LOGP(DSCCP, LOGL_ERROR, "Failed to create DT1 msg.\n");
		return NULL;
	}

	msgb->l2h = &msgb->data[0];

	dt1 = (struct sccp_data_form1 *) msgb_put(msgb, sizeof(*dt1));
	dt1->type = SCCP_MSG_TYPE_DT1;
	memcpy(&dt1->destination_local_reference, dst_ref,
	       sizeof(struct sccp_source_reference));
	dt1->segmenting = 0;

	/* copy the data */
	dt1->variable_start = 1;
	data = msgb_put(msgb, 1 + len);
	data[0] = len;
	memcpy(&data[1], inp_data, len);

	return msgb;
}

static int _sccp_send_connection_data(struct sccp_connection *conn, struct msgb *_data)
{
	struct msgb *msgb;

	if (msgb_l3len(_data) < 2 || msgb_l3len(_data) > 256) {
		LOGP(DSCCP, LOGL_ERROR, "data size too big, segmenting unimplemented.\n");
		return -1;
	}

	msgb = sccp_create_dt1(&conn->destination_local_reference,
			       _data->l3h, msgb_l3len(_data));
	if (!msgb)
		return -1;

	_send_msg(conn, msgb, NULL);
	return 0;
}

static int _sccp_send_connection_it(struct sccp_connection *conn)
{
	struct msgb *msgb;
	struct sccp_data_it *it;

	msgb = msgb_alloc_headroom(SCCP_MSG_SIZE,
				   SCCP_MSG_HEADROOM, "sccp it");
	msgb->l2h = &msgb->data[0];
	it = (struct sccp_data_it *) msgb_put(msgb, sizeof(*it));
	it->type = SCCP_MSG_TYPE_IT;
	memcpy(&it->destination_local_reference, &conn->destination_local_reference,
		sizeof(struct sccp_source_reference));
	memcpy(&it->source_local_reference, &conn->source_local_reference,
		sizeof(struct sccp_source_reference));

	it->proto_class = 0x2;
	it->sequencing[0] = it->sequencing[1] = 0;
	it->credit = 0;

	_send_msg(conn, msgb, NULL);
	return 0;
}

struct msgb *sccp_create_rlsd(struct sccp_source_reference *src_ref,
			      struct sccp_source_reference *dst_ref, int cause)
{
	struct msgb *msg;
	struct sccp_connection_released *rel;
	uint8_t *data;

	msg = msgb_alloc_headroom(SCCP_MSG_SIZE, SCCP_MSG_HEADROOM,
				  "sccp: connection released");
	if (!msg) {
		LOGP(DSCCP, LOGL_ERROR, "Failed to allocate RLSD.\n");
		return NULL;
	}

	msg->l2h = &msg->data[0];
	rel = (struct sccp_connection_released *) msgb_put(msg, sizeof(*rel));
	rel->type = SCCP_MSG_TYPE_RLSD;
	rel->release_cause = cause;

	/* copy the source references */
	memcpy(&rel->destination_local_reference, dst_ref,
	       sizeof(struct sccp_source_reference));
	memcpy(&rel->source_local_reference, src_ref,
	       sizeof(struct sccp_source_reference));

	data = msgb_put(msg, 1);
	data[0] = SCCP_PNC_END_OF_OPTIONAL;
	return msg;
}

static int _sccp_send_connection_released(struct sccp_connection *conn, int cause)
{
	struct msgb *msg;

	msg = sccp_create_rlsd(&conn->source_local_reference,
			       &conn->destination_local_reference,
			       cause);
	if (!msg)
		return -1;

	_sccp_set_connection_state(conn, SCCP_CONNECTION_STATE_RELEASE);
	_send_msg(conn, msg, NULL);
	return 0;
}

/*
 * Open a connection. The following is going to happen:
 *
 *	- Verify the packet, e.g. that we have no other connection
 *	  that id.
 *      - Ask the user if he wants to accept the connection
 *      - Try to open the connection by assigning a source local reference
 *        and sending the packet
 */
static int _sccp_handle_connection_request(struct msgb *msgb, void *ctx)
{
	struct sccp_parse_result result;

	struct sccp_data_callback *cb;
	struct sccp_connection *connection;

	if (_sccp_parse_connection_request(msgb, &result) != 0)
		return -1;

	cb = _find_ssn(result.called.ssn);
	if (!cb || !cb->accept_cb) {
		LOGP(DSCCP, LOGL_ERROR, "No routing for CR for called SSN: %u\n", result.called.ssn);
		return -1;
	}

	/* check if the system wants this connection */
	connection = talloc_zero(tall_sccp_ctx, struct sccp_connection);
	if (!connection) {
		LOGP(DSCCP, LOGL_ERROR, "Allocation failed\n");
		return -1;
	}

	/*
	 * sanity checks:
	 *	- Is the source_local_reference in any other connection?
	 * then will call accept, assign a "destination" local reference
	 * and send a connection confirm, otherwise we will send a refuseed
	 * one....
	 */
	if (destination_local_reference_is_free(result.source_local_reference) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "Need to reject connection with existing reference\n");
		_sccp_send_refuse(result.source_local_reference, SCCP_REFUSAL_SCCP_FAILURE, ctx);
		talloc_free(connection);
		return -1;
	}

	connection->incoming = 1;
	connection->destination_local_reference = *result.source_local_reference;

	if (cb->accept_cb(connection, cb->accept_context) != 0) {
		_sccp_send_refuse(result.source_local_reference, SCCP_REFUSAL_END_USER_ORIGINATED, ctx);
		_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_REFUSED);
		talloc_free(connection);
		return 0;
	}


	llist_add_tail(&connection->list, &sccp_connections);

	if (_sccp_send_connection_confirm(connection) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "Sending confirm failed... no available source reference?\n");

		_sccp_send_refuse(result.source_local_reference, SCCP_REFUSAL_SCCP_FAILURE, ctx);
		_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_REFUSED);
		llist_del(&connection->list);
		talloc_free(connection);

		return -1;
	}

	/*
	 * If we have data let us forward things.
	 */
	if (result.data_len != 0 && connection->data_cb) {
		connection->data_cb(connection, msgb, result.data_len);
	}

	return 0;
}

/* Handle the release confirmed */
static int _sccp_handle_connection_release_complete(struct msgb *msgb)
{
	struct sccp_parse_result result;
	struct sccp_connection *conn;

	if (_sccp_parse_connection_release_complete(msgb, &result) != 0)
		return -1;

	/* find the connection */
	llist_for_each_entry(conn, &sccp_connections, list) {
		if (conn->data_cb
		    && memcmp(&conn->source_local_reference,
			      result.destination_local_reference,
			      sizeof(conn->source_local_reference)) == 0
		    && memcmp(&conn->destination_local_reference,
			      result.source_local_reference,
			      sizeof(conn->destination_local_reference)) == 0) {
		    goto found;
		}
	}


	LOGP(DSCCP, LOGL_ERROR, "Release complete of unknown connection\n");
	return -1;

found:
	llist_del(&conn->list);
	_sccp_set_connection_state(conn, SCCP_CONNECTION_STATE_RELEASE_COMPLETE);
	return 0;
}

/* Handle the Data Form 1 message */
static int _sccp_handle_connection_dt1(struct msgb *msgb)
{
	struct sccp_parse_result result;
	struct sccp_connection *conn;

	if (_sccp_parse_connection_dt1(msgb, &result) != 0)
		return -1;

	/* lookup if we have a connection with the given reference */
	llist_for_each_entry(conn, &sccp_connections, list) {
		if (conn->data_cb
		    && memcmp(&conn->source_local_reference,
			      result.destination_local_reference,
			      sizeof(conn->source_local_reference)) == 0) {
			goto found;
		}
	}

	LOGP(DSCCP, LOGL_ERROR, "No connection found for dt1 data\n");
	return -1;

found:
	conn->data_cb(conn, msgb, result.data_len);
	return 0;
}

/* confirm a connection release */
static int _sccp_send_connection_release_complete(struct sccp_connection *connection)
{
	struct msgb *msgb;
	struct sccp_connection_release_complete *rlc;

	msgb = msgb_alloc_headroom(SCCP_MSG_SIZE,
				   SCCP_MSG_HEADROOM, "sccp rlc");
	msgb->l2h = &msgb->data[0];

	rlc = (struct sccp_connection_release_complete *) msgb_put(msgb, sizeof(*rlc));
	rlc->type = SCCP_MSG_TYPE_RLC;
	memcpy(&rlc->destination_local_reference,
	       &connection->destination_local_reference, sizeof(struct sccp_source_reference));
	memcpy(&rlc->source_local_reference,
	       &connection->source_local_reference, sizeof(struct sccp_source_reference));

	_send_msg(connection, msgb, NULL);

	/*
	 * Remove from the list of active connections and set the state. User code
	 * should now free the entry.
	 */
	llist_del(&connection->list);
	_sccp_set_connection_state(connection, SCCP_CONNECTION_STATE_RELEASE_COMPLETE);
	return 0;
}

/* connection released, send a released confirm */
static int _sccp_handle_connection_released(struct msgb *msgb)
{
	struct sccp_parse_result result;
	struct sccp_connection *conn;

	if (_sccp_parse_connection_released(msgb, &result) == -1)
		return -1;

	/* lookup if we have a connection with the given reference */
	llist_for_each_entry(conn, &sccp_connections, list) {
		if (conn->data_cb
		    && memcmp(&conn->source_local_reference,
			      result.destination_local_reference,
			      sizeof(conn->source_local_reference)) == 0
		    && memcmp(&conn->destination_local_reference,
			      result.source_local_reference,
			      sizeof(conn->destination_local_reference)) == 0) {
		    goto found;
		}
	}


	LOGP(DSCCP, LOGL_ERROR, "Unknown connection was released.\n");
	return -1;

	/* we have found a connection */
found:
	/* optional data */
	if (result.data_len != 0 && conn->data_cb) {
		conn->data_cb(conn, msgb, result.data_len);
	}

	/* generate a response */
	if (_sccp_send_connection_release_complete(conn) != 0) {
		LOGP(DSCCP, LOGL_ERROR, "Sending release confirmed failed\n");
		return -1;
	}

	return 0;
}

static int _sccp_handle_connection_refused(struct msgb *msgb)
{
	struct sccp_parse_result result;
	struct sccp_connection *conn;

	if (_sccp_parse_connection_refused(msgb, &result) != 0)
		return -1;

	/* lookup if we have a connection with the given reference */
	llist_for_each_entry(conn, &sccp_connections, list) {
		if (conn->incoming == 0 && conn->data_cb
		    && memcmp(&conn->source_local_reference,
			      result.destination_local_reference,
			      sizeof(conn->source_local_reference)) == 0) {
		    goto found;
		}
	}

	LOGP(DSCCP, LOGL_ERROR, "Refused but no connection found\n");
	return -1;

found:
	/* optional data */
	if (result.data_len != 0 && conn->data_cb) {
		conn->data_cb(conn, msgb, result.data_len);
	}


	llist_del(&conn->list);
	_sccp_set_connection_state(conn, SCCP_CONNECTION_STATE_REFUSED);
	return 0;
}

static int _sccp_handle_connection_confirm(struct msgb *msgb)
{
	struct sccp_parse_result result;
	struct sccp_connection *conn;

	if (_sccp_parse_connection_confirm(msgb, &result) != 0)
		return -1;

	/* lookup if we have a connection with the given reference */
	llist_for_each_entry(conn, &sccp_connections, list) {
		if (conn->incoming == 0 && conn->data_cb
		    && memcmp(&conn->source_local_reference,
			      result.destination_local_reference,
			      sizeof(conn->source_local_reference)) == 0) {
		    goto found;
		}
	}

	LOGP(DSCCP, LOGL_ERROR, "Confirmed but no connection found\n");
	return -1;

found:
	/* copy the addresses of the connection */
	conn->destination_local_reference = *result.source_local_reference;
	_sccp_set_connection_state(conn, SCCP_CONNECTION_STATE_ESTABLISHED);

	/* optional data */
	if (result.data_len != 0 && conn->data_cb) {
		conn->data_cb(conn, msgb, result.data_len);
	}

	return 0;
}


int sccp_system_init(void (*outgoing)(struct sccp_connection *conn, struct msgb *data, void *, void *), void *ctx)
{
	sccp_system.write_data = outgoing;
	sccp_system.write_context = ctx;

	return 0;
}

/* oh my god a real SCCP packet. need to dispatch it now */
int sccp_system_incoming(struct msgb *msgb)
{
	return sccp_system_incoming_ctx(msgb, NULL);
}

int sccp_system_incoming_ctx(struct msgb *msgb, void *ctx)
{
	if (msgb_l2len(msgb) < 1 ) {
		LOGP(DSCCP, LOGL_ERROR, "Too short packet\n");
		return -1;
	}

	int type = msgb->l2h[0];

	switch(type) {
	case SCCP_MSG_TYPE_CR:
		return _sccp_handle_connection_request(msgb, ctx);
		break;
	case SCCP_MSG_TYPE_RLSD:
		return _sccp_handle_connection_released(msgb);
		break;
	case SCCP_MSG_TYPE_CREF:
		return _sccp_handle_connection_refused(msgb);
		break;
	case SCCP_MSG_TYPE_CC:
		return _sccp_handle_connection_confirm(msgb);
		break;
	case SCCP_MSG_TYPE_RLC:
		return _sccp_handle_connection_release_complete(msgb);
		break;
	case SCCP_MSG_TYPE_DT1:
		return _sccp_handle_connection_dt1(msgb);
		break;
	case SCCP_MSG_TYPE_UDT:
		return _sccp_handle_read(msgb);
		break;
	default:
		LOGP(DSCCP, LOGL_ERROR, "unimplemented msg type: %d\n", type);
	};

	return -1;
}

/* create a packet from the data */
int sccp_connection_write(struct sccp_connection *connection, struct msgb *data)
{
	if (connection->connection_state < SCCP_CONNECTION_STATE_CONFIRM
	    || connection->connection_state > SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DSCCP, LOGL_ERROR, "sccp_connection_write: Wrong connection state: %p %d\n",
		       connection, connection->connection_state);
		return -1;
	}

	return _sccp_send_connection_data(connection, data);
}

/*
 * Send a Inactivity Test message. The owner of the connection
 * should start a timer and call this method regularily. Calling
 * this every 60 seconds should be good enough.
 */
int sccp_connection_send_it(struct sccp_connection *connection)
{
	if (connection->connection_state < SCCP_CONNECTION_STATE_CONFIRM
	    || connection->connection_state > SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DSCCP, LOGL_ERROR, "sccp_connection_write: Wrong connection state: %p %d\n",
		       connection, connection->connection_state);
		return -1;
	}

	return _sccp_send_connection_it(connection);
}

/* send a connection release and wait for the connection released */
int sccp_connection_close(struct sccp_connection *connection, int cause)
{
	if (connection->connection_state < SCCP_CONNECTION_STATE_CONFIRM
	    || connection->connection_state > SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DSCCP, LOGL_ERROR, "Can not close the connection. It was never opened: %p %d\n",
			connection, connection->connection_state);
		return -1;
	}

	return _sccp_send_connection_released(connection, cause);
}

int sccp_connection_free(struct sccp_connection *connection)
{
	if (connection->connection_state > SCCP_CONNECTION_STATE_NONE
	    && connection->connection_state < SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		LOGP(DSCCP, LOGL_ERROR, "The connection needs to be released before it is freed");
		return -1;
	}

	talloc_free(connection);
	return 0;
}

int sccp_connection_force_free(struct sccp_connection *con)
{
	if (con->connection_state > SCCP_CONNECTION_STATE_NONE &&
	    con->connection_state < SCCP_CONNECTION_STATE_RELEASE_COMPLETE)
		llist_del(&con->list);

	con->connection_state = SCCP_CONNECTION_STATE_REFUSED;
	sccp_connection_free(con);
        return 0;
}

struct sccp_connection *sccp_connection_socket(void)
{
	return talloc_zero(tall_sccp_ctx, struct sccp_connection);
}

int sccp_connection_connect(struct sccp_connection *conn,
			    const struct sockaddr_sccp *local,
			    struct msgb *data)
{
	return _sccp_send_connection_request(conn, local, data);
}

int sccp_connection_set_incoming(const struct sockaddr_sccp *sock,
				 int (*accept_cb)(struct sccp_connection *, void *), void *context)
{
	struct sccp_data_callback *cb;

	if (!sock)
		return -2;

	cb = _find_ssn(sock->sccp_ssn);
	if (!cb)
		return -1;

	cb->accept_cb = accept_cb;
	cb->accept_context = context;
	return 0;
}

int sccp_write(struct msgb *data, const struct sockaddr_sccp *in,
	       const struct sockaddr_sccp *out, int class, void *ctx)
{
	return _sccp_send_data(class, in, out, data, ctx);
}

int sccp_set_read(const struct sockaddr_sccp *sock,
		  int (*read_cb)(struct msgb *, unsigned int, void *), void *context)
{
	struct sccp_data_callback *cb;

	if (!sock)
		return -2;

	cb  = _find_ssn(sock->sccp_ssn);
	if (!cb)
		return -1;

	cb->read_cb = read_cb;
	cb->read_context = context;
	return 0;
}

osmo_static_assert(sizeof(struct sccp_source_reference) <= sizeof(uint32_t), enough_space);

uint32_t sccp_src_ref_to_int(struct sccp_source_reference *ref)
{
	uint32_t src_ref = 0;
#if OSMO_IS_LITTLE_ENDIAN
	memcpy(&src_ref, ref, sizeof(*ref));
#elif OSMO_IS_BIG_ENDIAN
	*(((uint8_t*)(&src_ref))+3) = ref->octet1;
	*(((uint8_t*)(&src_ref))+2) = ref->octet2;
	*(((uint8_t*)(&src_ref))+1) = ref->octet3;
#endif
	return src_ref;
}

struct sccp_source_reference sccp_src_ref_from_int(uint32_t int_ref)
{
	struct sccp_source_reference ref;
#if OSMO_IS_LITTLE_ENDIAN
	memcpy(&ref, &int_ref, sizeof(ref));
#elif OSMO_IS_BIG_ENDIAN
	ref.octet1 = *(((uint8_t*)(&int_ref))+3);
	ref.octet2 = *(((uint8_t*)(&int_ref))+2);
	ref.octet3 = *(((uint8_t*)(&int_ref))+1);
#endif
	return ref;
}

int sccp_determine_msg_type(struct msgb *msg)
{
	if (msgb_l2len(msg) < 1)
		return -1;

	return msg->l2h[0];
}

int sccp_parse_header(struct msgb *msg, struct sccp_parse_result *result)
{
	int type;

	if (msgb_l2len(msg) < 1)
		return -1;

	type = msg->l2h[0];
	switch(type) {
	case SCCP_MSG_TYPE_CR:
		return _sccp_parse_connection_request(msg, result);
		break;
	case SCCP_MSG_TYPE_RLSD:
		return _sccp_parse_connection_released(msg, result);
		break;
	case SCCP_MSG_TYPE_CREF:
		return _sccp_parse_connection_refused(msg, result);
		break;
	case SCCP_MSG_TYPE_CC:
		return _sccp_parse_connection_confirm(msg, result);
		break;
	case SCCP_MSG_TYPE_RLC:
		return _sccp_parse_connection_release_complete(msg, result);
		break;
	case SCCP_MSG_TYPE_DT1:
		return _sccp_parse_connection_dt1(msg, result);
		break;
	case SCCP_MSG_TYPE_UDT:
		return _sccp_parse_udt(msg, result);
		break;
	case SCCP_MSG_TYPE_IT:
		return _sccp_parse_it(msg, result);
		break;
	case SCCP_MSG_TYPE_ERR:
		return _sccp_parse_err(msg, result);
		break;
	};

	LOGP(DSCCP, LOGL_ERROR, "Unimplemented MSG Type: 0x%x\n", type);
	return -1;
}

static __attribute__((constructor)) void on_dso_load(void)
{
	tall_sccp_ctx = talloc_named_const(NULL, 1, "sccp");
}

static __attribute__((destructor)) void on_dso_unload(void)
{
	talloc_report_full(tall_sccp_ctx, stderr);
}

void sccp_set_log_area(int log_area)
{
	DSCCP = log_area;
}
