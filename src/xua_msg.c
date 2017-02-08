/* Routines for generating and parsing messages */
/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>

#include <arpa/inet.h>

#include <string.h>
#include <errno.h>

static void *tall_xua;
static int DXUA = -1;

struct xua_msg *xua_msg_alloc(void)
{
	struct xua_msg *msg;

	msg = talloc_zero(tall_xua, struct xua_msg);
	if (!msg) {
		LOGP(DXUA, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	INIT_LLIST_HEAD(&msg->headers);
	return msg;
}

void xua_msg_free(struct xua_msg *msg)
{
	talloc_free(msg);
}

int xua_msg_add_data(struct xua_msg *msg, uint16_t tag,
		      uint16_t len, uint8_t *dat)
{
	struct xua_msg_part *part;

	part = talloc_zero(msg, struct xua_msg_part);
	if (!part)
		return -1;

	part->tag = tag;
	part->len = len;

	/* do we have any data? */
	if (part->len != 0) {
		part->dat = talloc_memdup(part, dat, len);
		if (!part->dat) {
			talloc_free(part);
			return -1;
		}
	}

	llist_add_tail(&part->entry, &msg->headers);
	return 0;
}

struct xua_msg_part *xua_msg_find_tag(struct xua_msg *xua, uint16_t tag)
{
	struct xua_msg_part *part;

	llist_for_each_entry(part, &xua->headers, entry)
		if (part->tag == tag)
			return part;

	return NULL;
}

struct xua_msg *xua_from_msg(const int version, uint16_t len, uint8_t *data)
{
	struct xua_parameter_hdr *par;
	struct xua_common_hdr *hdr;
	struct xua_msg *msg;
	uint16_t pos, par_len, padding;
	int rc;

	msg = xua_msg_alloc();
	if (!msg)
		return NULL;

	if (len < sizeof(*hdr))
		goto fail;

	hdr = (struct xua_common_hdr *) data;
	if (hdr->version != version)
		goto fail;
	if (ntohl(hdr->msg_length) > len)
		goto fail;

	msg->hdr = *hdr;
	pos = sizeof(*hdr);

	while (pos + sizeof(*par) < len) {
		par = (struct xua_parameter_hdr *) &data[pos];
		par_len = ntohs(par->len);

		if (pos + par_len > len || par_len < 4) 
			goto fail;

		rc = xua_msg_add_data(msg, ntohs(par->tag),
				       par_len - 4, par->data);
		if (rc != 0)
			goto fail;

		pos += par_len;

		/* move over the padding */
		padding = (4 - (par_len % 4)) & 0x3;
		pos += padding;
	}

	/* TODO: parse */
	return msg;

fail:
	LOGP(DXUA, LOGL_ERROR, "Failed to parse.\n");
	xua_msg_free(msg);
	return NULL;
}

struct msgb *xua_to_msg(const int version, struct xua_msg *xua)
{
	struct xua_msg_part *part;
	struct xua_common_hdr *hdr;
	struct msgb *msg;
	uint8_t rest;

	msg = msgb_alloc_headroom(2048, 512, "xua msg");
	if (!msg) {
		LOGP(DXUA, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));
	hdr = (struct xua_common_hdr *) msg->l2h;
	memcpy(hdr, &xua->hdr, sizeof(*hdr));

	/* make sure that is right */
	hdr->version = version;
	hdr->spare = 0;

	llist_for_each_entry(part, &xua->headers, entry) {
		msgb_put_u16(msg, part->tag);
		msgb_put_u16(msg, part->len + 4);
		if (part->dat) {
			uint8_t *dat = msgb_put(msg, part->len);
			memcpy(dat, part->dat, part->len);

			/* padding */
			rest = (4 - (part->len % 4)) & 0x3;
			if (rest > 0) {
				dat = msgb_put(msg, rest);
				memset(dat, 0, rest);
			}
		}
	}

	/* update the size of the data */
	hdr->msg_length = htonl(msgb_l2len(msg));
	return msg;
}

void xua_set_log_area(int log_area)
{
	DXUA = log_area;
}


/***********************************************************************
 * Message encoding helper functions
 ***********************************************************************/

int msgb_t16l16vp_put(struct msgb *msg, uint16_t tag, uint16_t len, const uint8_t *data)
{
	uint8_t *cur;
	unsigned int rest;
	unsigned int tlv_len = 4 + len + (4 - (len % 4));

	if (msgb_tailroom(msg) < tlv_len)
		return -ENOMEM;

	/* tag */
	msgb_put_u16(msg, tag);
	/* length */
	msgb_put_u16(msg, len + 4);
	/* value */
	cur = msgb_put(msg, len);
	memcpy(cur, data, len);
	/* padding */
	rest = (4 - (len % 4)) & 0x3;
	if (rest > 0) {
		cur = msgb_put(msg, rest);
		memset(cur, 0, rest);
	}

	return 0;
}

int msgb_t16l16vp_put_u32(struct msgb *msg, uint16_t tag, uint32_t val)
{
	uint32_t val_n = htonl(val);

	return msgb_t16l16vp_put(msg, tag, sizeof(val_n), (uint8_t *)&val_n);
}

int xua_msg_add_u32(struct xua_msg *xua, uint16_t iei, uint32_t val)
{
	uint32_t val_n = htonl(val);
	return xua_msg_add_data(xua, iei, sizeof(val_n), (uint8_t *) &val_n);
}

uint32_t xua_msg_get_u32(struct xua_msg *xua, uint16_t iei)
{
	struct xua_msg_part *part = xua_msg_find_tag(xua, iei);
	uint32_t rc = 0;
	if (part)
		rc = ntohl(*(uint32_t *)part->dat);
	return rc;
}
