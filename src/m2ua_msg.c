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

#include <m2ua/m2ua_msg.h>

#include <osmocore/msgb.h>
#include <osmocore/logging.h>
#include <osmocore/talloc.h>

#include <arpa/inet.h>

#include <string.h>

static void *tall_m2ua;
static int DM2UA = -1;

struct m2ua_msg *m2ua_msg_alloc(void)
{
	struct m2ua_msg *msg;

	msg = talloc_zero(tall_m2ua, struct m2ua_msg);
	if (!msg) {
		LOGP(DM2UA, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	INIT_LLIST_HEAD(&msg->headers);
	return msg;
}

void m2ua_msg_free(struct m2ua_msg *msg)
{
	talloc_free(msg);
}

int m2ua_msg_add_data(struct m2ua_msg *msg, uint16_t tag,
		      uint16_t len, uint8_t *dat)
{
	struct m2ua_msg_part *part;

	part = talloc_zero(msg, struct m2ua_msg_part);
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

struct m2ua_msg_part *m2ua_msg_find_tag(struct m2ua_msg *m2ua, uint16_t tag)
{
	struct m2ua_msg_part *part;

	llist_for_each_entry(part, &m2ua->headers, entry)
		if (part->tag == tag)
			return part;

	return NULL;
}

struct m2ua_msg *m2ua_from_msg(uint16_t len, uint8_t *data)
{
	struct m2ua_parameter_hdr *par;
	struct m2ua_common_hdr *hdr;
	struct m2ua_msg *msg;
	uint16_t pos, par_len, padding;
	int rc;

	msg = m2ua_msg_alloc();
	if (!msg)
		return NULL;

	if (len < sizeof(*hdr))
		goto fail;

	hdr = (struct m2ua_common_hdr *) data;
	if (hdr->version != M2UA_VERSION)
		goto fail;
	if (ntohl(hdr->msg_length) > len)
		goto fail;

	msg->hdr = *hdr;
	pos = sizeof(*hdr);

	while (pos + sizeof(*par) < len) {
		par = (struct m2ua_parameter_hdr *) &data[pos];
		par_len = ntohs(par->len);

		if (pos + par_len > len || par_len < 4) 
			goto fail;

		rc = m2ua_msg_add_data(msg, ntohs(par->tag),
				       par_len - 4, par->data);
		if (rc != 0)
			goto fail;

		pos += par_len;

		/* move over the padding */
		padding = par_len % 4;
		pos += padding;
	}

	/* TODO: parse */
	return msg;

fail:
	LOGP(DM2UA, LOGL_ERROR, "Failed to parse.\n");
	m2ua_msg_free(msg);
	return NULL;
}

struct msgb *m2ua_to_msg(struct m2ua_msg *m2ua)
{
	struct m2ua_msg_part *part;
	struct m2ua_common_hdr *hdr;
	struct msgb *msg;
	uint8_t rest;

	msg = msgb_alloc_headroom(2048, 512, "m2ua msg");
	if (!msg) {
		LOGP(DM2UA, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*hdr));
	hdr = (struct m2ua_common_hdr *) msg->l2h;
	memcpy(hdr, &m2ua->hdr, sizeof(*hdr));

	/* make sure that is right */
	hdr->version = M2UA_VERSION;
	hdr->spare = 0;

	llist_for_each_entry(part, &m2ua->headers, entry) {
		msgb_put_u16(msg, part->tag);
		msgb_put_u16(msg, part->len + 4);
		if (part->dat) {
			uint8_t *dat = msgb_put(msg, part->len);
			memcpy(dat, part->dat, part->len);

			/* padding */
			rest = part->len % 4;
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
