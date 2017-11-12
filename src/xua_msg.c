/* Routines for generating and parsing messages */
/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2016-2017 by Harald Welte <laforge@gnumonks.org>
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/sigtran/xua_msg.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>

#include <arpa/inet.h>

#include <string.h>
#include <errno.h>

static void *tall_xua;

struct xua_msg *xua_msg_alloc(void)
{
	struct xua_msg *msg;

	msg = talloc_zero(tall_xua, struct xua_msg);
	if (!msg)
		return NULL;

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

struct xua_msg_part *xua_msg_find_tag(const struct xua_msg *xua, uint16_t tag)
{
	struct xua_msg_part *part;

	llist_for_each_entry(part, &xua->headers, entry)
		if (part->tag == tag)
			return part;

	return NULL;
}

int xua_msg_free_tag(struct xua_msg *xua, uint16_t tag)
{
	struct xua_msg_part *part;

	llist_for_each_entry(part, &xua->headers, entry) {
		if (part->tag == tag) {
			llist_del(&part->entry);
			talloc_free(part);
			return 1;
		}
	}
	return 0;
}

int xua_msg_copy_part(struct xua_msg *xua_out, uint16_t tag_out,
		      const struct xua_msg *xua_in, uint16_t tag_in)
{
	const struct xua_msg_part *part;

	part = xua_msg_find_tag(xua_in, tag_in);
	if (!part)
		return -1;

	return xua_msg_add_data(xua_out, tag_out, part->len, part->dat);
}

static int xua_from_msg_common(struct xua_msg *msg, const uint8_t *data, uint16_t pos, uint16_t len)
{
	struct xua_parameter_hdr *par;
	uint16_t par_len, padding;
	int rc;

	while (pos + sizeof(*par) < len) {
		par = (struct xua_parameter_hdr *) &data[pos];
		par_len = ntohs(par->len);

		if (pos + par_len > len || par_len < 4)
			return -1;

		rc = xua_msg_add_data(msg, ntohs(par->tag),
				       par_len - 4, par->data);
		if (rc != 0)
			return -1;

		pos += par_len;

		/* move over the padding */
		padding = (4 - (par_len % 4)) & 0x3;
		pos += padding;
	}

	return 0;
}

struct xua_msg *xua_from_msg(const int version, uint16_t len, uint8_t *data)
{
	struct xua_common_hdr *hdr;
	struct xua_msg *msg;
	uint16_t pos;
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

	rc = xua_from_msg_common(msg, data, pos, len);
	if (rc < 0)
		goto fail;

	return msg;

fail:
	xua_msg_free(msg);
	return NULL;

}

struct xua_msg *xua_from_nested(struct xua_msg_part *outer)
{
	struct xua_msg *msg = xua_msg_alloc();
	int rc;

	if (!msg)
		return NULL;

	rc = xua_from_msg_common(msg, outer->dat, 0, outer->len);
	if (rc < 0) {
		xua_msg_free(msg);
		return NULL;
	}

	return msg;
}

struct msgb *xua_to_msg(const int version, struct xua_msg *xua)
{
	struct xua_msg_part *part;
	struct xua_common_hdr *hdr;
	struct msgb *msg;
	uint8_t rest;

	msg = msgb_alloc_headroom(2048, 512, "xua msg");
	if (!msg)
		return NULL;

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

uint32_t xua_msg_part_get_u32(struct xua_msg_part *part)
{
	OSMO_ASSERT(part->len >= 4);
	return ntohl(*(uint32_t *)part->dat);
}

uint32_t xua_msg_get_u32(struct xua_msg *xua, uint16_t iei)
{
	struct xua_msg_part *part = xua_msg_find_tag(xua, iei);
	if (!part)
		return 0;
	return xua_msg_part_get_u32(part);
}

void xua_part_add_gt(struct msgb *msg, const struct osmo_sccp_gt *gt)
{
	uint16_t *len_ptr;
	unsigned int num_digits = strlen(gt->digits);
	unsigned int num_digit_bytes;
	unsigned int i, j;

	/* Tag + Length */
	msgb_put_u16(msg, SUA_IEI_GT);
	len_ptr = (uint16_t *) msgb_put(msg, sizeof(uint16_t));

	/* first dword: padding + GT */
	msgb_put_u32(msg, gt->gti);

	/* second header dword */
	msgb_put_u8(msg, strlen(gt->digits));
	msgb_put_u8(msg, gt->tt);
	msgb_put_u8(msg, gt->npi);
	msgb_put_u8(msg, gt->nai);

	/* actual digits */
	num_digit_bytes = num_digits / 2;
	if (num_digits & 1)
		num_digit_bytes++;
	for (i = 0, j = 0; i < num_digit_bytes; i++) {
		uint8_t byte;
		byte = osmo_char2bcd(gt->digits[j++]);
		if (j < num_digits) {
			byte |= osmo_char2bcd(gt->digits[j++]) << 4;
		}
		msgb_put_u8(msg, byte);
	}
	/* pad to 32bit */
	if (num_digit_bytes % 4)
		msgb_put(msg, 4 - (num_digit_bytes % 4));
	*len_ptr = htons(msg->tail - (uint8_t *)len_ptr + 2);
}

int xua_msg_add_sccp_addr(struct xua_msg *xua, uint16_t iei, const struct osmo_sccp_addr *addr)
{
	struct msgb *tmp = msgb_alloc(128, "SCCP Address");
	uint16_t addr_ind = 0;
	int rc;

	if (!tmp)
		return -ENOMEM;

	switch (addr->ri) {
	case OSMO_SCCP_RI_GT:
		msgb_put_u16(tmp, SUA_RI_GT);
		break;
	case OSMO_SCCP_RI_SSN_PC:
		msgb_put_u16(tmp, SUA_RI_SSN_PC);
		break;
	case OSMO_SCCP_RI_SSN_IP:
		msgb_put_u16(tmp, SUA_RI_SSN_IP);
		break;
	default:
		return -EINVAL;
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN)
		addr_ind |= 0x0001;
	if (addr->presence & OSMO_SCCP_ADDR_T_PC)
		addr_ind |= 0x0002;
	if (addr->presence & OSMO_SCCP_ADDR_T_GT)
		addr_ind |= 0x0004;

	msgb_put_u16(tmp, addr_ind);

	if (addr->presence & OSMO_SCCP_ADDR_T_GT) {
		xua_part_add_gt(tmp, &addr->gt);
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_PC) {
		msgb_t16l16vp_put_u32(tmp, SUA_IEI_PC, addr->pc);
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN) {
		msgb_t16l16vp_put_u32(tmp, SUA_IEI_SSN, addr->ssn);
	}
	if (addr->presence & OSMO_SCCP_ADDR_T_IPv4) {
		msgb_t16l16vp_put_u32(tmp, SUA_IEI_IPv4, ntohl(addr->ip.v4.s_addr));
	} else if (addr->presence & OSMO_SCCP_ADDR_T_IPv6) {
		/* FIXME: IPv6 address */
	}
	rc = xua_msg_add_data(xua, iei, msgb_length(tmp), tmp->data);
	msgb_free(tmp);

	return rc;
}

/*! \brief Map from a xua_msg (class+type) to an event
 *  \param[in] xua xUA message which is to be mapped
 *  \param[in] maps Table containing msg type+class -> event maps
 *  \[aram[in] num_maps number of entries in \ref maps
 *  \returns event >= 0; negative on error (no map found) */
int xua_msg_event_map(const struct xua_msg *xua,
		      const struct xua_msg_event_map *maps,
		      unsigned int num_maps)
{
	int i;

	for (i= 0; i < num_maps; i++) {
		const struct xua_msg_event_map *map = &maps[i];
		if (xua->hdr.msg_class == map->msg_class &&
		    xua->hdr.msg_type == map->msg_type) {
			return map->event;
		}
	}
	return -1;
}

const char *xua_class_msg_name(const struct xua_msg_class *xmc, uint16_t msg_type)
{
	static char class_buf[64];

	if (xmc && xmc->msgt_names)
		return get_value_string(xmc->msgt_names, msg_type);
	else {
		snprintf(class_buf, sizeof(class_buf), "Unknown 0x%04x", msg_type);
		return class_buf;
	}
}

const char *xua_class_iei_name(const struct xua_msg_class *xmc, uint16_t iei)
{
	static char iei_buf[64];

	if (xmc && xmc->iei_names)
		return get_value_string(xmc->iei_names, iei);
	else {
		snprintf(iei_buf, sizeof(iei_buf), "Unknown 0x%04x", iei);
		return iei_buf;
	}
}

char *xua_hdr_dump(struct xua_msg *xua, const struct xua_dialect *dialect)
{
	const struct xua_msg_class *xmc = NULL;
	static char buf[128];

	if (dialect)
		xmc = dialect->class[xua->hdr.msg_class];
	if (!xmc)
		snprintf(buf, sizeof(buf), "%u:%u", xua->hdr.msg_class, xua->hdr.msg_type);
	else
		snprintf(buf, sizeof(buf), "%s:%s", xmc->name,
			xua_class_msg_name(xmc, xua->hdr.msg_type));
	return buf;
}

int xua_dialect_check_all_mand_ies(const struct xua_dialect *dialect, struct xua_msg *xua)
{
	uint8_t msg_class = xua->hdr.msg_class;
	uint8_t msg_type = xua->hdr.msg_type;
	const struct xua_msg_class *xmc = dialect->class[msg_class];
	const uint16_t *ies;
	uint16_t ie;

	/* unknown class? */
	if (!xmc)
		return 1;

	ies = xmc->mand_ies[msg_type];
	/* no mandatory IEs? */
	if (!ies)
		return 1;

	for (ie = *ies; ie; ie = *ies++) {
		if (!xua_msg_find_tag(xua, ie)) {
			LOGP(dialect->log_subsys, LOGL_ERROR,
				"%s Message %s:%s should "
				"contain IE %s, but doesn't\n",
				dialect->name, xmc->name,
				xua_class_msg_name(xmc, msg_type),
				xua_class_iei_name(xmc, ie));
			return 0;
		}
	}

	return 1;
}

static void append_to_buf(char *buf, bool *comma, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!comma || *comma == true) {
		strcat(buf, ",");
	} else if (comma)
		*comma = true;
	vsprintf(buf+strlen(buf), fmt, ap);
	va_end(ap);
}

char *xua_msg_dump(struct xua_msg *xua, const struct xua_dialect *dialect)
{
	static char buf[1024];
	struct xua_msg_part *part;
	const struct xua_msg_class *xmc = NULL;

	if (dialect)
		xmc = dialect->class[xua->hdr.msg_class];

	buf[0] = '\0';

	append_to_buf(buf, NULL, "HDR=(%s,V=%u,LEN=%u)",
			xua_hdr_dump(xua, dialect),
			xua->hdr.version, xua->hdr.msg_length);
	buf[0] = ' ';
	llist_for_each_entry(part, &xua->headers, entry)
		append_to_buf(buf, NULL, "\n\tPART(T=%s,L=%u,D=%s)",
				xua_class_iei_name(xmc, part->tag), part->len,
				osmo_hexdump_nospc(part->dat, part->len));
	return buf;
}
