/* SCCP <-> SUA transcoding routines */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * based on my 2011 Erlang implementation osmo_ss7/src/sua_sccp_conv.erl
 *
 * References: ITU-T Q.713 and IETF RFC 3868
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
 */

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <osmocom/sccp/sccp.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/xua_msg.h>

#include "xua_internal.h"
#include "sccp_internal.h"

/* libosmocore candidates */

static void msgb_put_u24be(struct msgb *msg, uint32_t val)
{
	msgb_put_u8(msg, (val >> 16) & 0xff);
	msgb_put_u8(msg, (val >> 8) & 0xff);
	msgb_put_u8(msg, val & 0xff);
}

static void msgb_put_u16le(struct msgb *msg, uint16_t val)
{
	msgb_put_u8(msg, val & 0xff);
	msgb_put_u8(msg, (val >> 8) & 0xff);
}

/*! \brief load a 24bit value as big-endian */
static uint32_t load_24be(const void *ptr)
{
	const uint8_t *data = ptr;
	return (data[0] << 16) | (data[1] << 8) | data[2];
}



/*! \brief Parse ISUP style address of BCD digets
 *  \param[out] out_digits user-allocated buffer for ASCII digits
 *  \param[in] in BCD-encoded digits
 *  \param[in] in_num_bytes Size of \ref in in bytes
 *  \param[in] odd Odd (true) or even (false) number of digits
 *  \returns number of digits generated
 * */
int osmo_isup_party_parse(char *out_digits, const uint8_t *in,
			    unsigned int in_num_bytes, bool odd)
{
	char *out = out_digits;
	unsigned int i;

	for (i = 0; i < in_num_bytes; i++) {
		*out_digits++ = osmo_bcd2char(in[i] & 0x0F);
		if (i+1 == in_num_bytes && odd)
			break;
		*out_digits++ = osmo_bcd2char(in[i] >> 4);
	}
	*out_digits = '\0';
	return (out_digits - out);
}

/*! \brief Encode an ISUP style address of BCD digits
 *  \param[out] msg Message to which the encoded address is appended
 *  \param[in] in_digits NUL-terminated ASCII string of digits
 *  \returns number of octets used for encoding \ref in_digits */
int osmo_isup_party_encode(struct msgb *msg, const char *in_digits)
{
	unsigned int num_digits = strlen(in_digits);
	unsigned int i, num_octets = num_digits/2;
	const char *cur_digit = in_digits;
	uint8_t *cur;

	if (num_digits & 1)
		num_octets++;

	cur = msgb_put(msg, num_octets);

	for (i = 0; i < num_octets;  i++) {
		cur[i] = osmo_char2bcd(*cur_digit++);
		if (cur_digit - in_digits < num_digits)
			cur[i] |= osmo_char2bcd(*cur_digit++) << 4;
	}
	return num_octets;
}

/*! \brief Parse wire-encoded SCCP address into osmo_sccp_addr
 *  \param[out] out user-allocated output data structure
 *  \param[in] addr wire-encoded SCCP address
 *  \param[in] addrlen Size of \ref addr in bytes
 *  \returns 0 in case of success, negative on error
 * According to Q.713/3.4 and RFC3868/3.10.2 */
int osmo_sccp_addr_parse(struct osmo_sccp_addr *out,
				const uint8_t *addr, unsigned int addrlen)
{
	struct sccp_called_party_address *sca;
	uint8_t *cur;
	uint8_t encoding;
	bool odd;
	int rc;

	memset(out, 0, sizeof(*out));

	sca = (struct sccp_called_party_address *) addr;
	cur = sca->data;

	if (sca->routing_indicator)
		out->ri = OSMO_SCCP_RI_SSN_PC;
	else
		out->ri = OSMO_SCCP_RI_GT;

	if (sca->point_code_indicator) {
		out->presence |= OSMO_SCCP_ADDR_T_PC;
		out->pc = (uint16_t) (cur[1] & 0x3f) << 8;
		out->pc |= cur[0];
		cur += 2;
	}

	if (sca->ssn_indicator) {
		out->presence |= OSMO_SCCP_ADDR_T_SSN;
		out->ssn = *cur;
		cur += 1;
	}

	switch (sca->global_title_indicator) {
	case SCCP_TITLE_IND_NONE:
		out->gt.gti = OSMO_SCCP_GTI_NO_GT;
		return 0;
	case SCCP_TITLE_IND_NATURE_ONLY:
		out->presence |= OSMO_SCCP_ADDR_T_GT;
		out->gt.gti = OSMO_SCCP_GTI_NAI_ONLY;
		out->gt.nai = *cur & 0x7f;
		if (*cur++ & 0x80)
			odd = true;
		else
			odd = false;
		break;
	case SCCP_TITLE_IND_TRANSLATION_ONLY:
		out->presence |= OSMO_SCCP_ADDR_T_GT;
		out->gt.gti = OSMO_SCCP_GTI_TT_ONLY;
		out->gt.tt = *cur++;
		/* abort, for national use only */
		LOGP(DLSUA, LOGL_ERROR, "Unsupported national GTI %u\n", sca->global_title_indicator);
		return -EINVAL;
	case SCCP_TITLE_IND_TRANS_NUM_ENC:
		out->presence |= OSMO_SCCP_ADDR_T_GT;
		out->gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC;
		out->gt.tt = *cur++;
		out->gt.npi = *cur >> 4;
		encoding = *cur++ & 0xF;
		switch (encoding) {
		case 1:
			odd = true;
			break;
		case 2:
			odd = false;
			break;
		default:
			LOGP(DLSUA, LOGL_ERROR, "Unknown GT encoding 0x%x\n", encoding);
			return -1;
		}
		break;
	case SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE:
		out->presence |= OSMO_SCCP_ADDR_T_GT;
		out->gt.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI;
		out->gt.tt = *cur++;
		out->gt.npi = *cur >> 4;
		encoding = *cur++ & 0xF;
		switch (encoding) {
		case 1:
			odd = true;
			break;
		case 2:
			odd = false;
			break;
		default:
			LOGP(DLSUA, LOGL_ERROR, "Unknown GT encoding 0x%x\n",
				encoding);
			return -EINVAL;
		}
		out->gt.nai = *cur++ & 0x7f;
		break;
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unknown GTI %u in SCCP message\n",
			sca->global_title_indicator);
		return -EINVAL;
	}
	rc = osmo_isup_party_parse(out->gt.digits, cur, (addr+addrlen-cur), odd);
	if (rc < 0)
		return rc;

	return 0;
}

/*! \brief encode a SCCP address from parsed format to wire format
 *  \param[out] msg message buffer to which address is to be appended
 *  \param[in] in data structure describing SCCP address
 *  \returns number of bytes written to \ref msg */
int osmo_sccp_addr_encode(struct msgb *msg, const struct osmo_sccp_addr *in)
{
	struct sccp_called_party_address *sca;
	bool odd;

	sca = (struct sccp_called_party_address *) msgb_put(msg, sizeof(*sca));
	switch (in->ri) {
	case OSMO_SCCP_RI_SSN_PC:
		sca->routing_indicator = 1;
		break;
	case OSMO_SCCP_RI_GT:
		sca->routing_indicator = 0;
		break;
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unknown CCP Routing Indicator %u"
			" requested\n", in->ri);
		return -EINVAL;
	}

	if (in->presence & OSMO_SCCP_ADDR_T_PC) {
		sca->point_code_indicator = 1;
		/* ITU-T Q.713 states that signalling point codes are 14bit */
		if (in->pc > 0x3fff) {
			LOGP(DLSUA, LOGL_ERROR, "Invalid Point Code %u requested\n", in->pc);
			return -EINVAL;
		}
		msgb_put_u16le(msg, in->pc & 0x3fff);
	}

	if (in->presence & OSMO_SCCP_ADDR_T_SSN) {
		sca->ssn_indicator = 1;
		if (in->ssn > 0xff) {
			LOGP(DLSUA, LOGL_ERROR, "Invalid SSN %u requested\n", in->ssn);
			return -EINVAL;
		}
		msgb_put_u8(msg, in->ssn);
	}

	if (!(in->presence & OSMO_SCCP_ADDR_T_GT)) {
		sca->global_title_indicator = SCCP_TITLE_IND_NONE;
		goto out;
	}

	if (in->gt.npi && (in->gt.npi > 0xF)) {
		LOGP(DLSUA, LOGL_ERROR, "Unsupported Numbering Plan %u", in->gt.npi);
		return -EINVAL;
	}

	if (in->gt.nai && (in->gt.nai > 0x7F)) {
		LOGP(DLSUA, LOGL_ERROR, "Unsupported Nature of Address %u", in->gt.nai);
		return -EINVAL;
	}

	odd = strlen(in->gt.digits) & 1;
	switch (in->gt.gti) {
	case OSMO_SCCP_GTI_NO_GT:
		sca->global_title_indicator = SCCP_TITLE_IND_NONE;
		goto out;
	case OSMO_SCCP_GTI_NAI_ONLY:
		sca->global_title_indicator = SCCP_TITLE_IND_NATURE_ONLY;
		msgb_put_u8(msg, (odd << 7) | (in->gt.nai & 0x7f));
		break;
	case OSMO_SCCP_GTI_TT_ONLY:
		sca->global_title_indicator = SCCP_TITLE_IND_TRANSLATION_ONLY;
		msgb_put_u8(msg, in->gt.tt);
		/* abort, for national use only */
		LOGP(DLSUA, LOGL_ERROR, "Unsupported Translation Type %u"
			"requested\n", in->gt.gti);
		return -EINVAL;
	case OSMO_SCCP_GTI_TT_NPL_ENC:
		sca->global_title_indicator = SCCP_TITLE_IND_TRANS_NUM_ENC;
		msgb_put_u8(msg, in->gt.tt);
		msgb_put_u8(msg, (in->gt.npi << 4) | (odd ? 1 : 2));
		break;
	case OSMO_SCCP_GTI_TT_NPL_ENC_NAI:
		sca->global_title_indicator = SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE;
		msgb_put_u8(msg, in->gt.tt);
		msgb_put_u8(msg, (in->gt.npi << 4) | (odd ? 1 : 2));
		msgb_put_u8(msg, in->gt.nai & 0x7f);
		break;
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unsupported GTI %u requested\n", in->gt.gti);
		return -EINVAL;
	}
	osmo_isup_party_encode(msg, in->gt.digits);

out:
	/* return number of bytes written */
	return msg->tail - (uint8_t *)sca;
}

/*! \brief convert SCCP address to SUA address
 *  \param xua user-provided xUA message to which address shall be added
 *  \param[in] iei SUA Information Element Identifier for address
 *  \param[in] addr SCCP wire format binary address
 *  \param[in] addrlen Size of \ref addr in bytes
 *  \returns 0 in case of success; negative on error */
static int sccp_addr_to_sua(struct xua_msg *xua, uint16_t iei, const uint8_t *addr,
			    unsigned int addrlen)
{
	struct osmo_sccp_addr osa;
	int rc;

	/* First decode the address from SCCP wire format to
	 * osmo_sccp_addr */
	rc = osmo_sccp_addr_parse(&osa, addr, addrlen);
	if (rc < 0)
		return rc;

	LOGP(DLSUA, LOGL_DEBUG, "IEI %u: Parsed Addr: %s\n", iei, osmo_sccp_addr_dump(&osa));

	/* Then re-encode it as SUA address */
	return xua_msg_add_sccp_addr(xua, iei, &osa);
}

/*! \brief convenience wrapper around sccp_addr_to_sua() for variable mandatory addresses */
static int sccp_addr_to_sua_ptr(struct xua_msg *xua, uint16_t iei, struct msgb *msg, uint8_t *ptr_addr)
{
	uint8_t *addr = ptr_addr + *ptr_addr + 1;
	unsigned int addrlen = *(ptr_addr + *ptr_addr);

	return sccp_addr_to_sua(xua, iei, addr, addrlen);
}

/*! \brief convert SUA address to SCCP address
 *  \param msg user-provided message buffer to which address shall be *  appended
 *  \param[in] part SUA wire format binary address
 *  \returns 0 in case of success; negative on error */
static int sua_addr_to_sccp(struct msgb *msg, struct xua_msg_part *part)
{
	struct osmo_sccp_addr osa;
	int rc;

	/* First decode the address from SUA wire format to
	 * osmo_sccp_addr */
	rc = sua_addr_parse_part(&osa, part);
	if (rc < 0)
		return rc;

	/* Then re-encode it as SCCP address */
	return osmo_sccp_addr_encode(msg, &osa);
}

/*! \brief Add a "SCCP Variable Mandatory Part" (Address format) to the given msgb
 *  \param msg Message buffer to which part shall be added
 *  \param[out] var_ptr pointer to relative pointer in SCCP header
 *  \param[in] xua xUA message from which to use address
 *  \param[in] iei xUA information element identifier of address */
static int sccp_add_var_addr(struct msgb *msg, uint8_t *var_ptr, struct xua_msg *xua, uint16_t iei)
{
	struct xua_msg_part *part = xua_msg_find_tag(xua, iei);
	uint8_t *lenbyte;
	int rc;
	if (!part) {
		LOGP(DLSUA, LOGL_ERROR, "Cannot find IEI %u in SUA message\n", iei);
		return -ENODEV;
	}

	/* first allocate one byte for the length */
	lenbyte = msgb_put(msg, 1);
	/* update the relative pointer to the length byte */
	*var_ptr = lenbyte - var_ptr;

	/* then append the encoded SCCP address */
	rc = sua_addr_to_sccp(msg, part);
	if (rc < 0)
		return rc;

	/* store the encoded length of the address */
	*lenbyte = rc;

	return rc;
}

/*! \brief Add a "SCCP Variable Mandatory Part" to the given msgb
 *  \param msg Message buffer to which part shall be added
 *  \param[out] var_ptr pointer to relative pointer in SCCP header
 *  \param[in] xua xUA message from which to use source data
 *  \param[in] iei xUA information element identifier of source data */
static int sccp_add_variable_part(struct msgb *msg, uint8_t *var_ptr, struct xua_msg *xua, uint16_t iei)
{
	struct xua_msg_part *part = xua_msg_find_tag(xua, iei);
	uint8_t *lenbyte;
	uint8_t *cur;
	if (!part) {
		LOGP(DLSUA, LOGL_ERROR, "Cannot find IEI %u in SUA message\n", iei);
		return -ENODEV;
	}

	/* first allocate one byte for the length */
	lenbyte = msgb_put(msg, 1);
	/* update the relative pointer to the length byte */
	*var_ptr = lenbyte - var_ptr;

	/* then append the encoded SCCP address */
	cur = msgb_put(msg, part->len);
	memcpy(cur, part->dat, part->len);

	/* store the encoded length of the address */
	*lenbyte = part->len;

	return part->len;
}


/*! \brief validate that SCCP part with pointer + length doesn't exceed msg tail
 *  \param[in] msg Message containing SCCP address
 *  \param[in] ptr_addr pointer to byte with relative SCCP pointer
 *  \returns true if OK; false if message inconsistent */
static bool sccp_ptr_part_consistent(struct msgb *msg, uint8_t *ptr_addr)
{
	uint8_t *ptr;

	/* check the address of the relative pointer is within msg */
	if (ptr_addr < msg->data || ptr_addr > msg->tail) {
		LOGP(DLSUA, LOGL_ERROR, "ptr_addr outside msg boundary\n");
		return false;
	}

	ptr = ptr_addr + *ptr_addr;
	if (ptr > msg->tail) {
		LOGP(DLSUA, LOGL_ERROR, "ptr points outside msg boundary\n");
		return false;
	}

	/* at destination of relative pointer is the length */
	if (ptr + 1 + *ptr > msg->tail) {
		LOGP(DLSUA, LOGL_ERROR, "ptr + len points outside msg boundary\n");
		return false;
	}
	return true;
}

/*! \brief convenience wrapper around xua_msg_add_data() for variable mandatory data */
static int sccp_data_to_sua_ptr(struct xua_msg *xua, uint16_t iei, struct msgb *msg, uint8_t *ptr_addr)
{
	uint8_t *addr = ptr_addr + *ptr_addr + 1;
	unsigned int addrlen = *(ptr_addr + *ptr_addr);

	return xua_msg_add_data(xua, iei, addrlen, addr);
}

/*! \brief Convert a given SCCP option to SUA and add it to given xua_msg
 *  \param xua caller-provided xUA message to which option is to be  added
 *  \param[in] sccp_opt_type SCCP option type (PNC)
 *  \param[in] opt_len size of \ref opt in bytes
 *  \param[in] opt pointer to wire-format encoded SCCP option data
 *  \returns 0 in case of success; negative on error */
static int xua_msg_add_sccp_opt(struct xua_msg *xua, uint8_t sccp_opt_type,
				uint16_t opt_len, uint8_t *opt)
{
	switch (sccp_opt_type) {
	case SCCP_PNC_DESTINATION_LOCAL_REFERENCE:
		if (opt_len != 3)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(opt));
		break;
	case SCCP_PNC_SOURCE_LOCAL_REFERENCE:
		if (opt_len != 3)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, load_24be(opt));
		break;
	case SCCP_PNC_CALLED_PARTY_ADDRESS:
		if (opt_len < 3)
			return -EINVAL;
		sccp_addr_to_sua(xua, SUA_IEI_DEST_ADDR, opt, opt_len);
		break;
	case SCCP_PNC_CALLING_PARTY_ADDRESS:
		if (opt_len < 3)
			return -EINVAL;
		sccp_addr_to_sua(xua, SUA_IEI_SRC_ADDR, opt, opt_len);
		break;
	case SCCP_PNC_PROTOCOL_CLASS:
		if (opt_len < 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, *opt);
		break;
	case SCCP_PNC_CREDIT:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_IMPORTANCE, *opt & 0x7);
		break;
	case SCCP_PNC_RELEASE_CAUSE:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RELEASE | *opt);
		break;
	case SCCP_PNC_RETURN_CAUSE:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RETURN | *opt);
		break;
	case SCCP_PNC_RESET_CAUSE:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RESET | *opt);
		break;
	case SCCP_PNC_ERROR_CAUSE:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_ERROR | *opt);
		break;
	case SCCP_PNC_REFUSAL_CAUSE:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | *opt);
		break;
	case SCCP_PNC_DATA:
		xua_msg_add_data(xua, SUA_IEI_DATA, opt_len, opt);
		break;
	case SCCP_PNC_HOP_COUNTER:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_S7_HOP_CTR, *opt);
		break;
	case SCCP_PNC_IMPORTANCE:
		if (opt_len != 1)
			return -EINVAL;
		xua_msg_add_u32(xua, SUA_IEI_IMPORTANCE, *opt & 0x7);
		break;
	case SCCP_PNC_LONG_DATA:
		xua_msg_add_data(xua, SUA_IEI_DATA, opt_len, opt);
		break;
	case SCCP_PNC_SEGMENTATION:
	case SCCP_PNC_SEGMENTING:
	case SCCP_PNC_RECEIVE_SEQ_NUMBER:
		/* only in class 3 */
	case SCCP_PNC_SEQUENCING:
		/* only in class 3 */
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unsupported SCCP option type %u\n",
			sccp_opt_type);
		return -1;
	}
	return 0;
}

/*! \brief append a SCCP option header to the given message
 *  \param msg Message to which header is to be appended
 *  \param[in] pnc PNC of the option header
 *  \param[in] len length of the option, excluding the header */
static void msgb_put_sccp_opt_hdr(struct msgb *msg, uint8_t pnc, uint8_t len)
{
	msgb_put_u8(msg, pnc);
	msgb_put_u8(msg, len);
}

/*! \brief append a SCCP option to the given message
 *  \param msg Message to which option is to be appended
 *  \param[in] pnc PNC of the option header
 *  \param[in] len length of the option, excluding the header
 *  \param[in] data actual data to be appended */
static void msgb_put_sccp_opt(struct msgb *msg, uint8_t pnc, uint8_t len, const uint8_t *data)
{
	uint8_t *cur;

	msgb_put_sccp_opt_hdr(msg, pnc, len);
	cur = msgb_put(msg, len);
	memcpy(cur, data, len);
}

/*! \brief Convert a given SUA option/IE to SCCP and add it to given * msgb
 *  \param msg caller-provided message buffer to which option is to be appended
 *  \param[in] opt xUA option/IE (messge part) to be converted+added
 *  \returns 0 in case of success; negative on error */
static int sccp_msg_add_sua_opt(enum sccp_message_types type, struct msgb *msg, struct xua_msg_part *opt)
{
	uint32_t tmp32;
	uint8_t pnc, *lenptr;
	int rc;

	switch (opt->tag) {
	case SUA_IEI_DEST_REF:
		msgb_put_sccp_opt_hdr(msg, SCCP_PNC_DESTINATION_LOCAL_REFERENCE, 3);
		msgb_put_u24be(msg, xua_msg_part_get_u32(opt));
		break;
	case SUA_IEI_SRC_REF:
		msgb_put_sccp_opt_hdr(msg, SCCP_PNC_SOURCE_LOCAL_REFERENCE, 3);
		msgb_put_u24be(msg, xua_msg_part_get_u32(opt));
		break;
	case SUA_IEI_DEST_ADDR:
		switch (type) {
		case SCCP_MSG_TYPE_CC:
		case SCCP_MSG_TYPE_CREF:
			/* The Destination of a CC message is the
			 * originator of the connection: Calling Party */
			msgb_put_u8(msg, SCCP_PNC_CALLING_PARTY_ADDRESS);
			break;
		default:
			msgb_put_u8(msg, SCCP_PNC_CALLED_PARTY_ADDRESS);
			break;
		}
		lenptr = msgb_put(msg, 1);
		rc = sua_addr_to_sccp(msg, opt);
		if (rc < 0)
			return rc;
		*lenptr = rc;
		break;
	case SUA_IEI_SRC_ADDR:
		switch (type) {
		case SCCP_MSG_TYPE_CC:
		case SCCP_MSG_TYPE_CREF:
			/* The Source of a CC message is the
			 * responder of the connection: Called Party */
			msgb_put_u8(msg, SCCP_PNC_CALLED_PARTY_ADDRESS);
			break;
		default:
			msgb_put_u8(msg, SCCP_PNC_CALLING_PARTY_ADDRESS);
			break;
		}
		lenptr = msgb_put(msg, 1);
		rc = sua_addr_to_sccp(msg, opt);
		if (rc < 0)
			return rc;
		*lenptr = rc;
		break;
	case SUA_IEI_PROTO_CLASS:
		msgb_put_sccp_opt_hdr(msg, SCCP_PNC_PROTOCOL_CLASS, 1);
		msgb_put_u8(msg, xua_msg_part_get_u32(opt));
		break;
	case SUA_IEI_CREDIT:
		msgb_put_sccp_opt_hdr(msg, SCCP_PNC_CREDIT, 1);
		msgb_put_u8(msg, xua_msg_part_get_u32(opt) & 0x7);
		break;
	case SUA_IEI_CAUSE:
		tmp32 = xua_msg_part_get_u32(opt);
		switch (tmp32 & SUA_CAUSE_T_MASK) {
		case SUA_CAUSE_T_RETURN:
			pnc = SCCP_PNC_RETURN_CAUSE;
			break;
		case SUA_CAUSE_T_REFUSAL:
			pnc = SCCP_PNC_REFUSAL_CAUSE;
			break;
		case SUA_CAUSE_T_RELEASE:
			pnc = SCCP_PNC_RELEASE_CAUSE;
			break;
		case SUA_CAUSE_T_RESET:
			pnc = SCCP_PNC_RESET_CAUSE;
			break;
		case SUA_CAUSE_T_ERROR:
			pnc = SCCP_PNC_ERROR_CAUSE;
			break;
		default:
			LOGP(DLSUA, LOGL_ERROR, "Unknown SUA Cause Class 0x%04x\n", tmp32);
			return -EINVAL;
		}
		msgb_put_sccp_opt_hdr(msg, pnc, 1);
		msgb_put_u8(msg, tmp32 & 0xff);
		break;
	case SUA_IEI_DATA:
		msgb_put_sccp_opt(msg, SCCP_PNC_DATA, opt->len, opt->dat);
		break;
	case SUA_IEI_S7_HOP_CTR:
		msgb_put_sccp_opt_hdr(msg, SCCP_PNC_HOP_COUNTER, 1);
		msgb_put_u8(msg, xua_msg_part_get_u32(opt));
		break;
	case SUA_IEI_IMPORTANCE:
		msgb_put_sccp_opt_hdr(msg, SCCP_PNC_IMPORTANCE, 1);
		msgb_put_u8(msg, xua_msg_part_get_u32(opt) & 0x7);
		break;
	case SUA_IEI_ROUTE_CTX:
		break;
	case SUA_IEI_SEQ_CTRL:
		/* TODO */
		break;
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unknown SUA IEI 0x%04x\n", opt->tag);
		return -1;
	}
	return 0;
}

/*! \brief convert SCCP optional part to list of SUA options
 *  \param[in] msg Message buffer holding SCCP message
 *  \param[in] ptr_opt address of relative pointer to optional part
 *  \param xua caller-provided xUA message to which options are added
 *  \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_opt(struct msgb *msg, uint8_t *ptr_opt, struct xua_msg *xua)
{
	uint8_t *opt_start, *oneopt;

	/* some bounds checking */
	if (ptr_opt < msg->data || ptr_opt > msg->tail)
		return NULL;

	/* Q.713 section 2.3 "Coding of pointers": pointer value all zeros used
	  to indicate that no optional param is present. */
	if (*ptr_opt == 0)
		return xua;

	opt_start = ptr_opt + *ptr_opt;
	if (opt_start > msg->tail)
		return NULL;

	oneopt = opt_start;

	enum sccp_parameter_name_codes opt_type = 0; /* dummy value not used */
	while (oneopt < msg->tail) {
		uint8_t opt_len;
		uint16_t opt_len16;
		opt_type = oneopt[0];

		switch (opt_type) {
		case SCCP_PNC_END_OF_OPTIONAL:
			return xua;
		case SCCP_PNC_LONG_DATA:
			/* two byte length field */
			if (oneopt + 2 > msg->tail)
				goto malformed;
			opt_len16 = oneopt[1] << 8 | oneopt[2];
			if (oneopt + 3 + opt_len16 > msg->tail)
				goto malformed;
			xua_msg_add_sccp_opt(xua, opt_type, opt_len16, oneopt+3);
			oneopt += 3 + opt_len16;
			break;
		default:
			/* one byte length field */
			if (oneopt + 1 > msg->tail)
				goto malformed;

			opt_len = oneopt[1];
			if (oneopt + 2 + opt_len > msg->tail)
				goto malformed;
			xua_msg_add_sccp_opt(xua, opt_type, opt_len, oneopt+2);
			oneopt += 2 + opt_len;
		}
	}
	LOGP(DLSUA, LOGL_ERROR, "Parameter %s not found\n", osmo_sccp_pnc_name(SCCP_PNC_END_OF_OPTIONAL));
	return NULL;

malformed:
	LOGP(DLSUA, LOGL_ERROR, "Malformed parameter %s (%d)\n", osmo_sccp_pnc_name(opt_type), opt_type);
	return NULL;
}

#define MAX_IES		6
#define NUM_SCCP_MSGT	(SCCP_MSG_TYPE_LUDTS+1)

/* This table indicates which information elements are mandatory and not
 * optional in SCCP, per message type */
static const uint16_t sccp_mandatory[NUM_SCCP_MSGT][MAX_IES] = {
	/* Table 3/Q.713 */
	[SCCP_MSG_TYPE_CR] = {
		SUA_IEI_SRC_REF, SUA_IEI_PROTO_CLASS, SUA_IEI_DEST_ADDR , 0
	},
	/* Table 4/Q.713 */
	[SCCP_MSG_TYPE_CC] = {
		SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, SUA_IEI_PROTO_CLASS, 0
	},
	/* Table 5/Q.713 */
	[SCCP_MSG_TYPE_CREF] = {
		SUA_IEI_DEST_REF, SUA_IEI_CAUSE, 0
	},
	/* Table 6/Q.713 */
	[SCCP_MSG_TYPE_RLSD] = {
		SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, SUA_IEI_CAUSE, 0
	},
	/* Table 7/Q.713 */
	[SCCP_MSG_TYPE_RLC] = {
		SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, 0
	},
	/* Table 8/Q.713 */
	[SCCP_MSG_TYPE_DT1] = {
		SUA_IEI_DEST_REF, SUA_IEI_SEGMENTATION, 0
	},
	/* Table 9/Q.713 */
	[SCCP_MSG_TYPE_DT2] = {
		SUA_IEI_DEST_REF, SUA_IEI_SEGMENTATION, 0
	},
	/* Table 10/Q.713 */
	[SCCP_MSG_TYPE_AK] = {
		SUA_IEI_DEST_REF, SUA_IEI_RX_SEQ_NR, 0
	},
	/* Table 11/Q.713 */
	[SCCP_MSG_TYPE_UDT] = {
		SUA_IEI_PROTO_CLASS, SUA_IEI_DEST_ADDR,
		SUA_IEI_SRC_ADDR, SUA_IEI_DATA, 0
	},
	/* Table 12/Q.713 */
	[SCCP_MSG_TYPE_UDTS] = {
		SUA_IEI_CAUSE, SUA_IEI_DEST_ADDR, SUA_IEI_SRC_ADDR, SUA_IEI_DATA, 0
	},
	/* Table 13/Q.713 */
	[SCCP_MSG_TYPE_ED] = {
		SUA_IEI_DEST_REF, 0
	},
	/* Table 14/Q.713 */
	[SCCP_MSG_TYPE_EA] = {
		SUA_IEI_DEST_REF, 0
	},
	/* Table 15/Q.713 */
	[SCCP_MSG_TYPE_RSR] = {
		SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, SUA_IEI_CAUSE, 0
	},
	/* Table 16/Q.713 */
	[SCCP_MSG_TYPE_RSC] = {
		SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, 0
	},
	/* Table 17/Q.713 */
	[SCCP_MSG_TYPE_ERR] = {
		SUA_IEI_DEST_REF, SUA_IEI_CAUSE, 0
	},
	/* Table 18/Q.713 */
	[SCCP_MSG_TYPE_IT] = {
		SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, SUA_IEI_PROTO_CLASS,
		SUA_IEI_SEGMENTATION, SUA_IEI_CREDIT, 0
	},
	/* Table 19/Q.713 */
	[SCCP_MSG_TYPE_XUDT] = {
		SUA_IEI_PROTO_CLASS, SUA_IEI_S7_HOP_CTR,
		SUA_IEI_DEST_ADDR, SUA_IEI_SRC_ADDR, SUA_IEI_DATA, 0
	},
	/* Table 20/Q.713 */
	[SCCP_MSG_TYPE_XUDTS] = {
		SUA_IEI_CAUSE, SUA_IEI_S7_HOP_CTR, SUA_IEI_DEST_ADDR,
		SUA_IEI_SRC_ADDR, SUA_IEI_DATA, 0
	},
	/* Table 21/Q.713 */
	[SCCP_MSG_TYPE_LUDT] = {
		SUA_IEI_PROTO_CLASS, SUA_IEI_S7_HOP_CTR,
		SUA_IEI_DEST_ADDR, SUA_IEI_SRC_ADDR, SUA_IEI_DATA, 0
	},
	/* Table 22/Q.713 */
	[SCCP_MSG_TYPE_LUDTS] = {
		SUA_IEI_CAUSE, SUA_IEI_S7_HOP_CTR, SUA_IEI_DEST_ADDR,
		SUA_IEI_SRC_ADDR, SUA_IEI_DATA, 0
	},
};

/* This table indicates which information elements are optionally
 * permitted in the respective SCCP message type */
static const uint16_t sccp_optional[NUM_SCCP_MSGT][MAX_IES] = {
	/* Table 3/Q.713 */
	[SCCP_MSG_TYPE_CR] = {
		SUA_IEI_CREDIT, SUA_IEI_SRC_ADDR, SUA_IEI_DATA,
		SUA_IEI_S7_HOP_CTR, SUA_IEI_IMPORTANCE, 0
	},
	/* Table 4/Q.713 */
	[SCCP_MSG_TYPE_CC] = {
		SUA_IEI_CREDIT, SUA_IEI_SRC_ADDR, SUA_IEI_DATA,
		SUA_IEI_IMPORTANCE, 0
	},
	/* Table 5/Q.713 */
	[SCCP_MSG_TYPE_CREF] = {
		SUA_IEI_SRC_ADDR, SUA_IEI_DATA, SUA_IEI_IMPORTANCE, 0
	},
	/* Table 6/Q.713 */
	[SCCP_MSG_TYPE_RLSD] = {
		SUA_IEI_DATA, SUA_IEI_IMPORTANCE, 0
	},
	/* Table 7/Q.713 */
	[SCCP_MSG_TYPE_RLC] = {
		0
	},
	/* Table 8/Q.713 */
	[SCCP_MSG_TYPE_DT1] = {
		0
	},
	/* Table 9/Q.713 */
	[SCCP_MSG_TYPE_DT2] = {
		0
	},
	/* Table 10/Q.713 */
	[SCCP_MSG_TYPE_AK] = {
		0
	},
	/* Table 11/Q.713 */
	[SCCP_MSG_TYPE_UDT] = {
		0
	},
	/* Table 12/Q.713 */
	[SCCP_MSG_TYPE_UDTS] = {
		0
	},
	/* Table 13/Q.713 */
	[SCCP_MSG_TYPE_ED] = {
		0
	},
	/* Table 14/Q.713 */
	[SCCP_MSG_TYPE_EA] = {
		0
	},
	/* Table 15/Q.713 */
	[SCCP_MSG_TYPE_RSR] = {
		0
	},
	/* Table 16/Q.713 */
	[SCCP_MSG_TYPE_RSC] = {
		0
	},
	/* Table 17/Q.713 */
	[SCCP_MSG_TYPE_ERR] = {
		0
	},
	/* Table 18/Q.713 */
	[SCCP_MSG_TYPE_IT] = {
		0
	},
	/* Table 19/Q.713 */
	[SCCP_MSG_TYPE_XUDT] = {
		SUA_IEI_SEGMENTATION, SUA_IEI_IMPORTANCE, 0
	},
	/* Table 20/Q.713 */
	[SCCP_MSG_TYPE_XUDTS] = {
		SUA_IEI_SEGMENTATION, SUA_IEI_IMPORTANCE, 0
	},
	/* Table 21/Q.713 */
	[SCCP_MSG_TYPE_LUDT] = {
		SUA_IEI_SEGMENTATION, SUA_IEI_IMPORTANCE, 0
	},
	/* Table 22/Q.713 */
	[SCCP_MSG_TYPE_LUDTS] = {
		SUA_IEI_SEGMENTATION, SUA_IEI_IMPORTANCE, 0
	},
};


static bool sccp_is_mandatory(enum sccp_message_types type, const struct xua_msg_part *part)
{
	unsigned int i;

	if (type >= ARRAY_SIZE(sccp_mandatory))
		return false;

	for (i = 0; i < MAX_IES; i++) {
		uint16_t val = sccp_mandatory[type][i];
		if (val == 0) {
			/* end of list, don't iterate further */
			return false;
		}
		if (val == part->tag) {
			/* found in list, it's mandatory */
			return true;
		}
	}
	/* not mandatory */
	return false;
}

static bool sccp_option_permitted(enum sccp_message_types type, const struct xua_msg_part *part)
{
	unsigned int i;

	if (type >= ARRAY_SIZE(sccp_optional))
		return false;

	for (i = 0; i < MAX_IES; i++) {
		uint16_t val = sccp_optional[type][i];
		if (val == 0) {
			/* end of list, don't iterate further */
			return false;
		}
		if (val == part->tag) {
			/* found in list, it's permitted */
			return true;
		}
	}
	/* not permitted */
	return false;
}

static int xua_ies_to_sccp_opts(struct msgb *msg, uint8_t *ptr_opt,
				enum sccp_message_types type, struct xua_msg *xua)
{
	struct xua_msg_part *part;

	/* store relative pointer to start of optional part */
	*ptr_opt = msg->tail - ptr_opt;

	llist_for_each_entry(part, &xua->headers, entry) {
		/* make sure we don't add a SCCP option for information
		 * that is already present in mandatory fixed or
		 * mandatory variable parts of the header */
		if (!sccp_is_mandatory(type, part) && sccp_option_permitted(type, part))
			sccp_msg_add_sua_opt(type, msg, part);
	}
	msgb_put_u8(msg, SCCP_PNC_END_OF_OPTIONAL);

	return 0;
}

/* store a 'local reference' as big-eidian 24bit value at local_ref */
static void store_local_ref(struct sccp_source_reference *local_ref, struct xua_msg *xua, uint16_t iei)
{
	uint32_t tmp32 = xua_msg_get_u32(xua, iei);
	local_ref->octet1 = (tmp32 >> 16) & 0xff;
	local_ref->octet2 = (tmp32 >> 8) & 0xff;
	local_ref->octet3 = tmp32 & 0xff;
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_cr(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_request *req = (struct sccp_connection_request *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, req->proto_class);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, load_24be(&req->source_local_reference));
	/* Variable Part */
	if (!sccp_ptr_part_consistent(msg, &req->variable_called))
		return NULL;
	sccp_addr_to_sua_ptr(xua, SUA_IEI_DEST_ADDR, msg, &req->variable_called);
	/* Optional Part */
	return sccp_to_xua_opt(msg, &req->optional_start, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static int sua_to_sccp_cr(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_request *req;
	req = (struct sccp_connection_request *) msgb_put(msg, sizeof(*req));

	/* Fixed Part */
	req->type = SCCP_MSG_TYPE_CR;
	req->proto_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	store_local_ref(&req->source_local_reference, xua, SUA_IEI_SRC_REF);
	/* Variable Part */
	sccp_add_var_addr(msg, &req->variable_called, xua, SUA_IEI_DEST_ADDR);

	/* Optional Part */
	return xua_ies_to_sccp_opts(msg, &req->optional_start, req->type, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_cc(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_confirm *cnf = (struct sccp_connection_confirm *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, cnf->proto_class);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&cnf->destination_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, load_24be(&cnf->source_local_reference));
	/* Optional Part */
	return sccp_to_xua_opt(msg, &cnf->optional_start, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static int sua_to_sccp_cc(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_confirm *cnf;
	cnf = (struct sccp_connection_confirm *) msgb_put(msg, sizeof(*cnf));

	/* Fixed Part */
	cnf->type = SCCP_MSG_TYPE_CC;
	cnf->proto_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	store_local_ref(&cnf->destination_local_reference, xua, SUA_IEI_DEST_REF);
	store_local_ref(&cnf->source_local_reference, xua, SUA_IEI_SRC_REF);
	/* Optional Part */
	return xua_ies_to_sccp_opts(msg, &cnf->optional_start, cnf->type, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_cref(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_refused *ref = (struct sccp_connection_refused *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&ref->destination_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | ref->cause);
	/* Optional Part */
	return sccp_to_xua_opt(msg, &ref->optional_start, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static int sua_to_sccp_cref(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_refused *ref;
	ref = (struct sccp_connection_refused *) msgb_put(msg, sizeof(*ref));

	/* Fixed Part */
	ref->type = SCCP_MSG_TYPE_CREF;
	store_local_ref(&ref->destination_local_reference, xua, SUA_IEI_DEST_REF);
	ref->cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE) & 0xff;
	/* Optional Part */
	return xua_ies_to_sccp_opts(msg, &ref->optional_start, ref->type, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_rlsd(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_released *rlsd = (struct sccp_connection_released *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&rlsd->destination_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, load_24be(&rlsd->source_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RELEASE | rlsd->release_cause);
	/* Optional Part */
	return sccp_to_xua_opt(msg, &rlsd->optional_start, xua);
}

static int sua_to_sccp_rlsd(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_released *rlsd;
	rlsd =(struct sccp_connection_released *) msgb_put(msg, sizeof(*rlsd));

	/* Fixed Part */
	rlsd->type = SCCP_MSG_TYPE_RLSD;
	store_local_ref(&rlsd->destination_local_reference, xua, SUA_IEI_DEST_REF);
	store_local_ref(&rlsd->source_local_reference, xua, SUA_IEI_SRC_REF);
	rlsd->release_cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE) & 0xff;

	/* Optional Part */
	return xua_ies_to_sccp_opts(msg, &rlsd->optional_start, rlsd->type, xua);
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_rlc(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_release_complete *rlc;
	rlc = (struct sccp_connection_release_complete *) msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&rlc->destination_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, load_24be(&rlc->source_local_reference));
	return xua;
}

static int sua_to_sccp_rlc(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_connection_release_complete *rlc;
	rlc = (struct sccp_connection_release_complete *) msgb_put(msg, sizeof(*rlc));

	/* Fixed Part */
	rlc->type = SCCP_MSG_TYPE_RLC;
	store_local_ref(&rlc->destination_local_reference, xua, SUA_IEI_DEST_REF);
	store_local_ref(&rlc->source_local_reference, xua, SUA_IEI_SRC_REF);
	return 0;
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_dt1(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_form1 *dt1 = (struct sccp_data_form1 *) msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&dt1->destination_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_SEGMENTATION, dt1->segmenting);
	/* Variable Part */
	if (!sccp_ptr_part_consistent(msg, &dt1->variable_start))
		return NULL;
	sccp_data_to_sua_ptr(xua, SUA_IEI_DATA, msg, &dt1->variable_start);
	return xua;
}

static int sua_to_sccp_dt1(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_form1 *dt1;
	dt1 = (struct sccp_data_form1 *) msgb_put(msg, sizeof(*dt1));

	/* Fixed Part */
	dt1->type = SCCP_MSG_TYPE_DT1;
	store_local_ref(&dt1->destination_local_reference, xua, SUA_IEI_DEST_REF);
	dt1->segmenting = xua_msg_get_u32(xua, SUA_IEI_SEGMENTATION);
	/* Variable Part */
	sccp_add_variable_part(msg, &dt1->variable_start, xua, SUA_IEI_DATA);
	return 0;
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_udt(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_unitdata *udt = (struct sccp_data_unitdata *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, udt->proto_class);
	/* Variable Part */
	if (!sccp_ptr_part_consistent(msg, &udt->variable_called))
		return NULL;
	sccp_addr_to_sua_ptr(xua, SUA_IEI_DEST_ADDR, msg, &udt->variable_called);
	if (!sccp_ptr_part_consistent(msg, &udt->variable_calling))
		return NULL;
	sccp_addr_to_sua_ptr(xua, SUA_IEI_SRC_ADDR, msg, &udt->variable_calling);
	if (!sccp_ptr_part_consistent(msg, &udt->variable_data))
		return NULL;
	sccp_data_to_sua_ptr(xua, SUA_IEI_DATA, msg, &udt->variable_data);
	return xua;

}

static int sua_to_sccp_udt(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_unitdata *udt;
	udt = (struct sccp_data_unitdata *) msgb_put(msg, sizeof(*udt));

	/* Fixed Part */
	udt->type = SCCP_MSG_TYPE_UDT;
	udt->proto_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	/* Variable Part */
	sccp_add_var_addr(msg, &udt->variable_called, xua, SUA_IEI_DEST_ADDR);
	sccp_add_var_addr(msg, &udt->variable_calling, xua, SUA_IEI_SRC_ADDR);
	sccp_add_variable_part(msg, &udt->variable_data, xua, SUA_IEI_DATA);
	return 0;
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_udts(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_unitdata_service *udts;
	udts =(struct sccp_data_unitdata_service *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RETURN | udts->return_cause);
	/* Variable Part */
	if (!sccp_ptr_part_consistent(msg, &udts->variable_called))
		return NULL;
	sccp_addr_to_sua_ptr(xua, SUA_IEI_DEST_ADDR, msg, &udts->variable_called);
	if (!sccp_ptr_part_consistent(msg, &udts->variable_calling))
		return NULL;
	sccp_addr_to_sua_ptr(xua, SUA_IEI_SRC_ADDR, msg, &udts->variable_calling);
	if (!sccp_ptr_part_consistent(msg, &udts->variable_data))
		return NULL;
	sccp_data_to_sua_ptr(xua, SUA_IEI_DATA, msg, &udts->variable_data);
	return xua;

}

static int sua_to_sccp_udts(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_unitdata_service *udts;
	udts = (struct sccp_data_unitdata_service *) msgb_put(msg, sizeof(*udts));

	/* Fixed Part */
	udts->type = SCCP_MSG_TYPE_UDTS;
	udts->return_cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE) & 0xff;
	/* Variable Part */
	sccp_add_var_addr(msg, &udts->variable_called, xua, SUA_IEI_DEST_ADDR);
	sccp_add_var_addr(msg, &udts->variable_calling, xua, SUA_IEI_SRC_ADDR);
	sccp_add_variable_part(msg, &udts->variable_data, xua, SUA_IEI_DATA);
	return 0;
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_it(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_it *it = (struct sccp_data_it *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, it->proto_class);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, load_24be(&it->source_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&it->destination_local_reference));
	if ((it->proto_class & 0xF) == 3) {
		//xua_msg_add_u32(xua, SUA_IEI_SEQUENCING, it->sequencing);
		xua_msg_add_u32(xua, SUA_IEI_CREDIT, it->credit);
	}
	return xua;
}

static int sua_to_sccp_it(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_data_it *it;
	it = (struct sccp_data_it *) msgb_put(msg, sizeof(*it));

	/* Fixed Part */
	it->type = SCCP_MSG_TYPE_IT;
	it->proto_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS);
	store_local_ref(&it->destination_local_reference, xua, SUA_IEI_DEST_REF);
	store_local_ref(&it->source_local_reference, xua, SUA_IEI_SRC_REF);
	if ((it->proto_class & 0xF) == 3) {
		//it->sequencing
		it->credit = xua_msg_get_u32(xua, SUA_IEI_CREDIT);
	}

	return 0;
}

/*! \returns \ref xua in case of success, NULL on error (xua not freed!) */
static struct xua_msg *sccp_to_xua_err(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_proto_err *err = (struct sccp_proto_err *)msg->l2h;

	/* Fixed Part */
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, load_24be(&err->destination_local_reference));
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_ERROR | err->error_cause);
	return xua;
}

static int sua_to_sccp_err(struct msgb *msg, struct xua_msg *xua)
{
	struct sccp_proto_err *err;
	err = (struct sccp_proto_err *) msgb_put(msg, sizeof(*err));

	/* Fixed Part */
	err->type = SCCP_MSG_TYPE_ERR;
	store_local_ref(&err->destination_local_reference, xua, SUA_IEI_DEST_REF);
	err->error_cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE) & 0xff;
	return 0;
}

/*! \brief convert SCCP message to a SUA message
 *  \param[in] msg message buffer holding SCCP message at l2h
 *  \returns callee-allocated xUA message on success; NULL on error */
struct xua_msg *osmo_sccp_to_xua(struct msgb *msg)
{
	struct xua_msg *xua;

	if (msgb_l2len(msg) < 1) {
		LOGP(DLSUA, LOGL_ERROR, "Short SCCP Message, cannot transcode\n");
		return NULL;
	}

	xua = xua_msg_alloc();
	if (!xua)
		return NULL;

	switch (msg->l2h[0]) {
	case SCCP_MSG_TYPE_CR:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CORE);
		if (!sccp_to_xua_cr(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_CC:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COAK);
		if (!sccp_to_xua_cc(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_CREF:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COREF);
		if (!sccp_to_xua_cref(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_RLSD:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
		if (!sccp_to_xua_rlsd(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_RLC:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELCO);
		if (!sccp_to_xua_rlc(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_DT1:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CODT);
		if (!sccp_to_xua_dt1(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_UDT:
		xua->hdr = XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDT);
		if (!sccp_to_xua_udt(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_UDTS:
		xua->hdr = XUA_HDR(SUA_MSGC_CL, SUA_CL_CLDR);
		if (!sccp_to_xua_udts(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_IT:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COIT);
		if (!sccp_to_xua_it(msg, xua))
			goto malformed;
		return xua;
	case SCCP_MSG_TYPE_ERR:
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COERR);
		if (!sccp_to_xua_err(msg, xua))
			goto malformed;
		return xua;
	/* Unsupported Message Types */
	case SCCP_MSG_TYPE_DT2:
	case SCCP_MSG_TYPE_AK:
	case SCCP_MSG_TYPE_ED:
	case SCCP_MSG_TYPE_EA:
	case SCCP_MSG_TYPE_RSR:
	case SCCP_MSG_TYPE_RSC:
	case SCCP_MSG_TYPE_XUDT:
	case SCCP_MSG_TYPE_XUDTS:
	case SCCP_MSG_TYPE_LUDT:
	case SCCP_MSG_TYPE_LUDTS:
		LOGP(DLSUA, LOGL_ERROR, "Unsupported SCCP message %s\n",
			osmo_sccp_msg_type_name(msg->l2h[0]));
		xua_msg_free(xua);
		return NULL;
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unsupported SCCP message type %u\n",
			msg->l2h[0]);
		xua_msg_free(xua);
		return NULL;
	}

	return NULL;

malformed:
	LOGP(DLSUA, LOGL_ERROR, "Malformed SCCP message %s\n",
	     osmo_sccp_msg_type_name(msg->l2h[0]));
	xua_msg_free(xua);
	return NULL;
}

/*! \brief convert parsed SUA message to SCCP message
 *  \param[in] xua parsed SUA message to be converted
 *  \returns callee-allocated msgb containing encoded SCCP message */
struct msgb *osmo_sua_to_sccp(struct xua_msg *xua)
{
	struct msgb *msg = sccp_msgb_alloc("SCCP from SUA");
	int rc;

	switch (xua->hdr.msg_class) {
	case SUA_MSGC_CL:
		switch (xua->hdr.msg_type) {
		case SUA_CL_CLDT:
			rc = sua_to_sccp_udt(msg, xua);
			break;
		case SUA_CL_CLDR:
			rc = sua_to_sccp_udts(msg, xua);
			break;
		default:
			LOGP(DLSUA, LOGL_ERROR, "Unsupported SUA message %s\n",
				xua_hdr_dump(xua, &xua_dialect_sua));
			goto out_err;
		}
		break;
	case SUA_MSGC_CO:
		switch (xua->hdr.msg_type) {
		case SUA_CO_CORE:
			rc = sua_to_sccp_cr(msg, xua);
			break;
		case SUA_CO_COAK:
			rc = sua_to_sccp_cc(msg, xua);
			break;
		case SUA_CO_COREF:
			rc = sua_to_sccp_cref(msg, xua);
			break;
		case SUA_CO_RELRE:
			rc = sua_to_sccp_rlsd(msg, xua);
			break;
		case SUA_CO_RELCO:
			rc = sua_to_sccp_rlc(msg, xua);
			break;
		case SUA_CO_CODT:
			rc = sua_to_sccp_dt1(msg, xua);
			break;
		case SUA_CO_COIT:
			rc = sua_to_sccp_it(msg, xua);
			break;
		case SUA_CO_COERR:
			rc = sua_to_sccp_err(msg, xua);
			break;
		default:
			LOGP(DLSUA, LOGL_ERROR, "Unsupported SUA message %s\n",
				xua_hdr_dump(xua, &xua_dialect_sua));
			goto out_err;
		}
		break;
	default:
		LOGP(DLSUA, LOGL_ERROR, "Unsupported SUA message class %s\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		goto out_err;
	}

	if (rc < 0)  {
		LOGP(DLSUA, LOGL_ERROR, "Malformed SUA message %s\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		goto out_err;
	}

	return msg;

out_err:
	msgb_free(msg);
	return NULL;
}
