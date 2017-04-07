/* Minimal implementation of RFC 3868 - SCCP User Adaptation Layer */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/fsm.h>

#include <osmocom/netif/stream.h>
#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "xua_asp_fsm.h"
#include "xua_internal.h"
#include "sccp_internal.h"

/* Appendix C.4 of Q.714 (all in milliseconds) */
#define CONNECTION_TIMER	( 1 * 60 * 100)
#define TX_INACT_TIMER		( 7 * 60 * 100)	/* RFC 3868 Ch. 8. */
#define RX_INACT_TIMER		(15 * 60 * 100) /* RFC 3868 Ch. 8. */
#define RELEASE_TIMER		(     10 * 100)
#define RELEASE_REP_TIMER	(     10 * 100)
#define INT_TIMER		( 1 * 60 * 100)
#define GUARD_TIMER		(23 * 60 * 100)
#define RESET_TIMER		(     10 * 100)

#define SCCP_MSG_SIZE 2048
#define SCCP_MSG_HEADROOM 512

struct msgb *sccp_msgb_alloc(const char *name)
{
	if (!name)
		name = "SCCP";
	return msgb_alloc_headroom(SCCP_MSG_SIZE+SCCP_MSG_HEADROOM,
				   SCCP_MSG_HEADROOM, name);
}

/***********************************************************************
 * Protocol Definition (string tables, mandatory IE checking)
 ***********************************************************************/

static const struct value_string sua_iei_names[] = {
	{ SUA_IEI_ROUTE_CTX,		"Routing Context" },
	{ SUA_IEI_CORR_ID,		"Correlation Id" },
	{ SUA_IEI_REG_RESULT,		"Registration Result" },
	{ SUA_IEI_DEREG_RESULT,		"De-Registration Result" },

	{ SUA_IEI_S7_HOP_CTR,		"SS7 Hop Counter" },
	{ SUA_IEI_SRC_ADDR,		"Source Address" },
	{ SUA_IEI_DEST_ADDR,		"Destination Address" },
	{ SUA_IEI_SRC_REF,		"Source Reference" },
	{ SUA_IEI_DEST_REF,		"Destination Reference" },
	{ SUA_IEI_CAUSE,		"Cause" },
	{ SUA_IEI_SEQ_NR,		"Sequence Number" },
	{ SUA_IEI_RX_SEQ_NR,		"Receive Sequence Number" },
	{ SUA_IEI_ASP_CAPA,		"ASP Capability" },
	{ SUA_IEI_CREDIT,		"Credit" },
	{ SUA_IEI_DATA,			"Data" },
	{ SUA_IEI_USER_CAUSE,		"User/Cause" },
	{ SUA_IEI_NET_APPEARANCE,	"Network Appearance" },
	{ SUA_IEI_ROUTING_KEY,		"Routing Key" },
	{ SUA_IEI_DRN,			"DRN Label" },
	{ SUA_IEI_TID,			"TID Label" },
	{ SUA_IEI_SMI,			"SMI" },
	{ SUA_IEI_IMPORTANCE,		"Importance" },
	{ SUA_IEI_MSG_PRIO,		"Message Priority" },
	{ SUA_IEI_PROTO_CLASS,		"Protocol Class" },
	{ SUA_IEI_SEQ_CTRL,		"Sequence Control" },
	{ SUA_IEI_SEGMENTATION,		"Segmentation" },
	{ SUA_IEI_CONG_LEVEL,		"Congestion Level" },

	{ SUA_IEI_GT,			"Global Title" },
	{ SUA_IEI_PC,			"Point Code" },
	{ SUA_IEI_SSN,			"Sub-System Number" },
	{ SUA_IEI_IPv4,			"IPv4 Address" },
	{ SUA_IEI_HOST,			"Host Name" },
	{ SUA_IEI_IPv6,			"IPv6 Address" },
	{ 0, NULL }
};

#define MAND_IES(msgt, ies)	[msgt] = (ies)

static const uint16_t cldt_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_SRC_ADDR,
	SUA_IEI_DEST_ADDR, SUA_IEI_SEQ_CTRL, SUA_IEI_DATA, 0
};
static const uint16_t cldr_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_CAUSE, SUA_IEI_SRC_ADDR,
	SUA_IEI_DEST_ADDR, 0
};
static const struct value_string sua_cl_msgt_names[] = {
	{ SUA_CL_CLDT,		"CLDT" },
	{ SUA_CL_CLDR,		"CLDR" },
	{ 0, NULL }
};
static const struct xua_msg_class msg_class_cl = {
	.name = "CL",
	.msgt_names = sua_cl_msgt_names,
	.iei_names = sua_iei_names,
	.mand_ies = {
		MAND_IES(SUA_CL_CLDT, cldt_mand_ies),
		MAND_IES(SUA_CL_CLDR, cldr_mand_ies),
	},
};

static const uint16_t codt_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_DATA, 0
};
static const uint16_t coda_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, 0
};
static const uint16_t core_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_SRC_REF,
	SUA_IEI_DEST_ADDR, SUA_IEI_SEQ_CTRL, 0
};
static const uint16_t coak_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_DEST_REF,
	SUA_IEI_SRC_REF, SUA_IEI_SEQ_CTRL, 0
};
static const uint16_t coref_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_CAUSE, 0
};
static const uint16_t relre_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF,
	SUA_IEI_CAUSE, 0
};
static const uint16_t relco_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, 0
};
static const uint16_t resre_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF,
	SUA_IEI_CAUSE, 0
};
static const uint16_t resco_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_SRC_REF, 0
};
static const uint16_t coerr_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_DEST_REF, SUA_IEI_CAUSE, 0
};
static const uint16_t coit_mand_ies[] = {
	SUA_IEI_ROUTE_CTX, SUA_IEI_PROTO_CLASS, SUA_IEI_SRC_REF,
	SUA_IEI_DEST_REF, 0
};
static const struct value_string sua_co_msgt_names[] = {
	{ SUA_CO_CODT,		"CODT" },
	{ SUA_CO_CODA,		"CODA" },
	{ SUA_CO_CORE,		"CORE" },
	{ SUA_CO_COAK,		"COAK" },
	{ SUA_CO_COREF,		"COREF" },
	{ SUA_CO_RELRE,		"RELRE" },
	{ SUA_CO_RELCO,		"RELCO" },
	{ SUA_CO_RESRE,		"RESRE" },
	{ SUA_CO_RESCO,		"RESCO" },
	{ SUA_CO_COERR,		"COERR" },
	{ SUA_CO_COIT,		"COIT" },
	{ 0, NULL }
};
static const struct xua_msg_class msg_class_co = {
	.name = "CO",
	.msgt_names = sua_co_msgt_names,
	.iei_names = sua_iei_names,
	.mand_ies = {
		MAND_IES(SUA_CO_CODT, codt_mand_ies),
		MAND_IES(SUA_CO_CODA, coda_mand_ies),
		MAND_IES(SUA_CO_CORE, core_mand_ies),
		MAND_IES(SUA_CO_COAK, coak_mand_ies),
		MAND_IES(SUA_CO_COREF, coref_mand_ies),
		MAND_IES(SUA_CO_RELRE, relre_mand_ies),
		MAND_IES(SUA_CO_RELCO, relco_mand_ies),
		MAND_IES(SUA_CO_RESRE, resre_mand_ies),
		MAND_IES(SUA_CO_RESCO, resco_mand_ies),
		MAND_IES(SUA_CO_COERR, coerr_mand_ies),
		MAND_IES(SUA_CO_COIT, coit_mand_ies),
	},
};

const struct xua_dialect xua_dialect_sua = {
	.name = "SUA",
	.ppid = SUA_PPID,
	.port = SUA_PORT,
	.log_subsys = DLSUA,
	.class = {
		[SUA_MSGC_MGMT] = &m3ua_msg_class_mgmt,
		[SUA_MSGC_SNM] = &m3ua_msg_class_snm,
		[SUA_MSGC_ASPSM] = &m3ua_msg_class_aspsm,
		[SUA_MSGC_ASPTM] = &m3ua_msg_class_asptm,
		[SUA_MSGC_CL] = &msg_class_cl,
		[SUA_MSGC_CO] = &msg_class_co,
		[SUA_MSGC_RKM] = &m3ua_msg_class_rkm,
	},
};

/***********************************************************************
 * ERROR generation
 ***********************************************************************/

static struct xua_msg *sua_gen_error(uint32_t err_code)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_MGMT, SUA_MGMT_ERR);
	xua->hdr.version = SUA_VERSION;
	xua_msg_add_u32(xua, SUA_IEI_ERR_CODE, err_code);

	return xua;
}

static struct xua_msg *sua_gen_error_msg(uint32_t err_code, struct msgb *msg)
{
	struct xua_msg *xua = sua_gen_error(err_code);
	unsigned int len_max_40 = msgb_length(msg);

	if (len_max_40 > 40)
		len_max_40 = 40;

	xua_msg_add_data(xua, SUA_IEI_DIAG_INFO, len_max_40, msgb_data(msg));

	return xua;
}

/***********************************************************************
 * Transmitting SUA messsages to SCTP
 ***********************************************************************/

static int sua_tx_xua_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct msgb *msg = xua_to_msg(SUA_VERSION, xua);

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA);

	if (!msg) {
		LOGPASP(asp, DLSUA, LOGL_ERROR, "Error encoding SUA Msg\n");
		return -1;
	}

	msgb_sctp_ppid(msg) = SUA_PPID;
	return osmo_ss7_asp_send(asp, msg);
}

/*! \brief Send a given xUA message via a given SUA Application Server
 *  \param[in] as Application Server through which to send \ref xua
 *  \param[in] xua xUA message to be sent
 *  \return 0 on success; negative on error */
int sua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	OSMO_ASSERT(as->cfg.proto == OSMO_SS7_ASP_PROT_SUA);

	/* FIXME: Select ASP within AS depending on traffic mode */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp)
			continue;
		if (asp)
			break;
	}
	if (!asp) {
		LOGP(DLSUA, LOGL_ERROR, "No ASP in AS, dropping message\n");
		return -ENODEV;
	}

	return sua_tx_xua_asp(asp, xua);
}

/***********************************************************************
 * Receiving SUA messsages from SCTP
 ***********************************************************************/

/*! \brief Decode SUA Global Title according to RFC3868 Section 3.10.2.3
 *  \param[out] gt User-allocated structure for decoded output
 *  \param[in] data binary-encoded data
 *  \param[in] datalen length of \ref data in octets
 */
int sua_parse_gt(struct osmo_sccp_gt *gt, const uint8_t *data, unsigned int datalen)
{
	uint8_t num_digits;
	char *out_digits;
	unsigned int i;

	/* 8 byte header at minimum, plus digits */
	if (datalen < 8)
		return -EINVAL;

	/* parse header */
	gt->gti = data[3];
	num_digits = data[4];
	gt->tt = data[5];
	gt->npi = data[6];
	gt->nai = data[7];

	/* parse digits */
	out_digits = gt->digits;
	for (i = 0; i < datalen-8; i++) {
		uint8_t byte = data[8+i];
		*out_digits++ = osmo_bcd2char(byte & 0x0F);
		if (out_digits - gt->digits >= num_digits)
			break;
		*out_digits++ = osmo_bcd2char(byte >> 4);
		if (out_digits - gt->digits >= num_digits)
			break;
	}
	*out_digits++ = '\0';

	return 0;
}

/*! \brief parse SCCP address from given xUA message part
 *  \param[out] out caller-allocated decoded SCCP address struct
 *  \param[in] param xUA message part containing address
    \returns 0 on success; negative on error */
int sua_addr_parse_part(struct osmo_sccp_addr *out,
			const struct xua_msg_part *param)
{
	const struct xua_parameter_hdr *par;
	uint16_t ri;
	uint16_t ai;
	uint16_t pos;
	uint16_t par_tag, par_len, par_datalen;
	uint32_t *p32;

	memset(out, 0, sizeof(*out));

	LOGP(DLSUA, LOGL_DEBUG, "%s(IEI=0x%04x) (%d) %s\n", __func__,
	     param->tag, param->len,
	     osmo_hexdump(param->dat, param->len));

	if (param->len < 4) {
		LOGP(DLSUA, LOGL_ERROR, "SUA IEI 0x%04x: invalid address length: %d\n",
		     param->tag, param->len);
		return -EINVAL;
	}

	pos = 0;
	ri = ntohs(*(uint16_t*) &param->dat[pos]);
	pos += 2;
	ai = ntohs(*(uint16_t*) &param->dat[pos]);
	pos += 2;

	switch (ri) {
	case SUA_RI_GT:
		out->ri = OSMO_SCCP_RI_GT;
		break;
	case SUA_RI_SSN_PC:
		out->ri = OSMO_SCCP_RI_SSN_PC;
		break;
	case SUA_RI_SSN_IP:
		out->ri = OSMO_SCCP_RI_SSN_IP;
		break;
	case SUA_RI_HOST:
	default:
		LOGP(DLSUA, LOGL_ERROR, "SUA IEI 0x%04x: Routing Indicator not supported yet: %d\n",
		     param->tag, ri);
		return -ENOTSUP;
	}

	if (ai != 7) {
#if 0
		LOGP(DLSUA, LOGL_ERROR, "SUA IEI 0x%04x: Address Indicator not supported yet: %x\n",
		     param->tag, ai);
		return -ENOTSUP;
#endif
	}

	/*
	 * FIXME: this parses the encapsulated T16L16V IEs on the go. We
	 * probably want to have a separate general parsing function storing
	 * the subparts in xua_msg_part. But before we do, we should find more
	 * users of this subpart parsing and be aware of the performance
	 * tradeoff.
	 */

	while (pos + sizeof(*par) < param->len) {
		par = (struct xua_parameter_hdr *) &param->dat[pos];
		par_tag = ntohs(par->tag);
		par_len = ntohs(par->len);
		par_datalen = par_len - sizeof(*par);

		LOGP(DLSUA, LOGL_DEBUG, "SUA IEI 0x%04x pos %hu/%hu: subpart tag 0x%04x, len %hu\n",
		     param->tag, pos, param->len, par_tag, par_len);

		switch (par_tag) {
		case SUA_IEI_PC:
			if (par_datalen != 4)
				goto subpar_fail;
			p32 = (uint32_t*)par->data;
			out->pc = ntohl(*p32);
			out->presence |= OSMO_SCCP_ADDR_T_PC;
			break;
		case SUA_IEI_SSN:
			if (par_datalen != 4)
				goto subpar_fail;
			/* 24 zero bits, then 8 bits SSN */
			out->ssn = par->data[3];
			out->presence |= OSMO_SCCP_ADDR_T_SSN;
			break;
		case SUA_IEI_GT:
			if (par_datalen < 8)
				goto subpar_fail;
			sua_parse_gt(&out->gt, par->data, par_datalen);
			out->presence |= OSMO_SCCP_ADDR_T_GT;
			break;
		case SUA_IEI_IPv4:
			if (par_datalen != 4)
				goto subpar_fail;
			p32 = (uint32_t*)par->data;
			/* no endian conversion, both network order */
			out->ip.v4.s_addr = *p32;
			out->presence |= OSMO_SCCP_ADDR_T_IPv4;
			break;
		default:
			LOGP(DLSUA, LOGL_ERROR, "SUA IEI 0x%04x: Unknown subpart tag %hd\n",
			     param->tag, par_tag);
			goto subpar_fail;
		}

		pos += par_len;
	}

	return 0;

subpar_fail:
	LOGP(DLSUA, LOGL_ERROR, "Failed to parse subparts of address IEI=0x%04x\n",
	     param->tag);
	return -EINVAL;
}

/*! \brief parse SCCP address from given xUA message IE
 *  \param[out] out caller-allocated decoded SCCP address struct
 *  \param[in] xua xUA message
 *  \param[in] iei Information Element Identifier inside \ref xua
    \returns 0 on success; negative on error */
int sua_addr_parse(struct osmo_sccp_addr *out, struct xua_msg *xua, uint16_t iei)
{
	const struct xua_msg_part *param = xua_msg_find_tag(xua, iei);
	if (!param) {
		memset(out, 0, sizeof(*out));
		return -ENODEV;
	}

	return sua_addr_parse_part(out, param);
}

/* connectionless messages received from socket */
static int sua_rx_cl(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct osmo_sccp_instance *inst = asp->inst->sccp;

	/* We feed into SCRC, which then hands the message into
	 * either SCLC or SCOC, or forwards it to MTP */
	return scrc_rx_mtp_xfer_ind_xua(inst, xua);
}

/* connection-oriented messages received from socket */
static int sua_rx_co(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct osmo_sccp_instance *inst = asp->inst->sccp;

	/* We feed into SCRC, which then hands the message into
	 * either SCLC or SCOC, or forwards it to MTP */
	return scrc_rx_mtp_xfer_ind_xua(inst, xua);
}

static int sua_rx_mgmt_err(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	uint32_t err_code = xua_msg_get_u32(xua, SUA_IEI_ERR_CODE);

	LOGPASP(asp, DLSUA, LOGL_ERROR, "Received MGMT_ERR '%s': %s\n",
		get_value_string(m3ua_err_names, err_code),
		xua_msg_dump(xua, &xua_dialect_sua));

	/* NEVER return != 0 here, as we cannot respont to an ERR
	 * message with another ERR! */
	return 0;
}

static int sua_rx_mgmt_ntfy(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct m3ua_notify_params ntfy;
	const char *type_name, *info_name;

	m3ua_decode_notify(&ntfy, asp, xua);

	type_name = get_value_string(m3ua_ntfy_type_names, ntfy.status_type);

	switch (ntfy.status_type) {
	case M3UA_NOTIFY_T_STATCHG:
		info_name = get_value_string(m3ua_ntfy_stchg_names,
						ntfy.status_info);
		break;
	case M3UA_NOTIFY_T_OTHER:
		info_name = get_value_string(m3ua_ntfy_other_names,
						ntfy.status_info);
		break;
	default:
		info_name = "NULL";
		break;
	}
	LOGPASP(asp, DLSUA, LOGL_NOTICE, "Received NOTIFY Type %s:%s (%s)\n",
		type_name, info_name,
		ntfy.info_string ? ntfy.info_string : "");

	if (ntfy.info_string)
		talloc_free(ntfy.info_string);

	/* TODO: should we report this soemwhere? */
	return 0;
}

static int sua_rx_mgmt(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	switch (xua->hdr.msg_type) {
	case SUA_MGMT_ERR:
		return sua_rx_mgmt_err(asp, xua);
	case SUA_MGMT_NTFY:
		return sua_rx_mgmt_ntfy(asp, xua);
	default:
		return SUA_ERR_UNSUPP_MSG_TYPE;
	}
}

/* map from SUA ASPSM/ASPTM to xua_asp_fsm event */
static const struct xua_msg_event_map sua_aspxm_map[] = {
	{ SUA_MSGC_ASPSM, SUA_ASPSM_UP, XUA_ASP_E_ASPSM_ASPUP },
	{ SUA_MSGC_ASPSM, SUA_ASPSM_DOWN, XUA_ASP_E_ASPSM_ASPDN },
	{ SUA_MSGC_ASPSM, SUA_ASPSM_BEAT, XUA_ASP_E_ASPSM_BEAT },
	{ SUA_MSGC_ASPSM, SUA_ASPSM_UP_ACK, XUA_ASP_E_ASPSM_ASPUP_ACK },
	{ SUA_MSGC_ASPSM, SUA_ASPSM_DOWN_ACK, XUA_ASP_E_ASPSM_ASPDN_ACK },
	{ SUA_MSGC_ASPSM, SUA_ASPSM_BEAT_ACK, XUA_ASP_E_ASPSM_BEAT_ACK },
	{ SUA_MSGC_ASPTM, SUA_ASPTM_ACTIVE, XUA_ASP_E_ASPTM_ASPAC },
	{ SUA_MSGC_ASPTM, SUA_ASPTM_INACTIVE, XUA_ASP_E_ASPTM_ASPIA },
	{ SUA_MSGC_ASPTM, SUA_ASPTM_ACTIVE_ACK, XUA_ASP_E_ASPTM_ASPAC_ACK },
	{ SUA_MSGC_ASPTM, SUA_ASPTM_INACTIVE_ACK, XUA_ASP_E_ASPTM_ASPIA_ACK },
};

static int sua_rx_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	int event;

	/* map from the SUA message class and message type to the XUA
	 * ASP FSM event number */
	event = xua_msg_event_map(xua, sua_aspxm_map,
				      ARRAY_SIZE(sua_aspxm_map));
	if (event < 0)
		return SUA_ERR_UNSUPP_MSG_TYPE;

	/* deliver that event to the ASP FSM */
	osmo_fsm_inst_dispatch(asp->fi, event, xua);

	return 0;
}

/*! \brief process SUA message received from socket
 *  \param[in] asp Application Server Process receiving \ref msg
 *  \param[in] msg received message buffer
 *  \returns 0 on success; negative on error */
int sua_rx_msg(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct xua_msg *xua = NULL, *err = NULL;
	int rc = 0;

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA);

	/* caller owns msg memory, we shall neither free it here nor
	 * keep references beyon the execution of this function and its
	 * callees. */

	if (!asp->inst->sccp) {
		LOGP(DLSUA, LOGL_ERROR, "%s(asp->inst->sccp=NULL)\n", __func__);
		return -EIO;
	}

	xua = xua_from_msg(1, msgb_length(msg), msg->data);
	if (!xua) {
		struct xua_common_hdr *hdr = (struct xua_common_hdr *) msg->data;

		LOGPASP(asp, DLSUA, LOGL_ERROR, "Unable to parse incoming "
			"SUA message\n");

		if (hdr->version != SUA_VERSION)
			err = sua_gen_error_msg(SUA_ERR_INVALID_VERSION, msg);
		else
			err = sua_gen_error_msg(SUA_ERR_PARAM_FIELD_ERR, msg);
		goto out;
	}

#if 0
	xua->mtp.opc = ;
	xua->mtp.dpc = ;
#endif
	xua->mtp.sio = MTP_SI_SCCP;

	LOGPASP(asp, DLSUA, LOGL_DEBUG, "Received SUA Message (%s)\n",
		xua_hdr_dump(xua, &xua_dialect_sua));

	if (!xua_dialect_check_all_mand_ies(&xua_dialect_sua, xua)) {
		/* FIXME: Return error? */
		err = sua_gen_error_msg(SUA_ERR_MISSING_PARAM, msg);
		goto out;
	}

	/* TODO: check for SCTP Strema ID */
	/* TODO: check if any AS configured in ASP */
	/* TODO: check for valid routing context */

	switch (xua->hdr.msg_class) {
	case SUA_MSGC_CL:
		rc = sua_rx_cl(asp, xua);
		break;
	case SUA_MSGC_CO:
		rc = sua_rx_co(asp, xua);
		break;
	case SUA_MSGC_ASPSM:
	case SUA_MSGC_ASPTM:
		rc = sua_rx_asp(asp, xua);
		break;
	case SUA_MSGC_MGMT:
		rc = sua_rx_mgmt(asp, xua);
		break;
	case SUA_MSGC_SNM:
	case SUA_MSGC_RKM:
		/* FIXME */
		LOGPASP(asp, DLSUA, LOGL_NOTICE, "Received unsupported SUA "
			"Message Class %u\n", xua->hdr.msg_class);
		err = sua_gen_error_msg(SUA_ERR_UNSUPP_MSG_CLASS, msg);
		break;
	default:
		LOGPASP(asp, DLSUA, LOGL_NOTICE, "Received unknown SUA "
			"Message Class %u\n", xua->hdr.msg_class);
		err = sua_gen_error_msg(SUA_ERR_UNSUPP_MSG_CLASS, msg);
		break;
	}

	if (rc > 0)
		err = sua_gen_error_msg(rc, msg);

out:
	if (err)
		sua_tx_xua_asp(asp, err);

	xua_msg_free(xua);

	return rc;
}

