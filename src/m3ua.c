/* Minimal implementation of RFC 4666 - MTP3 User Adaptation Layer */

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

#include <osmocom/netif/stream.h>
#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>

#include "xua_asp_fsm.h"
#include "xua_internal.h"

#define M3UA_MSGB_SIZE 1500

/***********************************************************************
 * Protocol Definition (string tables, mandatory IE checking)
 ***********************************************************************/

/* Section 3.8.1 */
const struct value_string m3ua_err_names[] = {
	{ M3UA_ERR_INVALID_VERSION,	"Invalid Version" },
	{ M3UA_ERR_UNSUPP_MSG_CLASS,	"Unsupported Message Class" },
	{ M3UA_ERR_UNSUPP_MSG_TYPE,	"Unsupported Message Type" },
	{ M3UA_ERR_UNSUPP_TRAF_MOD_TYP,	"Unsupported Traffic Mode Type" },
	{ M3UA_ERR_UNEXPECTED_MSG,	"Unexpected Message" },
	{ M3UA_ERR_PROTOCOL_ERR,	"Protocol Error" },
	{ M3UA_ERR_INVAL_STREAM_ID,	"Invalid Stream Identifier" },
	{ M3UA_ERR_REFUSED_MGMT_BLOCKING, "Refused - Management Blocking" },
	{ M3UA_ERR_ASP_ID_REQD,		"ASP Identifier Required" },
	{ M3UA_ERR_INVAL_ASP_ID,	"Invalid ASP Identifier" },
	{ M3UA_ERR_INVAL_PARAM_VAL,	"Invalid Parameter Value" },
	{ M3UA_ERR_PARAM_FIELD_ERR,	"Parameter Field Error" },
	{ M3UA_ERR_UNEXP_PARAM,		"Unexpected Parameter" },
	{ M3UA_ERR_DEST_STATUS_UNKN,	"Destination Status Unknown" },
	{ M3UA_ERR_INVAL_NET_APPEAR,	"Invalid Network Appearance" },
	{ M3UA_ERR_MISSING_PARAM,	"Missing Parameter" },
	{ M3UA_ERR_INVAL_ROUT_CTX,	"Invalid Routing Context" },
	{ M3UA_ERR_NO_CONFGD_AS_FOR_ASP,"No Configured AS for ASP" },
	{ SUA_ERR_SUBSYS_STATUS_UNKN,	"Subsystem Status Unknown" },
	{ SUA_ERR_INVAL_LOADSH_LEVEL,	"Invalid loadsharing level" },
	{ 0, NULL }
};

const struct value_string m3ua_ntfy_type_names[] = {
	{ M3UA_NOTIFY_T_STATCHG,	"State Change" },
	{ M3UA_NOTIFY_T_OTHER,		"Other" },
	{ 0, NULL }
};

const struct value_string m3ua_ntfy_stchg_names[] = {
	{ M3UA_NOTIFY_I_RESERVED,	"Reserved" },
	{ M3UA_NOTIFY_I_AS_INACT,	"AS Inactive" },
	{ M3UA_NOTIFY_I_AS_ACT,		"AS Active" },
	{ M3UA_NOTIFY_I_AS_PEND,	"AS Pending" },
	{ 0, NULL }
};

const struct value_string m3ua_ntfy_other_names[] = {
	{ M3UA_NOTIFY_I_OT_INS_RES,	"Insufficient ASP Resouces active in AS" },
	{ M3UA_NOTIFY_I_OT_ALT_ASP_ACT,	"Alternative ASP Active" },
	{ M3UA_NOTIFY_I_OT_ASP_FAILURE,	"ASP Failure" },
	{ 0, NULL }
};

static const struct value_string m3ua_iei_names[] = {
	{ M3UA_IEI_INFO_STRING,		"INFO String" },
	{ M3UA_IEI_ROUTE_CTX,		"Routing Context" },
	{ M3UA_IEI_DIAG_INFO,		"Diagnostic Info" },
	{ M3UA_IEI_HEARDBT_DATA,	"Heartbeat Data" },
	{ M3UA_IEI_TRAF_MODE_TYP,	"Traffic Mode Type" },
	{ M3UA_IEI_ERR_CODE,		"Error Code" },
	{ M3UA_IEI_STATUS,		"Status" },
	{ M3UA_IEI_ASP_ID,		"ASP Identifier" },
	{ M3UA_IEI_AFFECTED_PC,		"Affected Point Code" },
	{ M3UA_IEI_CORR_ID,		"Correlation Id" },

	{ M3UA_IEI_NET_APPEAR,		"Network Appearance" },
	{ M3UA_IEI_USER_CAUSE,		"User/Cause" },
	{ M3UA_IEI_CONG_IND,		"Congestion Indication" },
	{ M3UA_IEI_CONC_DEST,		"Concerned Destination" },
	{ M3UA_IEI_ROUT_KEY,		"Routing Key" },
	{ M3UA_IEI_REG_RESULT,		"Registration Result" },
	{ M3UA_IEI_DEREG_RESULT,	"De-Registration Result" },
	{ M3UA_IEI_LOC_RKEY_ID,		"Local Routing-Key Identifier" },
	{ M3UA_IEI_DEST_PC,		"Destination Point Code" },
	{ M3UA_IEI_SVC_IND,		"Service Indicators" },
	{ M3UA_IEI_ORIG_PC,		"Originating Point Code List" },
	{ M3UA_IEI_PROT_DATA,		"Protocol Data" },
	{ M3UA_IEI_REG_STATUS,		"Registration Status" },
	{ M3UA_IEI_DEREG_STATUS,	"De-Registration Status" },
	{ 0, NULL }
};

#define MAND_IES(msgt, ies)	[msgt] = (ies)

/* XFER */
static const uint16_t data_mand_ies[] = {
	M3UA_IEI_PROT_DATA, 0
};
static const struct value_string m3ua_xfer_msgt_names[] = {
	{ M3UA_XFER_DATA,	"DATA" },
	{ 0, NULL }
};
static const struct xua_msg_class msg_class_xfer = {
	.name = "XFER",
	.msgt_names = m3ua_xfer_msgt_names,
	.mand_ies = {
		MAND_IES(M3UA_XFER_DATA, data_mand_ies),
	},
};

/* SNM */
static const uint16_t duna_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t dava_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t daud_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t scon_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t dupu_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, M3UA_IEI_USER_CAUSE, 0
};
static const uint16_t drst_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const struct value_string m3ua_snm_msgt_names[] = {
	{ M3UA_SNM_DUNA,	"DUNA" },
	{ M3UA_SNM_DAVA,	"DAVA" },
	{ M3UA_SNM_DAUD,	"DAUD" },
	{ M3UA_SNM_SCON,	"SCON" },
	{ M3UA_SNM_DUPU,	"DUPU" },
	{ M3UA_SNM_DRST,	"DRST" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_snm = {
	.name = "SNM",
	.msgt_names = m3ua_snm_msgt_names,
	.mand_ies = {
		MAND_IES(M3UA_SNM_DUNA, duna_mand_ies),
		MAND_IES(M3UA_SNM_DAVA, dava_mand_ies),
		MAND_IES(M3UA_SNM_DAUD, daud_mand_ies),
		MAND_IES(M3UA_SNM_SCON, scon_mand_ies),
		MAND_IES(M3UA_SNM_DUPU, dupu_mand_ies),
		MAND_IES(M3UA_SNM_DRST, drst_mand_ies),
	},
};

/* ASPSM */
static const struct value_string m3ua_aspsm_msgt_names[] = {
	{ M3UA_ASPSM_UP,	"UP" },
	{ M3UA_ASPSM_DOWN,	"DOWN" },
	{ M3UA_ASPSM_BEAT,	"BEAT" },
	{ M3UA_ASPSM_UP_ACK,	"UP-ACK" },
	{ M3UA_ASPSM_DOWN_ACK,	"DOWN-ACK" },
	{ M3UA_ASPSM_BEAT_ACK,	"BEAT-ACK" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_aspsm = {
	.name = "ASPSM",
	.msgt_names = m3ua_aspsm_msgt_names,
};

/* ASPTM */
const struct value_string m3ua_asptm_msgt_names[] = {
	{ M3UA_ASPTM_ACTIVE,	"ACTIVE" },
	{ M3UA_ASPTM_INACTIVE,	"INACTIVE" },
	{ M3UA_ASPTM_ACTIVE_ACK,"ACTIVE-ACK" },
	{ M3UA_ASPTM_INACTIVE_ACK, "INACTIVE-ACK" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_asptm = {
	.name = "ASPTM",
	.msgt_names = m3ua_asptm_msgt_names,
	.iei_names = m3ua_iei_names,
};

/* MGMT */
static const uint16_t err_req_ies[] = {
	M3UA_IEI_ERR_CODE, 0
};
static const uint16_t ntfy_req_ies[] = {
	M3UA_IEI_STATUS, 0
};
static const struct value_string m3ua_mgmt_msgt_names[] = {
	{ M3UA_MGMT_ERR,	"ERROR" },
	{ M3UA_MGMT_NTFY,	"NOTIFY" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_mgmt = {
	.name = "MGMT",
	.msgt_names = m3ua_mgmt_msgt_names,
	.iei_names = m3ua_iei_names,
	.mand_ies = {
		MAND_IES(M3UA_MGMT_ERR, err_req_ies),
		MAND_IES(M3UA_MGMT_NTFY, ntfy_req_ies),
	},
};

/* RKM */
static const uint16_t reg_req_ies[] = {
	M3UA_IEI_ROUT_KEY, 0
};
static const uint16_t reg_rsp_ies[] = {
	M3UA_IEI_REG_RESULT, 0
};
static const uint16_t dereg_req_ies[] = {
	M3UA_IEI_ROUT_KEY, 0
};
static const uint16_t dereg_rsp_ies[] = {
	M3UA_IEI_DEREG_RESULT, 0
};
static const struct value_string m3ua_rkm_msgt_names[] = {
	{ M3UA_RKM_REG_REQ,	"REG-REQ" },
	{ M3UA_RKM_REG_RSP,	"REG-RESP" },
	{ M3UA_RKM_DEREG_REQ,	"DEREG-REQ" },
	{ M3UA_RKM_DEREG_RSP,	"DEREG-RESP" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_rkm = {
	.name = "RKM",
	.msgt_names = m3ua_rkm_msgt_names,
	.iei_names = m3ua_iei_names,
	.mand_ies = {
		MAND_IES(M3UA_RKM_REG_REQ, reg_req_ies),
		MAND_IES(M3UA_RKM_REG_RSP, reg_rsp_ies),
		MAND_IES(M3UA_RKM_DEREG_REQ, dereg_req_ies),
		MAND_IES(M3UA_RKM_DEREG_RSP, dereg_rsp_ies),
	},
};

/* M3UA dialect of XUA, MGMT,XFER,SNM,ASPSM,ASPTM,RKM */
const struct xua_dialect xua_dialect_m3ua = {
	.name = "M3UA",
	.ppid = M3UA_PPID,
	.port = M3UA_PORT,
	.log_subsys = DLM3UA,
	.class = {
		[M3UA_MSGC_MGMT] = &m3ua_msg_class_mgmt,
		[M3UA_MSGC_XFER] = &msg_class_xfer,
		[M3UA_MSGC_SNM] = &m3ua_msg_class_snm,
		[M3UA_MSGC_ASPSM] = &m3ua_msg_class_aspsm,
		[M3UA_MSGC_ASPTM] = &m3ua_msg_class_asptm,
		[M3UA_MSGC_RKM] = &m3ua_msg_class_rkm,
	},
};

/* convert osmo_mtp_transfer_param to m3ua_data_hdr */
void mtp_xfer_param_to_m3ua_dh(struct m3ua_data_hdr *mdh,
				const struct osmo_mtp_transfer_param *param)
{
	mdh->opc = htonl(param->opc);
	mdh->dpc = htonl(param->dpc);
	mdh->si = param->sio & 0xF;
	mdh->ni = (param->sio >> 6) & 0x3;
	mdh->mp = (param->sio >> 4) & 0x3;
	mdh->sls = param->sls;
}

/* convert m3ua_data_hdr to osmo_mtp_transfer_param */
void m3ua_dh_to_xfer_param(struct osmo_mtp_transfer_param *param,
			   const struct m3ua_data_hdr *mdh)
{
	param->opc = ntohl(mdh->opc);
	param->dpc = ntohl(mdh->dpc);
	param->sls = mdh->sls;
	/* re-construct SIO */
	param->sio = (mdh->si & 0xF) |
		     (mdh->mp & 0x3 << 4) |
		     (mdh->ni & 0x3 << 6);
}

#define M3UA_MSG_SIZE 2048
#define M3UA_MSG_HEADROOM 512

struct msgb *m3ua_msgb_alloc(const char *name)
{
	if (!name)
		name = "M3UA";
	return msgb_alloc_headroom(M3UA_MSG_SIZE+M3UA_MSG_HEADROOM,
				   M3UA_MSG_HEADROOM, name);
}

/***********************************************************************
 * ERROR generation
 ***********************************************************************/

static struct xua_msg *m3ua_gen_error(uint32_t err_code)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(M3UA_MSGC_MGMT, M3UA_MGMT_ERR);
	xua->hdr.version = M3UA_VERSION;
	xua_msg_add_u32(xua, M3UA_IEI_ERR_CODE, err_code);

	return xua;
}

static struct xua_msg *m3ua_gen_error_msg(uint32_t err_code, struct msgb *msg)
{
	struct xua_msg *xua = m3ua_gen_error(err_code);
	unsigned int len_max_40 = msgb_length(msg);

	if (len_max_40 > 40)
		len_max_40 = 40;

	xua_msg_add_data(xua, M3UA_IEI_DIAG_INFO, len_max_40, msgb_data(msg));

	return xua;
}

/***********************************************************************
 * NOTIFY generation
 ***********************************************************************/

/* RFC4666 Ch. 3.8.2. Notify */
struct xua_msg *m3ua_encode_notify(const struct m3ua_notify_params *npar)
{
	struct xua_msg *xua = xua_msg_alloc();
	uint32_t status;

	xua->hdr = XUA_HDR(M3UA_MSGC_MGMT, M3UA_MGMT_NTFY);

	status = M3UA_NOTIFY(htons(npar->status_type), htons(npar->status_info));
	/* cannot use xua_msg_add_u32() as it does endian conversion */
	xua_msg_add_data(xua, M3UA_IEI_STATUS, sizeof(status), (uint8_t *) &status);

	/* Conditional: ASP Identifier */
	if (npar->presence & NOTIFY_PAR_P_ASP_ID)
		xua_msg_add_u32(xua, M3UA_IEI_ASP_ID, npar->asp_id);

	/* Optional Routing Context */
	if (npar->presence & NOTIFY_PAR_P_ROUTE_CTX)
		xua_msg_add_u32(xua, M3UA_IEI_ROUTE_CTX, npar->route_ctx);

	/* Optional: Info String */
	if (npar->info_string)
		xua_msg_add_data(xua, M3UA_IEI_INFO_STRING,
				 strlen(npar->info_string)+1,
				 (uint8_t *) npar->info_string);

	return xua;
}

/* RFC4666 Ch. 3.8.2. Notify */
int m3ua_decode_notify(struct m3ua_notify_params *npar, void *ctx,
			const struct xua_msg *xua)
{
	struct xua_msg_part *info_ie, *aspid_ie, *status_ie, *rctx_ie;
	uint32_t status;

	/* cannot use xua_msg_get_u32() as it does endian conversion */
	status_ie = xua_msg_find_tag(xua, M3UA_IEI_STATUS);
	status = *(uint32_t *) status_ie->dat;

	aspid_ie = xua_msg_find_tag(xua, M3UA_IEI_ASP_ID);
	rctx_ie = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	info_ie = xua_msg_find_tag(xua, M3UA_IEI_INFO_STRING);

	npar->presence = 0;
	npar->status_type = ntohs(status & 0xffff);
	npar->status_info = ntohs(status >> 16);

	if (aspid_ie) {
		npar->asp_id = xua_msg_part_get_u32(aspid_ie);
		npar->presence |= NOTIFY_PAR_P_ASP_ID;
	}

	if (rctx_ie) {
		npar->route_ctx = xua_msg_part_get_u32(rctx_ie);
		npar->presence |= NOTIFY_PAR_P_ROUTE_CTX;
	}

	if (info_ie) {
		npar->info_string = talloc_size(ctx, info_ie->len);
		memcpy(npar->info_string, info_ie->dat, info_ie->len);
	} else
		npar->info_string = NULL;

	return 0;
}

/***********************************************************************
 * Transmitting M3UA messsages to SCTP
 ***********************************************************************/

static int m3ua_tx_xua_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct msgb *msg = xua_to_msg(M3UA_VERSION, xua);

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA);

	xua_msg_free(xua);

	if (!msg) {
		LOGP(DLM3UA, LOGL_ERROR, "Error encoding M3UA Msg\n");
		return -1;
	}

	msgb_sctp_ppid(msg) = M3UA_PPID;
	return osmo_ss7_asp_send(asp, msg);
}

/*! \brief Send a given xUA message via a given M3UA Application Server
 *  \param[in] as Application Server through which to send \ref xua
 *  \param[in] xua xUA message to be sent
 *  \return 0 on success; negative on error */
int m3ua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	OSMO_ASSERT(as->cfg.proto == OSMO_SS7_ASP_PROT_M3UA);

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp)
			continue;
		if (asp)
			break;
	}
	if (!asp) {
		LOGP(DLM3UA, LOGL_ERROR, "No ASP entroy in AS, dropping message\n");
		xua_msg_free(xua);
		return -ENODEV;
	}

	return m3ua_tx_xua_asp(asp, xua);
}

/***********************************************************************
 * Receiving M3UA messsages from SCTP
 ***********************************************************************/

/* obtain the destination point code from a M3UA message in XUA fmt * */
struct m3ua_data_hdr *data_hdr_from_m3ua(struct xua_msg *xua)
{
	struct xua_msg_part *data_ie;
	struct m3ua_data_hdr *data_hdr;

	if (xua->hdr.msg_class != M3UA_MSGC_XFER ||
	    xua->hdr.msg_type != M3UA_XFER_DATA)
		return NULL;

	data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	if (!data_ie)
		return NULL;
	data_hdr = (struct m3ua_data_hdr *) data_ie->dat;

	return data_hdr;
}

static int m3ua_rx_xfer(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct m3ua_data_hdr *dh;

	/* store the MTP-level information in the xua_msg for use by
	 * higher layer protocols */
	dh = data_hdr_from_m3ua(xua);
	OSMO_ASSERT(dh);
	m3ua_dh_to_xfer_param(&xua->mtp, dh);

	return m3ua_hmdc_rx_from_l2(asp->inst, xua);
}

static int m3ua_rx_mgmt_err(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	uint32_t err_code = xua_msg_get_u32(xua, M3UA_IEI_ERR_CODE);

	LOGPASP(asp, DLM3UA, LOGL_ERROR, "Received MGMT_ERR '%s': %s\n",
		get_value_string(m3ua_err_names, err_code),
		xua_msg_dump(xua, &xua_dialect_m3ua));

	/* NEVER return != 0 here, as we cannot respont to an ERR
	 * message with another ERR! */
	return 0;
}

static int m3ua_rx_mgmt_ntfy(struct osmo_ss7_asp *asp, struct xua_msg *xua)
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
	LOGPASP(asp, DLM3UA, LOGL_NOTICE, "Received NOTIFY Type %s:%s (%s)\n",
		type_name, info_name,
		ntfy.info_string ? ntfy.info_string : "");

	if (ntfy.info_string)
		talloc_free(ntfy.info_string);

	/* TODO: should we report this soemwhere? */
	return 0;
}

static int m3ua_rx_mgmt(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	switch (xua->hdr.msg_type) {
	case M3UA_MGMT_ERR:
		return m3ua_rx_mgmt_err(asp, xua);
	case M3UA_MGMT_NTFY:
		return m3ua_rx_mgmt_ntfy(asp, xua);
	default:
		return M3UA_ERR_UNSUPP_MSG_TYPE;
	}
}

/* map from M3UA ASPSM/ASPTM to xua_asp_fsm event */
static const struct xua_msg_event_map m3ua_aspxm_map[] = {
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_UP, XUA_ASP_E_ASPSM_ASPUP },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_DOWN, XUA_ASP_E_ASPSM_ASPDN },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_BEAT, XUA_ASP_E_ASPSM_BEAT },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_UP_ACK, XUA_ASP_E_ASPSM_ASPUP_ACK },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_DOWN_ACK, XUA_ASP_E_ASPSM_ASPDN_ACK },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_BEAT_ACK, XUA_ASP_E_ASPSM_BEAT_ACK },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_ACTIVE, XUA_ASP_E_ASPTM_ASPAC },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_INACTIVE, XUA_ASP_E_ASPTM_ASPIA },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_ACTIVE_ACK, XUA_ASP_E_ASPTM_ASPAC_ACK },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_INACTIVE_ACK, XUA_ASP_E_ASPTM_ASPIA_ACK },
};


static int m3ua_rx_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	int event;

	/* map from the M3UA message class and message type to the XUA
	 * ASP FSM event number */
	event = xua_msg_event_map(xua, m3ua_aspxm_map,
				  ARRAY_SIZE(m3ua_aspxm_map));
	if (event < 0)
		return M3UA_ERR_UNSUPP_MSG_TYPE;

	/* deliver that event to the ASP FSM */
	osmo_fsm_inst_dispatch(asp->fi, event, xua);

	return 0;
}

/*! \brief process M3UA message received from socket
 *  \param[in] asp Application Server Process receiving \ref msg
 *  \param[in] msg received message buffer
 *  \returns 0 on success; negative on error */
int m3ua_rx_msg(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct xua_msg *xua = NULL, *err = NULL;
	int rc = 0;

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA);

	/* caller owns msg memory, we shall neither free it here nor
	 * keep references beyond the executin of this function and its
	 * callees */

	xua = xua_from_msg(M3UA_VERSION, msgb_length(msg), msgb_data(msg));
	if (!xua) {
		struct xua_common_hdr *hdr = (struct xua_common_hdr *) msg->data;

		LOGPASP(asp, DLM3UA, LOGL_ERROR, "Unable to parse incoming "
			"M3UA message\n");

		if (hdr->version != M3UA_VERSION)
			err = m3ua_gen_error_msg(M3UA_ERR_INVALID_VERSION, msg);
		else
			err = m3ua_gen_error_msg(M3UA_ERR_PARAM_FIELD_ERR, msg);
		goto out;
	}

	LOGPASP(asp, DLM3UA, LOGL_DEBUG, "Received M3UA Message (%s)\n",
		xua_hdr_dump(xua, &xua_dialect_m3ua));

	if (!xua_dialect_check_all_mand_ies(&xua_dialect_m3ua, xua)) {
		err = m3ua_gen_error_msg(M3UA_ERR_MISSING_PARAM, msg);
		goto out;
	}

	/* TODO: check for SCTP Strema ID */
	/* TODO: check if any AS configured in ASP */
	/* TODO: check for valid routing context */

	switch (xua->hdr.msg_class) {
	case M3UA_MSGC_XFER:
		rc = m3ua_rx_xfer(asp, xua);
		break;
	case M3UA_MSGC_ASPSM:
	case M3UA_MSGC_ASPTM:
		rc = m3ua_rx_asp(asp, xua);
		break;
		break;
	case M3UA_MSGC_MGMT:
		rc = m3ua_rx_mgmt(asp, xua);
		break;
	case M3UA_MSGC_SNM:
	case M3UA_MSGC_RKM:
		/* FIXME */
		LOGPASP(asp, DLM3UA, LOGL_NOTICE, "Received unsupported M3UA "
			"Message Class %u\n", xua->hdr.msg_class);
		err = m3ua_gen_error_msg(M3UA_ERR_UNSUPP_MSG_CLASS, msg);
		break;
	default:
		LOGPASP(asp, DLM3UA, LOGL_NOTICE, "Received unknown M3UA "
			"Message Class %u\n", xua->hdr.msg_class);
		err = m3ua_gen_error_msg(M3UA_ERR_UNSUPP_MSG_CLASS, msg);
		break;
	}

	if (rc > 0)
		err = m3ua_gen_error_msg(rc, msg);

out:
	if (err)
		m3ua_tx_xua_asp(asp, err);

	xua_msg_free(xua);

	return rc;
}
