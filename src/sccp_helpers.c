/* SCCP User SAP helper functions */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
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

#include <string.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include "sccp_internal.h"

#define SCU_MSG_SIZE		2048
#define SCU_MSG_HEADROOM	512

static struct msgb *scu_msgb_alloc(const char *name)
{
	return msgb_alloc_headroom(SCU_MSG_SIZE+SCU_MSG_HEADROOM, SCU_MSG_HEADROOM, name);
}

void osmo_sccp_make_addr_pc_ssn(struct osmo_sccp_addr *addr, uint32_t pc, uint32_t ssn)
{
	*addr = (struct osmo_sccp_addr){
			.presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC,
			.ri = OSMO_SCCP_RI_SSN_PC,
			.ssn = ssn,
			.pc = pc,
		};
}

void osmo_sccp_addr_set_ssn(struct osmo_sccp_addr *addr, uint32_t ssn)
{
	addr->presence |= OSMO_SCCP_ADDR_T_SSN;
	addr->ssn = ssn;
}

int osmo_sccp_tx_unitdata(struct osmo_sccp_user *scu,
			  const struct osmo_sccp_addr *calling_addr,
			  const struct osmo_sccp_addr *called_addr,
			  const uint8_t *data, unsigned int len)
{
	struct msgb *msg = scu_msgb_alloc(__func__);
	struct osmo_scu_prim *prim;
	struct osmo_scu_unitdata_param *param;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	param = &prim->u.unitdata;
	memcpy(&param->calling_addr, calling_addr, sizeof(*calling_addr));
	memcpy(&param->called_addr, called_addr, sizeof(*called_addr));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST, msg);

	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);

	return osmo_sccp_user_sap_down(scu, &prim->oph);
}

int osmo_sccp_tx_unitdata_ranap(struct osmo_sccp_user *scu,
				uint32_t src_point_code,
				uint32_t dst_point_code,
				const uint8_t *data, unsigned int len)
{
	struct osmo_sccp_addr calling_addr;
	struct osmo_sccp_addr called_addr;
	osmo_sccp_make_addr_pc_ssn(&calling_addr, src_point_code,
				   OSMO_SCCP_SSN_RANAP);
	osmo_sccp_make_addr_pc_ssn(&called_addr, dst_point_code,
				   OSMO_SCCP_SSN_RANAP);
	return osmo_sccp_tx_unitdata(scu, &calling_addr, &called_addr,
				     data, len);
}

int osmo_sccp_tx_unitdata_msg(struct osmo_sccp_user *scu,
			      const struct osmo_sccp_addr *calling_addr,
			      const struct osmo_sccp_addr *called_addr,
			      struct msgb *msg)
{
	int rc;

	rc = osmo_sccp_tx_unitdata(scu, calling_addr, called_addr,
				   msg->data, msgb_length(msg));
	msgb_free(msg);

	return rc;
}

int osmo_sccp_tx_conn_req(struct osmo_sccp_user *scu, uint32_t conn_id,
			  const struct osmo_sccp_addr *calling_addr,
			  const struct osmo_sccp_addr *called_addr,
			  const uint8_t *data, unsigned int len)
{
	struct msgb *msg = scu_msgb_alloc(__func__);
	struct osmo_scu_prim *prim;
	struct osmo_scu_connect_param *param;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_REQUEST, msg);
	param = &prim->u.connect;
	if (calling_addr)
		memcpy(&param->calling_addr, calling_addr, sizeof(*calling_addr));
	memcpy(&param->called_addr, called_addr, sizeof(*called_addr));
	param->sccp_class = 2;
	param->conn_id = conn_id;

	if (data && len) {
		msg->l2h = msgb_put(msg, len);
		memcpy(msg->l2h, data, len);
	}

	return osmo_sccp_user_sap_down(scu, &prim->oph);
}

int osmo_sccp_tx_conn_req_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
			      const struct osmo_sccp_addr *calling_addr,
			      const struct osmo_sccp_addr *called_addr,
			      struct msgb *msg)
{
	int rc;

	rc = osmo_sccp_tx_conn_req(scu, conn_id, calling_addr, called_addr,
				   msg->data, msgb_length(msg));
	msgb_free(msg);

	return rc;
}

int osmo_sccp_tx_data(struct osmo_sccp_user *scu, uint32_t conn_id,
		      const uint8_t *data, unsigned int len)
{
	struct msgb *msg = scu_msgb_alloc(__func__);
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	prim->u.data.conn_id = conn_id;

	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);

	return osmo_sccp_user_sap_down(scu, &prim->oph);
}

int osmo_sccp_tx_data_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
			  struct msgb *msg)
{
	int rc;

	rc = osmo_sccp_tx_data(scu, conn_id, msg->data, msgb_length(msg));
	msgb_free(msg);

	return rc;
}

/* N-DISCONNECT.req */
int osmo_sccp_tx_disconn(struct osmo_sccp_user *scu, uint32_t conn_id,
			 const struct osmo_sccp_addr *resp_addr,
			 uint32_t cause)
{
	struct msgb *msg = scu_msgb_alloc(__func__);
	struct osmo_scu_prim *prim;
	struct osmo_scu_disconn_param *param;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DISCONNECT,
			PRIM_OP_REQUEST, msg);
	param = &prim->u.disconnect;
	memset(param, 0, sizeof(*param));
	param->originator = OSMO_SCCP_ORIG_NS_USER;
	if (resp_addr)
		memcpy(&param->responding_addr, resp_addr, sizeof(*resp_addr));
	param->conn_id = conn_id;
	param->cause = cause;

	return osmo_sccp_user_sap_down(scu, &prim->oph);
}

/* N-CONNECT.resp */
int osmo_sccp_tx_conn_resp_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
				const struct osmo_sccp_addr *resp_addr,
				struct msgb *msg)
{
	struct osmo_scu_prim *prim;
	struct osmo_scu_connect_param *param;

	msg->l2h = msg->data;

	prim = (struct osmo_scu_prim *) msgb_push(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_RESPONSE, msg);
	param = &prim->u.connect;
	param->conn_id = conn_id;
	memcpy(&param->responding_addr, resp_addr, sizeof(*resp_addr));
	param->sccp_class = 2;

	return osmo_sccp_user_sap_down(scu, &prim->oph);
}

int osmo_sccp_tx_conn_resp(struct osmo_sccp_user *scu, uint32_t conn_id,
			   const struct osmo_sccp_addr *resp_addr,
			   const uint8_t *data, unsigned int len)
{
	struct msgb *msg = scu_msgb_alloc(__func__);

	if (data && len) {
		msg->l2h = msgb_put(msg, len);
		memcpy(msg->l2h, data, len);
	}
	return osmo_sccp_tx_conn_resp_msg(scu, conn_id, resp_addr, msg);
}

static void append_to_buf(char *buf, size_t size, bool *comma, const char *fmt, ...)
{
	va_list ap;
	size_t printed;

	va_start(ap, fmt);
	if (*comma == true) {
		strcat(buf, ",");
	} else
		*comma = true;
	printed = strlen(buf);
	OSMO_ASSERT(printed <= size);
	vsnprintf(buf + printed, size - printed, fmt, ap);
	va_end(ap);
}

char *osmo_sccp_gt_dump(const struct osmo_sccp_gt *gt)
{
	static char buf[256];
	bool comma = false;

	buf[0] = '\0';

	if (gt->gti == OSMO_SCCP_GTI_NO_GT) {
		strcat(buf, "NONE");
		return buf;
	}
	if (gt->gti == OSMO_SCCP_GTI_NAI_ONLY) {
		return buf;
	}
	if (gt->gti == OSMO_SCCP_GTI_TT_ONLY ||
	    gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC ||
	    gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC_NAI)
		append_to_buf(buf, sizeof(buf), &comma, "TT=%u", gt->tt);

	if (gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC ||
	    gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC_NAI)
		append_to_buf(buf, sizeof(buf), &comma, "NPL=%u", gt->npi);

	if (gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC_NAI)
		append_to_buf(buf, sizeof(buf), &comma, "NAI=%u", gt->nai);

	append_to_buf(buf, sizeof(buf), &comma, "DIG=%s", gt->digits);

	return buf;
}

/* Return string representation of SCCP address raw bytes in a static string. */
char *osmo_sccp_addr_dump(const struct osmo_sccp_addr *addr)
{
	static char buf[256];
	bool comma = false;
	char ipbuf[INET6_ADDRSTRLEN];

	buf[0] = '\0';

	append_to_buf(buf, sizeof(buf), &comma, "RI=%d", addr->ri);

	if (addr->presence & OSMO_SCCP_ADDR_T_PC)
		append_to_buf(buf, sizeof(buf), &comma, "PC=%u", addr->pc);
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN)
		append_to_buf(buf, sizeof(buf), &comma, "SSN=%u", addr->ssn);
	if (addr->presence & OSMO_SCCP_ADDR_T_IPv4)
		append_to_buf(buf, sizeof(buf), &comma, "IP=%s", inet_ntop(AF_INET, &addr->ip.v4, ipbuf, sizeof(ipbuf)));
	else if (addr->presence & OSMO_SCCP_ADDR_T_IPv6)
		append_to_buf(buf, sizeof(buf), &comma, "IP=%s", inet_ntop(AF_INET6, &addr->ip.v6, ipbuf, sizeof(ipbuf)));
	if (addr->gt.gti != OSMO_SCCP_GTI_NO_GT || addr->presence & OSMO_SCCP_ADDR_T_GT)
		append_to_buf(buf, sizeof(buf), &comma, "GTI=%u", addr->gt.gti);
	if (addr->presence & OSMO_SCCP_ADDR_T_GT)
		append_to_buf(buf, sizeof(buf), &comma, "GT=(%s)", osmo_sccp_gt_dump(&addr->gt));

	return buf;
}

static int sccp_addr_to_str_buf(char *buf, size_t buf_len, const struct osmo_ss7_instance *ss7,
				const struct osmo_sccp_addr *addr, char sep_char)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_len };
	char ipbuf[INET6_ADDRSTRLEN];

	OSMO_STRBUF_PRINTF(sb, "RI=%s", osmo_sccp_routing_ind_name(addr->ri));

	if (addr->presence & OSMO_SCCP_ADDR_T_PC)
		OSMO_STRBUF_PRINTF(sb, "%cPC=%s", sep_char, osmo_ss7_pointcode_print(ss7, addr->pc));
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN)
		OSMO_STRBUF_PRINTF(sb, "%cSSN=%s", sep_char, osmo_sccp_ssn_name(addr->ssn));
	if (addr->presence & OSMO_SCCP_ADDR_T_IPv4)
		OSMO_STRBUF_PRINTF(sb, "%cIP=%s", sep_char, inet_ntop(AF_INET, &addr->ip.v4, ipbuf, sizeof(ipbuf)));
	else if (addr->presence & OSMO_SCCP_ADDR_T_IPv6)
		OSMO_STRBUF_PRINTF(sb, "%cIP=%s", sep_char, inet_ntop(AF_INET6, &addr->ip.v6, ipbuf, sizeof(ipbuf)));
	if (addr->gt.gti != OSMO_SCCP_GTI_NO_GT || addr->presence & OSMO_SCCP_ADDR_T_GT)
		OSMO_STRBUF_PRINTF(sb, "%cGTI=%s", sep_char, osmo_sccp_gti_name(addr->gt.gti));
	if (addr->presence & OSMO_SCCP_ADDR_T_GT)
		OSMO_STRBUF_PRINTF(sb, "%cGT=(%s)", sep_char, osmo_sccp_gt_dump(&addr->gt));

	return sb.chars_needed;
}

int osmo_sccp_addr_to_str_buf(char *buf, size_t buf_len, const struct osmo_ss7_instance *ss7,
			      const struct osmo_sccp_addr *addr)
{
	return sccp_addr_to_str_buf(buf, buf_len, ss7, addr, ',');
}

char *osmo_sccp_addr_to_str_c(void *ctx, const struct osmo_ss7_instance *ss7, const struct osmo_sccp_addr *addr)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_sccp_addr_to_str_buf, ss7, addr)
}

/*! like osmo_sccp_addr_to_str_buf, but using only characters passing osmo_identifier_valid(). Useful for FSM and CTRL
 * IDs.
 *
 * The advantage over using osmo_sccp_addr_to_str_buf() followed by osmo_identifier_sanitize_buf() is that here, the
 * address elements are separated by ':', while osmo_identifier_sanitize_buf() would replace all characters with the
 * same, e.g. '-'.
 */
int osmo_sccp_addr_to_id_buf(char *buf, size_t buf_len, const struct osmo_ss7_instance *ss7,
			     const struct osmo_sccp_addr *addr)
{
	int rc = sccp_addr_to_str_buf(buf, buf_len, ss7, addr, ':');
	/* inet_ntop() and osmo_sccp_gt_dump() may have written non-id chars. */
	osmo_identifier_sanitize_buf(buf, "", '-');
	return rc;
}

char *osmo_sccp_addr_to_id_c(void *ctx, const struct osmo_ss7_instance *ss7, const struct osmo_sccp_addr *addr)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_sccp_addr_to_id_buf, ss7, addr)
}

/* Rather use osmo_sccp_addr_to_str_buf() or osmo_sccp_addr_to_str_c() to not use a static buffer */
char *osmo_sccp_addr_name(const struct osmo_ss7_instance *ss7, const struct osmo_sccp_addr *addr)
{
	static char buf[256];
	osmo_sccp_addr_to_str_buf(buf, sizeof(buf), ss7, addr);
	return buf;
}

int osmo_sccp_inst_addr_to_str_buf(char *buf, size_t buf_len, const struct osmo_sccp_instance *sccp,
				   const struct osmo_sccp_addr *addr)
{
	return osmo_sccp_addr_to_str_buf(buf, buf_len, sccp? sccp->ss7 : NULL, addr);
}

char *osmo_sccp_inst_addr_to_str_c(void *ctx, const struct osmo_sccp_instance *sccp,
				   const struct osmo_sccp_addr *addr)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_sccp_inst_addr_to_str_buf, sccp, addr);
}

/* Rather use osmo_sccp_inst_addr_to_str_buf() or osmo_sccp_inst_addr_to_str_c() to not use a static buffer.
 * Derive ss7 from the sccp instance and call osmo_sccp_addr_name() with that.
 * If sccp is passed as NULL, simply use the default point code format. */
char *osmo_sccp_inst_addr_name(const struct osmo_sccp_instance *sccp, const struct osmo_sccp_addr *addr)
{
	return osmo_sccp_addr_name(sccp? sccp->ss7 : NULL, addr);
}
