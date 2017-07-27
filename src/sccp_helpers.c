/* SCCP User SAP helper functions */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
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

#include <string.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include "sccp_internal.h"

static struct msgb *scu_msgb_alloc(const char *name)
{
	return sccp_msgb_alloc("SCU");
}

void osmo_sccp_make_addr_pc_ssn(struct osmo_sccp_addr *addr, uint32_t pc, uint32_t ssn)
{
	addr->presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
	addr->ri = OSMO_SCCP_RI_SSN_PC;
	addr->ssn = ssn;
	addr->pc = pc;
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

static void append_to_buf(char *buf, bool *comma, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (*comma == true) {
		strcat(buf, ",");
	} else
		*comma = true;
	vsprintf(buf+strlen(buf), fmt, ap);
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
		append_to_buf(buf, &comma, "TT=%u", gt->tt);

	if (gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC ||
	    gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC_NAI)
		append_to_buf(buf, &comma, "NPL=%u", gt->npi);

	if (gt->gti == OSMO_SCCP_GTI_TT_NPL_ENC_NAI)
		append_to_buf(buf, &comma, "NAI=%u", gt->nai);

	append_to_buf(buf, &comma, "DIG=%s", gt->digits);

	return buf;
}

char *osmo_sccp_addr_dump(const struct osmo_sccp_addr *addr)
{
	static char buf[256];
	bool comma = false;

	buf[0] = '\0';

	append_to_buf(buf, &comma, "RI=7");

	if (addr->presence & OSMO_SCCP_ADDR_T_PC)
		append_to_buf(buf, &comma, "PC=%u", addr->pc);
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN)
		append_to_buf(buf, &comma, "SSN=%u", addr->ssn);
	if (addr->presence & OSMO_SCCP_ADDR_T_IPv4)
		append_to_buf(buf, &comma, "IP=%s", inet_ntoa(addr->ip.v4));
	append_to_buf(buf, &comma, "GTI=%u", addr->gt.gti);
	if (addr->presence & OSMO_SCCP_ADDR_T_GT)
		append_to_buf(buf, &comma, "GT=(%s)", osmo_sccp_gt_dump(&addr->gt));

	return buf;
}
