/* SCCP User SAP helper functions (move to libosmo-sigtran?) */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
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

#include <string.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sua.h>

#include "sccp_helpers.h"

void sccp_make_addr_pc_ssn(struct osmo_sccp_addr *addr, uint32_t pc, uint32_t ssn)
{
	addr->presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
	addr->ssn = ssn;
	addr->pc = pc;
}

int sccp_tx_unitdata(struct osmo_sua_link *link,
		     const struct osmo_sccp_addr *calling_addr,
		     const struct osmo_sccp_addr *called_addr,
		     uint8_t *data, unsigned int len)
{
	struct msgb *msg = msgb_alloc(1024, "sccp_tx_unitdata");
	struct osmo_scu_prim *prim;
	struct osmo_scu_unitdata_param *param;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	param = &prim->u.unitdata;
	sccp_make_addr_pc_ssn(&param->calling_addr, 1, OSMO_SCCP_SSN_RANAP);
	sccp_make_addr_pc_ssn(&param->called_addr, 2, OSMO_SCCP_SSN_RANAP);
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST, msg);

	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);

	return osmo_sua_user_link_down(link, &prim->oph);
}

int sccp_tx_unitdata_msg(struct osmo_sua_link *link,
			 const struct osmo_sccp_addr *calling_addr,
			 const struct osmo_sccp_addr *called_addr,
			 struct msgb *msg)
{
	int rc;

	rc = sccp_tx_unitdata(link, calling_addr, called_addr,
			      msg->data, msgb_length(msg));
	msgb_free(msg);

	return rc;
}

int sccp_tx_conn_req(struct osmo_sua_link *link, uint32_t conn_id,
		     const struct osmo_sccp_addr *calling_addr,
		     const struct osmo_sccp_addr *called_addr,
		     uint8_t *data, unsigned int len)
{
	struct msgb *msg = msgb_alloc(1024, "sccp_tx_conn_req");
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_REQUEST, msg);
	sccp_make_addr_pc_ssn(&prim->u.connect.calling_addr, 1, OSMO_SCCP_SSN_RANAP);
	prim->u.connect.sccp_class = 2;
	prim->u.connect.conn_id = conn_id;

	if (data && len) {
		msg->l2h = msgb_put(msg, len);
		memcpy(msg->l2h, data, len);
	}

	return osmo_sua_user_link_down(link, &prim->oph);
}

int sccp_tx_conn_req_msg(struct osmo_sua_link *link, uint32_t conn_id,
			 const struct osmo_sccp_addr *calling_addr,
			 const struct osmo_sccp_addr *called_addr,
			 struct msgb *msg)
{
	int rc;

	rc = sccp_tx_conn_req(link, conn_id, calling_addr, called_addr,
			      msg->data, msgb_length(msg));
	msgb_free(msg);

	return rc;
}

int sccp_tx_data(struct osmo_sua_link *link, uint32_t conn_id,
		 uint8_t *data, unsigned int len)
{
	struct msgb *msg = msgb_alloc(1024, "sccp_tx_data");
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	prim->u.data.conn_id = conn_id;

	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);

	return osmo_sua_user_link_down(link, &prim->oph);
}

int sccp_tx_data_msg(struct osmo_sua_link *link, uint32_t conn_id,
		     struct msgb *msg)
{
	int rc;

	rc = sccp_tx_data(link, conn_id, msg->data, msgb_length(msg));
	msgb_free(msg);

	return rc;
}
