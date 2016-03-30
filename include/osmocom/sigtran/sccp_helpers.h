#pragma once
#include <unistd.h>
#include <osmocom/core/msgb.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sua.h>

int sccp_tx_unitdata(struct osmo_sua_link *link,
		     const struct osmo_sccp_addr *calling_addr,
		     const struct osmo_sccp_addr *called_addr,
		     uint8_t *data, unsigned int len);

int sccp_tx_unitdata_msg(struct osmo_sua_link *link,
			 const struct osmo_sccp_addr *calling_addr,
			 const struct osmo_sccp_addr *called_addr,
			 struct msgb *msg);

void sccp_make_addr_pc_ssn(struct osmo_sccp_addr *addr, uint32_t pc, uint32_t ssn);

int sccp_tx_conn_req(struct osmo_sua_link *link, uint32_t conn_id,
		     const struct osmo_sccp_addr *calling_addr,
		     const struct osmo_sccp_addr *called_addr,
		     uint8_t *data, unsigned int len);

int sccp_tx_conn_req_msg(struct osmo_sua_link *link, uint32_t conn_id,
			 const struct osmo_sccp_addr *calling_addr,
			 const struct osmo_sccp_addr *called_addr,
			 struct msgb *msg);

int sccp_tx_data(struct osmo_sua_link *link, uint32_t conn_id,
		 uint8_t *data, unsigned int len);

int sccp_tx_data_msg(struct osmo_sua_link *link, uint32_t conn_id,
		     struct msgb *msg);
