#pragma once

#include <unistd.h>
#include <osmocom/core/msgb.h>
#include <osmocom/sigtran/sccp_sap.h>

int osmo_sccp_tx_unitdata(struct osmo_sccp_user *scu,
			  const struct osmo_sccp_addr *calling_addr,
			  const struct osmo_sccp_addr *called_addr,
			  const uint8_t *data, unsigned int len);

int osmo_sccp_tx_unitdata_msg(struct osmo_sccp_user *scu,
			      const struct osmo_sccp_addr *calling_addr,
			      const struct osmo_sccp_addr *called_addr,
			      struct msgb *msg);

void osmo_sccp_make_addr_pc_ssn(struct osmo_sccp_addr *addr,
				uint32_t pc, uint32_t ssn);

void osmo_sccp_addr_set_ssn(struct osmo_sccp_addr *addr, uint32_t ssn);

int osmo_sccp_tx_unitdata_ranap(struct osmo_sccp_user *scu,
				uint32_t src_point_code,
				uint32_t dst_point_code,
				const uint8_t *data, unsigned int len);

int osmo_sccp_tx_conn_req(struct osmo_sccp_user *scu, uint32_t conn_id,
			  const struct osmo_sccp_addr *calling_addr,
			  const struct osmo_sccp_addr *called_addr,
			  const uint8_t *data, unsigned int len);

int osmo_sccp_tx_conn_req_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
			      const struct osmo_sccp_addr *calling_addr,
			      const struct osmo_sccp_addr *called_addr,
			      struct msgb *msg);

int osmo_sccp_tx_data(struct osmo_sccp_user *scu, uint32_t conn_id,
		      const uint8_t *data, unsigned int len);

int osmo_sccp_tx_data_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
			  struct msgb *msg);

int osmo_sccp_tx_disconn(struct osmo_sccp_user *scu, uint32_t conn_id,
			 const struct osmo_sccp_addr *resp_addr,
			 uint32_t cause);

int osmo_sccp_tx_disconn_data(struct osmo_sccp_user *scu, uint32_t conn_id,
				const struct osmo_sccp_addr *resp_addr,
				uint32_t cause, const uint8_t *data, size_t len);

int osmo_sccp_tx_conn_resp_msg(struct osmo_sccp_user *scu, uint32_t conn_id,
				const struct osmo_sccp_addr *resp_addr,
				struct msgb *msg);

int osmo_sccp_tx_conn_resp(struct osmo_sccp_user *scu, uint32_t conn_id,
			   const struct osmo_sccp_addr *resp_addr,
			   const uint8_t *data, unsigned int len);

char *osmo_sccp_gt_dump(const struct osmo_sccp_gt *gt);
char *osmo_sccp_addr_dump(const struct osmo_sccp_addr *addr);

int osmo_sccp_inst_addr_to_str_buf(char *buf, size_t buf_len, const struct osmo_sccp_instance *sccp,
				   const struct osmo_sccp_addr *addr);
char *osmo_sccp_inst_addr_to_str_c(void *ctx, const struct osmo_sccp_instance *sccp,
				   const struct osmo_sccp_addr *addr);
int osmo_sccp_addr_to_str_buf(char *buf, size_t buf_len, const struct osmo_ss7_instance *ss7,
			      const struct osmo_sccp_addr *addr);
char *osmo_sccp_addr_to_str_c(void *ctx, const struct osmo_ss7_instance *ss7, const struct osmo_sccp_addr *addr);

int osmo_sccp_addr_to_id_buf(char *buf, size_t buf_len, const struct osmo_ss7_instance *ss7,
			      const struct osmo_sccp_addr *addr);
char *osmo_sccp_addr_to_id_c(void *ctx, const struct osmo_ss7_instance *ss7, const struct osmo_sccp_addr *addr);

bool osmo_sccp_conn_id_exists(const struct osmo_sccp_instance *inst, uint32_t id);

char *osmo_sccp_addr_name(const struct osmo_ss7_instance *ss7, const struct osmo_sccp_addr *addr);
char *osmo_sccp_inst_addr_name(const struct osmo_sccp_instance *sccp, const struct osmo_sccp_addr *addr);
