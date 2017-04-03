#pragma once

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/xua_msg.h>

struct osmo_sccp_addr;
struct m3ua_data_hdr;

int sua_addr_parse_part(struct osmo_sccp_addr *out,
			const struct xua_msg_part *param);
int sua_addr_parse(struct osmo_sccp_addr *out, struct xua_msg *xua, uint16_t iei);

int sua_parse_gt(struct osmo_sccp_gt *gt, const uint8_t *data, unsigned int datalen);

struct xua_msg *osmo_sccp_to_xua(struct msgb *msg);
struct msgb *osmo_sua_to_sccp(struct xua_msg *xua);

int sua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua);

struct osmo_mtp_prim *m3ua_to_xfer_ind(struct xua_msg *xua);
int m3ua_hmdc_rx_from_l2(struct osmo_ss7_instance *inst, struct xua_msg *xua);
int m3ua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua);
int m3ua_rx_msg(struct osmo_ss7_asp *asp, struct msgb *msg);

struct msgb *m3ua_msgb_alloc(const char *name);
struct m3ua_data_hdr *data_hdr_from_m3ua(struct xua_msg *xua);
void m3ua_dh_to_xfer_param(struct osmo_mtp_transfer_param *param,
			   const struct m3ua_data_hdr *mdh);
void mtp_xfer_param_to_m3ua_dh(struct m3ua_data_hdr *mdh,
				const struct osmo_mtp_transfer_param *param);


extern const struct xua_msg_class m3ua_msg_class_mgmt;
extern const struct xua_msg_class m3ua_msg_class_snm;
extern const struct xua_msg_class m3ua_msg_class_rkm;
extern const struct xua_msg_class m3ua_msg_class_aspsm;
extern const struct xua_msg_class m3ua_msg_class_asptm;

extern const struct value_string m3ua_err_names[];
extern const struct value_string m3ua_ntfy_type_names[];
extern const struct value_string m3ua_ntfy_stchg_names[];
extern const struct value_string m3ua_ntfy_other_names[];

#define NOTIFY_PAR_P_ASP_ID	(1 << 0)
#define NOTIFY_PAR_P_ROUTE_CTX	(1 << 1)

struct m3ua_notify_params {
	uint32_t presence;
	uint16_t status_type;
	uint16_t status_info;
	uint32_t asp_id;
	uint32_t route_ctx;
	char *info_string;
};

struct xua_msg *m3ua_encode_notify(const struct m3ua_notify_params *npar);
int m3ua_decode_notify(struct m3ua_notify_params *npar, void *ctx,
			const struct xua_msg *xua);
