#pragma once

/* Internal header used by libosmo-sccp, not available publicly for lib users */

#include <stdbool.h>
#include <osmocom/sigtran/osmo_ss7.h>

extern bool ss7_initialized;

bool ss7_ipv6_sctp_supported(const char *host, bool bind);

struct osmo_ss7_asp *ss7_asp_alloc(struct osmo_ss7_instance *inst, const char *name,
				   uint16_t remote_port, uint16_t local_port,
				   enum osmo_ss7_asp_protocol proto);
bool ss7_asp_set_default_peer_hosts(struct osmo_ss7_asp *asp);
struct osmo_ss7_asp *ss7_asp_find_by_socket_addr(int fd);
int ss7_asp_proto_to_ip_proto(enum osmo_ss7_asp_protocol proto);
int ss7_asp_ipa_srv_conn_cb(struct osmo_stream_srv *conn);
int ss7_asp_xua_srv_conn_cb(struct osmo_stream_srv *conn);
int ss7_asp_xua_srv_conn_closed_cb(struct osmo_stream_srv *srv);
int ss7_asp_apply_peer_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_primary_address(const struct osmo_ss7_asp *asp);

bool ss7_asp_peer_match_host(const struct osmo_ss7_asp_peer *peer, const char *host, bool host_is_v6);

bool ss7_xua_server_set_default_local_hosts(struct osmo_xua_server *oxs);

enum ss7_as_ctr {
	SS7_AS_CTR_RX_MSU_TOTAL,
	SS7_AS_CTR_TX_MSU_TOTAL,
};

enum ss7_asp_ctr {
	SS7_ASP_CTR_PKT_RX_TOTAL,
	SS7_ASP_CTR_PKT_RX_UNKNOWN,
	SS7_ASP_CTR_PKT_TX_TOTAL,
};
