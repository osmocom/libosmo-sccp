#pragma once

/* Internal header used by libosmo-sccp, not available publicly for lib users */

#include <stdbool.h>
#include <osmocom/sigtran/osmo_ss7.h>

bool osmo_ss7_asp_set_default_peer_hosts(struct osmo_ss7_asp *asp);
bool osmo_ss7_xua_server_set_default_local_hosts(struct osmo_xua_server *oxs);

enum ss7_as_ctr {
	SS7_AS_CTR_RX_MSU_TOTAL,
	SS7_AS_CTR_TX_MSU_TOTAL,
};
