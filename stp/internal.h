#pragma once

#include <osmocom/vty/command.h>

enum stp_vty_node {
	L_CS7_NODE = _LAST_OSMOVTY_NODE + 1,
	L_CS7_AS_NODE,
	L_CS7_ASP_NODE,
	L_CS7_SUA_NODE,
	L_CS7_M3UA_NODE,
	L_CS7_RTABLE_NODE,
};

void osmo_ss7_set_vty_alloc_ctx(void *ctx);
void osmo_ss7_vty_init_asp(void);
void osmo_ss7_vty_init_sg(void);
int osmo_ss7_vty_go_parent(struct vty *vty);
int osmo_ss7_is_config_node(struct vty *vty, int node);
