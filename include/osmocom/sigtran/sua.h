#pragma once

#include <stdint.h>
#include <osmocom/core/prim.h>

struct osmo_sccp_user;
struct osmo_sccp_link;

void osmo_sua_set_log_area(int area);

struct osmo_sccp_user *osmo_sua_user_create(void *ctx, osmo_prim_cb prim_cb,
					    void *priv);
void osmo_sua_user_destroy(struct osmo_sccp_user *user);

int osmo_sua_server_listen(struct osmo_sccp_user *user, const char *hostname, uint16_t port);

int osmo_sua_client_connect(struct osmo_sccp_user *user, const char *hostname, uint16_t port);
struct osmo_sccp_link *osmo_sua_client_get_link(struct osmo_sccp_user *user);

/* user hands us a SCCP-USER SAP primitive down into the stack */
int osmo_sua_user_link_down(struct osmo_sccp_link *link, struct osmo_prim_hdr *oph);

void *osmo_sccp_link_get_user_priv(struct osmo_sccp_link *slink);
