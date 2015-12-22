#pragma once

#include <stdint.h>
#include <osmocom/core/prim.h>

struct osmo_sua_user;
struct osmo_sua_link;

void osmo_sua_set_log_area(int area);

struct osmo_sua_user *osmo_sua_user_create(void *ctx, osmo_prim_cb prim_cb);
void osmo_sua_user_destroy(struct osmo_sua_user *user);

int osmo_sua_server_listen(struct osmo_sua_user *user, const char *hostname, uint16_t port);

int osmo_sua_client_connect(struct osmo_sua_user *user, const char *hostname, uint16_t port);
struct osmo_sua_link *osmo_sua_client_get_link(struct osmo_sua_user *user);

/* user hands us a SCCP-USER SAP primitive down into the stack */
int osmo_sua_user_link_down(struct osmo_sua_link *link, struct osmo_prim_hdr *oph);

