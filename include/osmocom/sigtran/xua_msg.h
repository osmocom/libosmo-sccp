/* Routines for generating and parsing messages */
/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#pragma once

#include "xua_types.h"

#include <osmocom/core/linuxlist.h>

#define XUA_HDR(class, type)	((struct xua_common_hdr) { .spare = 0, .msg_class = (class), .msg_type = (type) })

struct msgb;
struct osmo_sccp_addr;

struct xua_msg {
	struct xua_common_hdr hdr;

	struct llist_head headers;
};

struct xua_msg_part {
	struct llist_head entry;

	uint16_t tag;
	uint16_t len;
	uint8_t  *dat;

	/* TODO: keep small data in the struct for perf reasons */
};


extern int DXUA;

struct xua_msg *xua_msg_alloc(void);
void xua_msg_free(struct xua_msg *msg);

int xua_msg_add_data(struct xua_msg *msg, uint16_t tag, uint16_t len, uint8_t *dat);

struct xua_msg_part *xua_msg_find_tag(struct xua_msg *msg, uint16_t tag);

struct xua_msg *xua_from_msg(const int version, uint16_t len, uint8_t *data);
struct msgb *xua_to_msg(const int version, struct xua_msg *msg);

void xua_set_log_area(int log_area);

int msgb_t16l16vp_put(struct msgb *msg, uint16_t tag, uint16_t len, const uint8_t *data);
int msgb_t16l16vp_put_u32(struct msgb *msg, uint16_t tag, uint32_t val);
int xua_msg_add_u32(struct xua_msg *xua, uint16_t iei, uint32_t val);
uint32_t xua_msg_get_u32(struct xua_msg *xua, uint16_t iei);
int xua_msg_add_sccp_addr(struct xua_msg *xua, uint16_t iei, const struct osmo_sccp_addr *addr);
