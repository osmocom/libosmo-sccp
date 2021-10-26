/* Routines for generating and parsing messages */
/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#include "xua_types.h"

#include <osmocom/core/linuxlist.h>
#include <osmocom/sigtran/mtp_sap.h>

#define XUA_HDR(class, type)	((struct xua_common_hdr) { .spare = 0, .msg_class = (class), .msg_type = (type) })

struct msgb;
struct osmo_sccp_addr;
struct osmo_sccp_gt;

struct xua_msg {
	struct xua_common_hdr hdr;
	struct osmo_mtp_transfer_param mtp;

	struct llist_head headers;
};

struct xua_msg_part {
	struct llist_head entry;

	uint16_t tag;
	uint16_t len;
	uint8_t  *dat;

	/* TODO: keep small data in the struct for perf reasons */
};

struct xua_msg_class {
	const char *name;
	const struct value_string *msgt_names;
	const struct value_string *iei_names;
	const uint16_t *mand_ies[256];
};

struct xua_dialect {
	const char *name;
	uint16_t port;
	uint16_t ppid;
	int log_subsys;
	const struct xua_msg_class *class[256];
};

struct xua_msg_event_map {
	uint8_t msg_class;
	uint8_t msg_type;
	int event;
};

extern const struct xua_dialect xua_dialect_sua;
extern const struct xua_dialect xua_dialect_m3ua;

void osmo_xua_msg_tall_ctx_init(void *ctx);

struct xua_msg *xua_msg_alloc(void);
void xua_msg_free(struct xua_msg *msg);

int xua_msg_add_data(struct xua_msg *msg, uint16_t tag, uint16_t len, const uint8_t *dat);

struct xua_msg_part *xua_msg_find_tag(const struct xua_msg *msg, uint16_t tag);
int xua_msg_free_tag(struct xua_msg *xua, uint16_t tag);
int xua_msg_copy_part(struct xua_msg *xua_out, uint16_t tag_out,
		      const struct xua_msg *xua_in, uint16_t tag_in);

struct xua_msg *xua_from_msg(const int version, uint16_t len, uint8_t *data);
struct msgb *xua_to_msg(const int version, struct xua_msg *msg);

struct xua_msg *xua_from_nested(struct xua_msg_part *outer);

int msgb_t16l16vp_put(struct msgb *msg, uint16_t tag, uint16_t len, const uint8_t *data);
int msgb_t16l16vp_put_u32(struct msgb *msg, uint16_t tag, uint32_t val);
int xua_msg_add_u32(struct xua_msg *xua, uint16_t iei, uint32_t val);
uint32_t xua_msg_part_get_u32(const struct xua_msg_part *part);
uint32_t xua_msg_get_u32(const struct xua_msg *xua, uint16_t iei);
const uint32_t *xua_msg_get_u32p(const struct xua_msg *xua, uint16_t iei, uint32_t *out);
const char *xua_msg_part_get_str(const struct xua_msg_part *part);
const char *xua_msg_get_str(const struct xua_msg *xua, uint16_t iei);
int xua_msg_get_len(const struct xua_msg *xua, uint16_t iei);
void xua_part_add_gt(struct msgb *msg, const struct osmo_sccp_gt *gt);
int xua_msg_add_sccp_addr(struct xua_msg *xua, uint16_t iei, const struct osmo_sccp_addr *addr);

const char *xua_class_msg_name(const struct xua_msg_class *xmc, uint16_t msg_type);
const char *xua_class_iei_name(const struct xua_msg_class *xmc, uint16_t iei);
char *xua_hdr_dump(struct xua_msg *xua, const struct xua_dialect *dialect);
char *xua_msg_dump(struct xua_msg *xua, const struct xua_dialect *dialect);
int xua_dialect_check_all_mand_ies(const struct xua_dialect *dialect, struct xua_msg *xua);

int xua_msg_event_map(const struct xua_msg *xua,
		      const struct xua_msg_event_map *maps,
		      unsigned int num_maps);
