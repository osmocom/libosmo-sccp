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


#ifndef m2ua_msg_h
#define m2ua_msg_h

#include "m2ua_types.h"

#include <osmocom/core/linuxlist.h>

struct msgb;

struct m2ua_msg {
	struct m2ua_common_hdr hdr;

	struct llist_head headers;
};

struct m2ua_msg_part {
	struct llist_head entry;

	uint16_t tag;
	uint16_t len;
	uint8_t  *dat;

	/* TODO: keep small data in the struct for perf reasons */
};


struct m2ua_msg *m2ua_msg_alloc(void);
void m2ua_msg_free(struct m2ua_msg *msg);

int m2ua_msg_add_data(struct m2ua_msg *msg, uint16_t tag, uint16_t len, uint8_t *dat);

struct m2ua_msg_part *m2ua_msg_find_tag(struct m2ua_msg *msg, uint16_t tag);

struct m2ua_msg *m2ua_from_msg(uint16_t len, uint8_t *data);
struct msgb *m2ua_to_msg(struct m2ua_msg *msg);

void m2ua_set_log_area(int log_area);

#endif
