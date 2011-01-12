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

#include <m2ua/m2ua_msg.h>

#include <osmocore/utils.h>
#include <osmocore/msgb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(msg) \
	do { \
		fprintf(stderr, "FAILURE: %s on line %d\n", msg, __LINE__); \
		abort(); \
	} while(0);

static uint8_t asp_up[] = {
	0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x10,
	0x00, 0x11, 0x00, 0x08, 0xac, 0x10, 0x01, 0x51,
};

int main(int argc, char **argv)
{
	struct m2ua_msg *m2u = m2ua_from_msg(ARRAY_SIZE(asp_up), asp_up);
	struct msgb *msg = m2ua_to_msg(m2u);

	if (msg->len != ARRAY_SIZE(asp_up)) {
		printf("Got %d wanted %d\n", msg->len, ARRAY_SIZE(asp_up));
		FAIL("Wrong size");
	}

	if (memcmp(msg->data, asp_up, msg->len) != 0) {
		printf("Got '%s'\n", hexdump(msg->data, msg->len));
		FAIL("Wrong memory");
	}

	return 0;
}
