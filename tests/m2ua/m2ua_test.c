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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

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

static uint8_t data[] = {
	0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x2c,
	0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x1a, 0x81, 0x5c, 0x00, 0x07,
	0x00, 0x11, 0xf0, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0x00, 0x00
};

static void test_asp_up(void)
{
	struct m2ua_msg_part *part;
	struct m2ua_msg *m2u = m2ua_from_msg(ARRAY_SIZE(asp_up), asp_up);
	struct msgb *msg = m2ua_to_msg(m2u);
	const uint8_t res[] = { 0xac, 0x10, 0x01, 0x51 };

	printf("Testing ASP UP parsing.\n");

	if (msg->len != ARRAY_SIZE(asp_up)) {
		printf("Got %d wanted %d\n", msg->len, ARRAY_SIZE(asp_up));
		FAIL("Wrong size");
	}

	if (memcmp(msg->data, asp_up, msg->len) != 0) {
		printf("Got '%s'\n", osmo_hexdump(msg->data, msg->len));
		FAIL("Wrong memory");
	}

	part = m2ua_msg_find_tag(m2u, 0x11);
	if (!part)
		FAIL("Could not find part");
	if (part->len != 4)
		FAIL("Part is not of length four\n");
	if (memcmp(part->dat, res, 4) != 0)
		FAIL("Wrong result for the tag\n");

	m2ua_msg_free(m2u);
	msgb_free(msg);
}

static void test_data(void)
{
	struct m2ua_msg_part *part;
	struct m2ua_msg *m2u = m2ua_from_msg(ARRAY_SIZE(data), data);
	struct msgb *msg = m2ua_to_msg(m2u);

	printf("Testing parsing of data.\n");

	if (msg->len != ARRAY_SIZE(data)) {
		printf("Got %d wanted %d\n", msg->len, ARRAY_SIZE(data));
		FAIL("Wrong size");
	}

	if (memcmp(msg->data, data, msg->len) != 0) {
		printf("Got '%s'\n", osmo_hexdump(msg->data, msg->len));
		FAIL("Wrong memory");
	}

	part = m2ua_msg_find_tag(m2u, 0x300);
	if (!part)
		FAIL("Could not find part");
	if (part->len != 22) {
		printf("Got the length %d\n", part->len);
		FAIL("Part is not of length 22\n");
	}

	m2ua_msg_free(m2u);
	msgb_free(msg);
}

int main(int argc, char **argv)
{
	test_asp_up();
	test_data();

	printf("All tests passed.\n");
	return 0;
}
