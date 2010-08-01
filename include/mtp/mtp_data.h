/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#ifndef mtp_data_h
#define mtp_data_h

#include <osmocore/msgb.h>
#include <osmocore/timer.h>
#include <osmocore/utils.h>

/* MTP Level3 timers */

/* Timers for SS7 */
#define MTP_T1		12, 0
#define MTP_T2		30, 0
#define START_DELAY	 8, 0

/**
 * The state of the mtp_link in terms of layer3 and upwards
 */
struct mtp_link {
	/* routing info.. */
	int dpc, opc;

	/* internal state */
	/* the MTP1 link is up */
	int available;
	int running;
	int sccp_up;

	/* misc data */
	uint8_t test_ptrn[14];

	int sltm_pending;
	struct llist_head pending_msgs;
	int sltm_once;
	int was_up;


	/* the associated link */
	int link;

	int slta_misses;
	struct timer_list t1_timer;
	struct timer_list t2_timer;

	struct timer_list delay_timer;
};


struct mtp_link *mtp_link_alloc(void);
void mtp_link_stop(struct mtp_link *link);
void mtp_link_reset(struct mtp_link *link);
int mtp_link_data(struct mtp_link *link, struct msgb *msg);
int mtp_link_submit_sccp_data(struct mtp_link *link, int sls, const uint8_t *data, unsigned int length);


/* one time init function */
void mtp_link_init(void);

/* to be implemented for MSU sending */
void mtp_link_submit(struct mtp_link *link, struct msgb *msg);
void mtp_link_forward_sccp(struct mtp_link *link, struct msgb *msg, int sls);
void mtp_link_restart(struct mtp_link *link);
void mtp_link_slta_recv(struct mtp_link *link);
void mtp_link_sccp_down(struct mtp_link *link);

#endif
