/*
 * SCCP management code
 *
 * (C) 2009, 2010, 2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009, 2010, 2013 by On-Waves
 *
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
 */

#ifndef SCCP_H
#define SCCP_H

#include <stdlib.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <osmocom/core/linuxlist.h>

#include "sccp_types.h"

struct msgb;
struct sccp_system;

enum {
	SCCP_CONNECTION_STATE_NONE,
	SCCP_CONNECTION_STATE_REQUEST,
	SCCP_CONNECTION_STATE_CONFIRM,
	SCCP_CONNECTION_STATE_ESTABLISHED,
	SCCP_CONNECTION_STATE_RELEASE,
	SCCP_CONNECTION_STATE_RELEASE_COMPLETE,
	SCCP_CONNECTION_STATE_REFUSED,
	SCCP_CONNECTION_STATE_SETUP_ERROR,
};

struct sockaddr_sccp {
	sa_family_t	sccp_family;		/* AF_SCCP in the future??? */
	uint8_t	sccp_ssn;		/* subssystem number for routing */

	/* TODO fill in address indicator... if that is ever needed */

	/* optional gti information */
	uint8_t *gti;
	int gti_len;

	/* any of SCCP_TITLE_IND_* */
	uint8_t gti_ind;

	int use_poi;
	uint8_t poi[2];

	/* not sure about these */
	/* uint8_t    sccp_class; */
};

/*
 * parsed structure of an address
 */
struct sccp_address {
	struct sccp_called_party_address    address;
	uint8_t			    ssn;
	uint8_t			    poi[2];

	uint8_t			    *gti_data;
	int			    gti_len;
};

struct sccp_optional_data {
	uint8_t			    data_len;
	uint8_t			    data_start;
};

struct sccp_connection {
	/* public */
	void *data_ctx;
	void (*data_cb)(struct sccp_connection *conn, struct msgb *msg, unsigned int len);

	void *state_ctx;
	void (*state_cb)(struct sccp_connection *, int old_state);

	struct sccp_source_reference source_local_reference;
	struct sccp_source_reference destination_local_reference;

	int connection_state;

	/* private */
	/* list of active connections */
	struct llist_head list;
	struct sccp_system *system;
	int incoming;
};

/**
 * system functionality to implement on top of any other transport layer:
 *   call sccp_system_incoming for incoming data (from the network)
 *   sccp will call outgoing whenever outgoing data exists
 *   The conn is NULL for UDT and other messages without a connection
 */
int sccp_system_init(void (*outgoing)(struct sccp_connection *conn, struct msgb *data, void *gctx, void *ctx), void *context);
int sccp_system_incoming_ctx(struct msgb *data, void *ctx);
int sccp_system_incoming(struct msgb *data);

/**
 * Send data on an existing connection
 */
int sccp_connection_write(struct sccp_connection *connection, struct msgb *data);
int sccp_connection_send_it(struct sccp_connection *connection);
int sccp_connection_close(struct sccp_connection *connection, int cause);
int sccp_connection_free(struct sccp_connection *connection);

/**
 * internal..
 */
int sccp_connection_force_free(struct sccp_connection *conn);

/**
 * Create a new socket. Set your callbacks and then call bind to open
 * the connection.
 */
struct sccp_connection *sccp_connection_socket(void);

/**
 * Open the connection and send additional data
 */
int sccp_connection_connect(struct sccp_connection *conn,
			    const struct sockaddr_sccp *sccp_called,
			    struct msgb *data);

/**
 * mostly for testing purposes only. Set the accept callback.
 * TODO: add true routing information... in analogy to socket, bind, accept
 */
int sccp_connection_set_incoming(const struct sockaddr_sccp *sock,
				 int (*accept_cb)(struct sccp_connection *connection, void *data),
				 void *user_data);

/**
 * Send data in terms of unit data. A fixed address indicator will be used.
 */
int sccp_write(struct msgb *data,
	       const struct sockaddr_sccp *sock_sender,
	       const struct sockaddr_sccp *sock_target,
	       int class, void *ctx);
int sccp_set_read(const struct sockaddr_sccp *sock,
		  int (*read_cb)(struct msgb *msgb, unsigned int, void *user_data),
		  void *user_data);

/* generic sock addresses */
extern const struct sockaddr_sccp sccp_ssn_bssap;

/* helpers */
uint32_t sccp_src_ref_to_int(struct sccp_source_reference *ref);
struct sccp_source_reference sccp_src_ref_from_int(uint32_t);

struct msgb *sccp_create_cr(const struct sccp_source_reference *src_ref, const struct sockaddr_sccp *called, const uint8_t *data, size_t length);
struct msgb *sccp_create_refuse(struct sccp_source_reference *src_ref, int cause, uint8_t *data, int length);
struct msgb *sccp_create_cc(struct sccp_source_reference *src_ref, struct sccp_source_reference *dst_ref);
struct msgb *sccp_create_rlsd(struct sccp_source_reference *src_ref, struct sccp_source_reference *dst_ref, int cause);
struct msgb *sccp_create_dt1(struct sccp_source_reference *dst_ref, uint8_t *data, uint8_t len);
struct msgb *sccp_create_udt(int _class, const struct sockaddr_sccp *sock_sender,
			     const struct sockaddr_sccp *sock_target, uint8_t *data, int len);

/**
 * Below this are helper functions and structs for parsing SCCP messages
 */
struct sccp_parse_result {
	struct sccp_address called;
	struct sccp_address calling;

	/* point to the msg packet */
	struct sccp_source_reference *source_local_reference;
	struct sccp_source_reference *destination_local_reference;

	/* data pointer */
	int data_len;
};

/*
 * helper functions for the nat code
 */
int sccp_determine_msg_type(struct msgb *msg);
int sccp_parse_header(struct msgb *msg, struct sccp_parse_result *result);

/*
 * osmocore logging features
 */
void sccp_set_log_area(int log_area);

#endif
