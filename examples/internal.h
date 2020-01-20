#pragma once

#define SSN_TEST_UNUSED		200
#define SSN_TEST_REFUSE		201
#define SSN_TEST_ECHO		202
#define SSN_TEST_CALLBACK	203

/* Debug Areas of the code */
enum {
	DMAIN
};

struct osmo_sccp_user;

int sccp_test_user_vty_install(struct osmo_sccp_instance *inst, int ssn);

int sccp_test_server_init(struct osmo_sccp_instance *sccp);
