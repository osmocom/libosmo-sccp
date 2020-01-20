
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include "internal.h"

unsigned int conn_id =1;

/* a simple SCCP User which refuses all connections and discards all
 * unitdata */
static int refuser_prim_cb(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *) oph;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_INFO, "refusing N-CONNECT.ind (local_ref=%u)\n",
		     scu_prim->u.connect.conn_id);
		osmo_sccp_tx_disconn(scu, scu_prim->u.connect.conn_id,
				     &scu_prim->u.connect.called_addr,
				     23);
		break;
	default:
		LOGP(DMAIN, LOGL_NOTICE, "Unknown primitive %s\n",
		     osmo_scu_prim_name(oph));
		break;
	}
	msgb_free(oph->msg);
	return 0;
}

/* a simple SCCP User which accepts all connections and echos back all
 * DATA + UNITDATA */
static int echo_prim_cb(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *) oph;
	const uint8_t *data = msgb_l2(oph->msg);
	unsigned int data_len = msgb_l2len(oph->msg);

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_INFO, "Accepting N-CONNECT.ind (local_ref=%u)\n",
		     scu_prim->u.connect.conn_id);
		osmo_sccp_tx_conn_resp(scu, scu_prim->u.connect.conn_id,
				     &scu_prim->u.connect.called_addr,
				     data, data_len);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_INFO, "Echoing N-DATA.ind (local_ref=%u)\n",
		    scu_prim->u.data.conn_id);
		osmo_sccp_tx_data(scu, scu_prim->u.data.conn_id,
				  data, data_len);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_INFO, "Echoing N-UNITDATA.ind\n");
		osmo_sccp_tx_unitdata(scu, &scu_prim->u.unitdata.called_addr,
				      &scu_prim->u.unitdata.calling_addr,
				      data, data_len);
		break;
	default:
		LOGP(DMAIN, LOGL_NOTICE, "Unknown primitive %s\n",
		     osmo_scu_prim_name(oph));
		break;
	}
	msgb_free(oph->msg);
	return 0;
}

/* a simple SCCP User which receives UNITDATA messages and connects back
 * to whoever sents UNITDATA and then echo's back all DATA */
static int callback_prim_cb(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *) oph;
	const uint8_t *data = msgb_l2(oph->msg);
	unsigned int data_len = msgb_l2len(oph->msg);

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_INFO, "N-UNITDATA.ind: Connecting back to sender\n");
		osmo_sccp_tx_conn_req(scu, conn_id++,
				     &scu_prim->u.unitdata.called_addr,
				     &scu_prim->u.unitdata.calling_addr,
				     data, data_len);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_INFO, "Echoing N-DATA.ind (local_ref=%u)\n",
		     scu_prim->u.data.conn_id);
		osmo_sccp_tx_data(scu, scu_prim->u.data.conn_id,
				  data, data_len);
		break;
	default:
		LOGP(DMAIN, LOGL_NOTICE, "Unknown primitive %s\n",
		     osmo_scu_prim_name(oph));
		break;
	}
	msgb_free(oph->msg);
	return 0;
}

int sccp_test_server_init(struct osmo_sccp_instance *sccp)
{
	osmo_sccp_user_bind(sccp, "refuser", &refuser_prim_cb, SSN_TEST_REFUSE);
	osmo_sccp_user_bind(sccp, "echo", &echo_prim_cb, SSN_TEST_ECHO);
	osmo_sccp_user_bind(sccp, "callback", &callback_prim_cb, SSN_TEST_CALLBACK);

	return 0;
}
