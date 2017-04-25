/* implementation of IPA/SCCPlite transport */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

//#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "xua_internal.h"
#include "xua_asp_fsm.h"


/*! \brief Send a given xUA message via a given IPA "Application Server"
 *  \param[in] as Application Server through which to send \a xua
 *  \param[in] xua xUA message to be sent
 *  \return 0 on success; negative on error */
int ipa_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct xua_msg_part *data_ie;
	struct msgb *msg;
	unsigned int src_len;
	const uint8_t *src;
	uint8_t *dst;

	OSMO_ASSERT(as->cfg.proto == OSMO_SS7_ASP_PROT_IPA);

	/* we're actually only interested in the data part */
	data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	if (!data_ie || data_ie->len < sizeof(struct m3ua_data_hdr))
		return -1;

	/* and even the data part still has the header prepended */
	src = data_ie->dat + sizeof(struct m3ua_data_hdr);
	src_len = data_ie->len - sizeof(struct m3ua_data_hdr);

	/* sufficient headroom for osmo_ipa_msg_push_header() */
	msg = ipa_msg_alloc(16);
	if (!msg)
		return -1;

	dst = msgb_put(msg, src_len);
	memcpy(dst, src, src_len);

	/* TODO: if we ever need something beyond SCCP, we can use the
	 * M3UA SIO to determine the protocol */
	osmo_ipa_msg_push_header(msg, IPAC_PROTO_SCCP);

	return xua_as_transmit_msg(as, msg);
}

static int ipa_rx_msg_ccm(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	uint8_t msg_type = msg->l2h[0];

	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s:%s\n", __func__, msgb_hexdump(msg));

	/* Convert CCM into events to the IPA_ASP_FSM */
	switch (msg_type) {
	case IPAC_MSGT_ID_ACK:
		osmo_fsm_inst_dispatch(asp->fi, IPA_ASP_E_ID_ACK, msg);
		break;
	case IPAC_MSGT_ID_RESP:
		osmo_fsm_inst_dispatch(asp->fi, IPA_ASP_E_ID_RESP, msg);
		break;
	case IPAC_MSGT_ID_GET:
		osmo_fsm_inst_dispatch(asp->fi, IPA_ASP_E_ID_GET, msg);
		break;
	case IPAC_MSGT_PING:
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_ASPSM_BEAT, msg);
		break;
	case IPAC_MSGT_PONG:
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_ASPSM_BEAT_ACK, msg);
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Unknown CCM Message 0x%02x: %s\n",
			msg_type, msgb_hexdump(msg));
		return -1;
	}

	msgb_free(msg);

	return 0;
}

static struct osmo_ss7_as *find_as_for_asp(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as;

	/* in the IPA case, weassume there is a 1:1 mapping between the
	 * ASP and the AS.  An AS without ASP means there is no
	 * connection, and an ASP without AS means that we don't (yet?)
	 * know the identity of the peer */

	llist_for_each_entry(as, &asp->inst->as_list, list) {
		if (osmo_ss7_as_has_asp(as, asp))
			return as;
	}
	return NULL;
}

static int ipa_rx_msg_sccp(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct m3ua_data_hdr data_hdr;
	struct xua_msg *xua = xua_msg_alloc();
	struct osmo_ss7_as *as = find_as_for_asp(asp);

	if (!as) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Rx message for IPA ASP without AS?!\n");
		msgb_free(msg);
		return -1;
	}

	/* pull the IPA header */
	msgb_pull_to_l2(msg);

	/* We have received an IPA-encapsulated SCCP message, without
	 * any MTP routing label.  This means we have no real idea where
	 * it came from, nor where it goes to.  We could simply treat it
	 * as being for the local point code, but then this means that
	 * we would have to implement SCCP connection coupling in order
	 * to route the connections to any other point code.  The reason
	 * for this is the lack of addressing information inside the
	 * non-CR/CC connection oriented messages.
	 *
	 * The only other alternative we have is to simply have a
	 * STP (server) side configuration that specifies which point
	 * code those messages are to be routed to, and then use this
	 * 'override DPC' in the routing decision.  We could do the same
	 * for the source point code to ensure responses are routed back
	 * to us.  This is all quite ugly, but then what can we do :/
	 */

	memset(&data_hdr, 0, sizeof(data_hdr));
	data_hdr.si = MTP_SI_SCCP;
	if (asp->cfg.is_server) {
		/* Source: the PC of the routing key */
		data_hdr.opc = as->cfg.routing_key.pc;
		/* Destination: Based on VTY config */
		data_hdr.dpc = as->cfg.pc_override.dpc;
	} else {
		/* Source: Based on VTY config */
		data_hdr.opc = as->cfg.pc_override.dpc;
		/* Destination: PC of the routing key */
		data_hdr.dpc = as->cfg.routing_key.pc;
	}
	xua = m3ua_xfer_from_data(&data_hdr, msgb_l2(msg), msgb_l2len(msg));

	return m3ua_hmdc_rx_from_l2(asp->inst, xua);
}

/*! \brief process M3UA message received from socket
 *  \param[in] asp Application Server Process receiving \a msg
 *  \param[in] msg received message buffer. Callee takes ownership!
 *  \returns 0 on success; negative on error */
int ipa_rx_msg(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct ipaccess_head *hh;
	int rc;

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA);

	/* osmo_ipa_process_msg() will already have verified length
	 * consistency and set up l2h poiter */
	hh = (struct ipaccess_head *) msg->l1h;

	switch (hh->proto) {
	case IPAC_PROTO_IPACCESS:
		rc = ipa_rx_msg_ccm(asp, msg);
		break;
	case IPAC_PROTO_SCCP:
		rc = ipa_rx_msg_sccp(asp, msg);
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_DEBUG, "Unknown Stream ID 0x%02x: %s\n",
			hh->proto, msgb_hexdump(msg));
		rc = -1;
	}

	return rc;
}
