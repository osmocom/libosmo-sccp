/* implementation of IPA/SCCPlite transport */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

//#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/sigtran/xua_msg.h>

#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>
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

/* Patch a SCCP message and add point codes to Called/Calling Party (if missing) */
static struct msgb *patch_sccp_with_pc(struct osmo_ss7_asp *asp, struct msgb *sccp_msg_in,
					uint32_t opc, uint32_t dpc)
{
	struct osmo_sccp_addr addr;
	struct msgb *sccp_msg_out;
	struct xua_msg *sua;
	int rc;

	/* start by converting SCCP to SUA */
	sua = osmo_sccp_to_xua(sccp_msg_in);
	if (!sua) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Couldn't convert SCCP to SUA: %s\n",
			msgb_hexdump(sccp_msg_in));
		msgb_free(sccp_msg_in);
		return NULL;
	}
	/* free the input message and work with SUA version instead */
	msgb_free(sccp_msg_in);

	rc = sua_addr_parse(&addr, sua, SUA_IEI_DEST_ADDR);
	switch (rc) {
	case 0:
		if (addr.presence & OSMO_SCCP_ADDR_T_PC)
			break;
		/* if there's no point code in dest_addr, add one */
		addr.presence |= OSMO_SCCP_ADDR_T_PC;
		addr.pc = dpc;
		xua_msg_free_tag(sua, SUA_IEI_DEST_ADDR);
		xua_msg_add_sccp_addr(sua, SUA_IEI_DEST_ADDR, &addr);
		break;
	case -ENODEV: /* no destination address in message */
		break;
	default: /* some other error */
		xua_msg_free(sua);
		return NULL;
	}

	rc = sua_addr_parse(&addr, sua, SUA_IEI_SRC_ADDR);
	switch (rc) {
	case 0:
		if (addr.presence & OSMO_SCCP_ADDR_T_PC)
			break;
		/* if there's no point code in src_addr, add one */
		addr.presence |= OSMO_SCCP_ADDR_T_PC;
		addr.pc = opc;
		xua_msg_free_tag(sua, SUA_IEI_SRC_ADDR);
		xua_msg_add_sccp_addr(sua, SUA_IEI_SRC_ADDR, &addr);
		break;
	case -ENODEV: /* no source address in message */
		break;
	default: /* some other error */
		xua_msg_free(sua);
		return NULL;
	}

	/* re-encode SUA to SCCP and return */
	sccp_msg_out = osmo_sua_to_sccp(sua);
	xua_msg_free(sua);
	return sccp_msg_out;
}

static int ipa_rx_msg_sccp(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	int rc;
	struct m3ua_data_hdr data_hdr;
	struct xua_msg *xua;
	struct osmo_ss7_as *as = find_as_for_asp(asp);
	uint32_t opc, dpc;

	if (!as) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Rx message for IPA ASP without AS?!\n");
		msgb_free(msg);
		return -1;
	}

	/* pull the IPA header */
	msgb_pull_to_l2(msg);

	/* We have received an IPA-encapsulated SCCP message, without
	 * any MTP routing label.  Furthermore, the SCCP Called/Calling
	 * Party are SSN-only, with no GT or PC.  This means we have no
	 * real idea where it came from, nor where it goes to.  We could
	 * simply treat it as being for the local point code, but then
	 * this means that we would have to implement SCCP connection
	 * coupling in order to route the connections to any other point
	 * code.  The reason for this is the lack of addressing
	 * information inside the non-CR/CC connection oriented
	 * messages.
	 *
	 * The only other alternative we have is to simply have a
	 * STP (server) side configuration that specifies which point
	 * code those messages are to be routed to, and then use this
	 * 'override DPC' in the routing decision.  We could do the same
	 * for the source point code to ensure responses are routed back
	 * to us.  This is all quite ugly, but then what can we do :/
	 */

	/* First, determine the DPC and OPC to use */
	if (asp->cfg.is_server) {
		/* Source: the PC of the routing key */
		opc = as->cfg.routing_key.pc;
		/* Destination: Based on VTY config */
		dpc = as->cfg.pc_override.dpc;
	} else {
		/* Source: Based on VTY config */
		opc = as->cfg.pc_override.dpc;
		/* Destination: PC of the routing key */
		dpc = as->cfg.routing_key.pc;
	}

	/* Second, patch this into the SCCP message */
	msg = patch_sccp_with_pc(asp, msg, opc, dpc);

	/* Third, create a MTP3/M3UA label with those point codes */
	memset(&data_hdr, 0, sizeof(data_hdr));
	data_hdr.si = MTP_SI_SCCP;
	data_hdr.opc = osmo_htonl(opc);
	data_hdr.dpc = osmo_htonl(dpc);
	/* Create M3UA message in XUA structure */
	xua = m3ua_xfer_from_data(&data_hdr, msgb_l2(msg), msgb_l2len(msg));
	msgb_free(msg);
	/* Update xua->mtp with values from data_hdr */
	m3ua_dh_to_xfer_param(&xua->mtp, &data_hdr);

	/* Pass on as if we had received it from an M3UA ASP */
	rc = m3ua_hmdc_rx_from_l2(asp->inst, xua);
	xua_msg_free(xua);
	return rc;
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
		rc = ss7_asp_rx_unknown(asp, hh->proto, msg);
	}

	return rc;
}
