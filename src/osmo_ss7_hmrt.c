/***********************************************************************
 * MTP Level 3 - Signalling message handling (SMH) Figure 23/Q.704
 ***********************************************************************/

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_internal.h"

/* convert from M3UA message to MTP-TRANSFER.ind osmo_mtp_prim */
struct osmo_mtp_prim *m3ua_to_xfer_ind(struct xua_msg *xua)
{
	struct osmo_mtp_prim *prim;
	struct osmo_mtp_transfer_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	struct m3ua_data_hdr *data_hdr;
	struct msgb *upmsg = m3ua_msgb_alloc("M3UA MTP-TRANSFER.ind");

	if (data_ie->len < sizeof(*data_hdr)) {
		/* FIXME: ERROR message */
		msgb_free(upmsg);
		return NULL;
	}
	data_hdr = (struct m3ua_data_hdr *) data_ie->dat;

	/* fill primitive */
	prim = (struct osmo_mtp_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.transfer;
	osmo_prim_init(&prim->oph, MTP_SAP_USER,
			OSMO_MTP_PRIM_TRANSFER,
			PRIM_OP_INDICATION, upmsg);

	m3ua_dh_to_xfer_param(param, data_hdr);
	/* copy data */
	upmsg->l2h = msgb_put(upmsg, data_ie->len - sizeof(*data_hdr));
	memcpy(upmsg->l2h, data_ie->dat+sizeof(*data_hdr), data_ie->len - sizeof(*data_hdr));

	return prim;
}

/* convert from MTP-TRANSFER.req to osmo_mtp_prim */
static struct xua_msg *mtp_prim_to_m3ua(struct osmo_mtp_prim *prim)
{
	struct msgb *msg = prim->oph.msg;
	struct osmo_mtp_transfer_param *param = &prim->u.transfer;
	struct m3ua_data_hdr data_hdr;

	mtp_xfer_param_to_m3ua_dh(&data_hdr, param);

	return m3ua_xfer_from_data(&data_hdr, msgb_l2(msg), msgb_l2len(msg));
}

/* delivery given XUA message to given SS7 user */
static int deliver_to_mtp_user(const struct osmo_ss7_user *osu,
				struct xua_msg *xua)
{
	struct osmo_mtp_prim *prim;

	/* Create MTP-TRANSFER.ind and feed to user */
	prim = m3ua_to_xfer_ind(xua);
	if (!prim)
		return -1;
	prim->u.transfer = xua->mtp;

	return osu->prim_cb(&prim->oph, (void *) osu->priv);
}

/* HMDC -> HMDT: Message for distribution; Figure 25/Q.704 */
/* This means it is a message we received from remote/L2, and it is to
 * be routed to a local user part */
static int hmdt_message_for_distribution(struct osmo_ss7_instance *inst, struct xua_msg *xua)
{
	struct m3ua_data_hdr *mdh;
	const struct osmo_ss7_user *osu;
	uint32_t service_ind;

	switch (xua->hdr.msg_class) {
	case M3UA_MSGC_XFER:
		switch (xua->hdr.msg_type) {
		case M3UA_XFER_DATA:
			mdh = data_hdr_from_m3ua(xua);
			service_ind = mdh->si & 0xf;
			break;
		default:
			LOGP(DLSS7, LOGL_ERROR, "Unknown M3UA XFER Message "
				"Type %u\n", xua->hdr.msg_type);
			return -1;
		}
		break;
	case M3UA_MSGC_SNM:
		/* FIXME */
		/* FIXME: SI = Signalling Network Management -> SRM/SLM/STM */
		/* FIXME: SI = Signalling Network Testing and Maintenance -> SLTC */
	default:
		/* Discard Message */
		LOGP(DLSS7, LOGL_ERROR, "Unknown M3UA Message Class %u\n",
			xua->hdr.msg_class);
		return -1;
	}

	/* Check for local SSN registered for this DPC/SSN */
	osu = inst->user[service_ind];
	if (osu) {
		return deliver_to_mtp_user(osu, xua);
	} else {
		LOGP(DLSS7, LOGL_NOTICE, "No MTP-User for SI %u\n", service_ind);
		/* Discard Message */
		/* FIXME: User Part Unavailable HMDT -> HMRT */
		return -1;
	}
}

/* HMDC->HMRT Msg For Routing; Figure 26/Q.704 */
/* local message was receive d from L4, SRM, SLM, STM or SLTC, or
 * remote message received from L2 and HMDC determined msg for routing */
static int hmrt_message_for_routing(struct osmo_ss7_instance *inst,
				    struct xua_msg *xua)
{
	uint32_t dpc = xua->mtp.dpc;
	struct osmo_ss7_route *rt;

	/* find route for DPC */
	/* FIXME: unify with gen_mtp_transfer_req_xua() */
	rt = osmo_ss7_route_lookup(inst, dpc);
	if (rt) {
		/* FIXME: DPC SP restart? */
		/* FIXME: DPC Congested? */
		/* FIXME: Select link based on SLS */
		/* FIXME: Transmit over respective Link */
		if (rt->dest.as) {
			struct osmo_ss7_as *as = rt->dest.as;
			switch (as->cfg.proto) {
			case OSMO_SS7_ASP_PROT_M3UA:
				return m3ua_tx_xua_as(as,xua);
			case OSMO_SS7_ASP_PROT_IPA:
				return ipa_tx_xua_as(as, xua);
			default:
				LOGP(DLSS7, LOGL_ERROR, "MTP message "
					"for ASP of unknown protocol%u\n",
					as->cfg.proto);
				break;
			}
		} else if (rt->dest.linkset) {
			LOGP(DLSS7, LOGL_ERROR, "MTP-TRANSFER.req for linkset"
				"%s unsupported\n",rt->dest.linkset->cfg.name);
		} else
			OSMO_ASSERT(0);
	} else {
		LOGP(DLSS7, LOGL_ERROR, "MTP-TRANSFER.req for DPC %u: "
			"no route!\n", dpc);
		/* DPC unknown HMRT -> MGMT */
		/* Message Received for inaccesible SP HMRT ->RTPC */
		/* Discard Message */
	}
	return -1;
}

/* HMDC: Received Message L2 -> L3; Figure 24/Q.704 */
/* This means a message was received from L2 and we have to decide if it
 * is for the local stack (HMDT) or for routng (HMRT) */
int m3ua_hmdc_rx_from_l2(struct osmo_ss7_instance *inst, struct xua_msg *xua)
{
	uint32_t dpc = xua->mtp.dpc;
	if (osmo_ss7_pc_is_local(inst, dpc)) {
		return hmdt_message_for_distribution(inst, xua);
	} else {
		return hmrt_message_for_routing(inst, xua);
	}
}

/* MTP-User requests to send a MTP-TRANSFER.req via the stack */
int osmo_ss7_user_mtp_xfer_req(struct osmo_ss7_instance *inst,
				struct osmo_mtp_prim *omp)
{
	struct xua_msg *xua;
	int rc;

	OSMO_ASSERT(omp->oph.sap == MTP_SAP_USER);

	switch (OSMO_PRIM_HDR(&omp->oph)) {
	case OSMO_PRIM(OSMO_MTP_PRIM_TRANSFER, PRIM_OP_REQUEST):
		xua = mtp_prim_to_m3ua(omp);
		xua->mtp = omp->u.transfer;
		/* normally we would call hmrt_message_for_routing()
		 * here, if we were to follow the state diagrams of the
		 * ITU-T Q.70x specifications.  However, what if a local
		 * MTP user sends a MTP-TRANSFER.req to a local SSN?
		 * This wouldn't work as per the spec, but I believe it
		 * is a very useful feature (aka "loopback device" in
		 * IPv4). So we call m3ua_hmdc_rx_from_l2() just like
		 * the MTP-TRANSFER had been received from L2. */
		rc = m3ua_hmdc_rx_from_l2(inst, xua);
		xua_msg_free(xua);
		break;
	default:
		LOGP(DLSS7, LOGL_ERROR, "Ignoring unknown primitive %u:%u\n",
			omp->oph.primitive, omp->oph.operation);
		rc = -1;
	}

	msgb_free(omp->oph.msg);
	return rc;
}
