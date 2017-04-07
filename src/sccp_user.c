/* SCCP User related routines */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * based on my 2011 Erlang implementation osmo_ss7/src/sua_sccp_conv.erl
 *
 * References: ITU-T Q.713 and IETF RFC 3868
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
 */

#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "sccp_internal.h"
#include "xua_internal.h"

/*! \brief Find a SCCP User registered for given PC+SSN or SSN only
 *  \param[in] inst SCCP Instance in which to search
 *  \param[in] ssn Sub-System Number to search for
 *  \param[in] pc Point Code to search for
 *  \returns Matching SCCP User; NULL if none found */
struct osmo_sccp_user *
sccp_user_find(struct osmo_sccp_instance *inst, uint16_t ssn, uint32_t pc)
{
	struct osmo_sccp_user *scu;

	/* First try to find match for PC + SSN */
	llist_for_each_entry(scu, &inst->users, list) {
		if (scu->pc_valid && scu->pc == pc && scu->ssn == ssn)
			return scu;
	}

	/* Then try to match on SSN only */
	llist_for_each_entry(scu, &inst->users, list) {
		if (!scu->pc_valid && scu->ssn == ssn)
			return scu;
	}

	return NULL;
}

/*! \brief Bind a SCCP User to a given Point Code
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] ssn Sub-System Number to bind to
 *  \param[in] pc Point Code to bind to (if any)
 *  \param[in] pc_valid Whether or not \ref pc is valid/used
 *  \returns Callee-allocated SCCP User on success; negative otherwise */
static struct osmo_sccp_user *
sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		  osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc, bool pc_valid)
{
	struct osmo_sccp_user *scu;
	if (!pc_valid)
		pc = 0;

	if (sccp_user_find(inst, ssn, pc))
		return NULL;

	LOGP(DLSCCP, LOGL_INFO, "Binding user '%s' to SSN=%u PC=%u (pc_valid=%u)\n",
		name, ssn, pc, pc_valid);

	scu = talloc_zero(inst, struct osmo_sccp_user);
	scu->name = talloc_strdup(scu, name);
	scu->inst = inst;
	scu->prim_cb = prim_cb;
	scu->ssn = ssn;
	scu->pc = pc;
	scu->pc_valid = pc_valid;
	llist_add_tail(&scu->list, &inst->users);

	return scu;
}

/*! \brief Bind a given SCCP User to a given SSN+PC
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] ssn Sub-System Number to bind to
 *  \param[in] pc Point Code to bind to (if any)
 *  \returns Callee-allocated SCCP User on success; negative otherwise */
struct osmo_sccp_user *
osmo_sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		       osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc)
{
	return sccp_user_bind_pc(inst, name, prim_cb, ssn, pc, true);
}

/*! \brief Bind a given SCCP User to a given SSN (at any PC)
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] ssn Sub-System Number to bind to
 *  \returns Callee-allocated SCCP User on success; negative otherwise */
struct osmo_sccp_user *
osmo_sccp_user_bind(struct osmo_sccp_instance *inst, const char *name,
		    osmo_prim_cb prim_cb, uint16_t ssn)
{
	return sccp_user_bind_pc(inst, name, prim_cb, ssn, 0, false);
}

/*! \brief Unbind a given SCCP user
 *  \param[in] scu SCCP User which is to be un-bound. Will be destroyed
 *  		at the time this function returns. */
void osmo_sccp_user_unbind(struct osmo_sccp_user *scu)
{
	LOGP(DLSCCP, LOGL_INFO, "Unbinding user '%s' from SSN=%u PC=%u "
		"(pc_valid=%u)\n", scu->name, scu->ssn, scu->pc,
		scu->pc_valid);
	/* FIXME: free/release all connections held by this user? */
	llist_del(&scu->list);
	talloc_free(scu);
}

void osmo_sccp_user_set_priv(struct osmo_sccp_user *scu, void *priv)
{
	scu->priv = priv;
}

void *osmo_sccp_user_get_priv(struct osmo_sccp_user *scu)
{
	return scu->priv;
}

/*! \brief Send a SCCP User SAP Primitive up to the User
 *  \param[in] scu SCCP User to whom to send the primitive
 *  \param[in] prim Primitive to send to the user
 *  \returns return value of the SCCP User's prim_cb() function */
int sccp_user_prim_up(struct osmo_sccp_user *scu, struct osmo_scu_prim *prim)
{
	LOGP(DLSCCP, LOGL_DEBUG, "Delivering %s to SCCP User '%s'\n",
		osmo_scu_prim_name(&prim->oph), scu->name);
	return scu->prim_cb(&prim->oph, scu);
}

/* prim_cb handed to MTP code for incoming MTP-TRANSFER.ind */
static int mtp_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_sccp_instance *inst = ctx;
	struct osmo_mtp_prim *omp = (struct osmo_mtp_prim *)oph;
	struct xua_msg *xua;
	int rc;

	OSMO_ASSERT(oph->sap == MTP_SAP_USER);

	switch OSMO_PRIM(oph->primitive, oph->operation) {
	case OSMO_PRIM(OSMO_MTP_PRIM_TRANSFER, PRIM_OP_INDICATION):
		/* Convert from SCCP to SUA in xua_msg format */
		xua = osmo_sccp_to_xua(oph->msg);
		xua->mtp = omp->u.transfer;
		/* hand this primitive into SCCP via the SCRC code */
		rc = scrc_rx_mtp_xfer_ind_xua(inst, xua);
	default:
		LOGP(DLSCCP, LOGL_ERROR, "Unknown primitive %u:%u receivd\n",
			oph->primitive, oph->operation);
		rc = -1;
	}
	msgb_free(oph->msg);
	return rc;
}

static LLIST_HEAD(sccp_instances);

/*! \brief create a SCCP Instance and register it as user with SS7 inst
 *  \param[in] ss7 SS7 instance to which this SCCP instance belongs
 *  \param[in] priv private data to be stored within SCCP instance
 *  \returns callee-allocated SCCP instance on success; NULL on error */
struct osmo_sccp_instance *
osmo_sccp_instance_create(struct osmo_ss7_instance *ss7, void *priv)
{
	struct osmo_sccp_instance *inst;

	inst = talloc_zero(ss7, struct osmo_sccp_instance);
	if (!inst)
		return NULL;

	inst->ss7 = ss7;
	inst->priv = priv;
	INIT_LLIST_HEAD(&inst->connections);
	INIT_LLIST_HEAD(&inst->users);

	inst->ss7_user.inst = ss7;
	inst->ss7_user.name = "SCCP";
	inst->ss7_user.prim_cb = mtp_user_prim_cb;
	inst->ss7_user.priv = inst;

	osmo_ss7_user_register(ss7, MTP_SI_SCCP, &inst->ss7_user);

	llist_add_tail(&inst->list, &sccp_instances);

	return inst;
}

void osmo_sccp_instance_destroy(struct osmo_sccp_instance *inst)
{
	struct osmo_sccp_user *scu, *scu2;

	inst->ss7->sccp = NULL;
	osmo_ss7_user_unregister(inst->ss7, MTP_SI_SCCP, &inst->ss7_user);

	llist_for_each_entry_safe(scu, scu2, &inst->users, list) {
		osmo_sccp_user_unbind(scu);
	}
	sccp_scoc_flush_connections(inst);
	llist_del(&inst->list);
	talloc_free(inst);
}

/***********************************************************************
 * Convenience function for CLIENT
 ***********************************************************************/

struct osmo_sccp_instance *
osmo_sccp_simple_client(void *ctx, const char *name, uint32_t pc,
			enum osmo_ss7_asp_protocol prot,
			int local_port, int remote_port, const char *remote_ip)
{
	struct osmo_ss7_instance *ss7;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route *rt;
	struct osmo_ss7_asp *asp;
	char *as_name, *asp_name;

	if (!remote_port || remote_port < 0)
		remote_port = osmo_ss7_asp_protocol_port(prot);
	if (local_port < 0)
		local_port = osmo_ss7_asp_protocol_port(prot);

	/* allocate + initialize SS7 instance */
	ss7 = osmo_ss7_instance_find_or_create(ctx, 1);
	if (!ss7)
		return NULL;
	ss7->cfg.primary_pc = pc;

	as_name = talloc_asprintf(ctx, "as-clnt-%s", name);
	asp_name = talloc_asprintf(ctx, "asp-clnt-%s", name);

	/* application server */
	as = osmo_ss7_as_find_or_create(ss7, as_name, prot);
	if (!as)
		goto out_strings;

	/* install default route */
	rt = osmo_ss7_route_create(ss7->rtable_system, 0, 0, as_name);
	if (!rt)
		goto out_as;
	talloc_free(as_name);

	/* application server process */
	asp = osmo_ss7_asp_find_or_create(ss7, asp_name, remote_port, local_port,
					  prot);
	if (!asp)
		goto out_rt;
	asp->cfg.remote.host = talloc_strdup(asp, remote_ip);
	osmo_ss7_as_add_asp(as, asp_name);
	talloc_free(asp_name);
	osmo_ss7_asp_restart(asp);

	/* Allocate SCCP stack + SCCP user */
	ss7->sccp = osmo_sccp_instance_create(ss7, NULL);
	if (!ss7->sccp)
		goto out_asp;

	return ss7->sccp;

out_asp:
	osmo_ss7_asp_destroy(asp);
out_rt:
	osmo_ss7_route_destroy(rt);
out_as:
	osmo_ss7_as_destroy(as);
out_strings:
	talloc_free(as_name);
	talloc_free(asp_name);
	osmo_ss7_instance_destroy(ss7);

	return NULL;
}

/***********************************************************************
 * Convenience function for SERVER
 ***********************************************************************/

struct osmo_sccp_instance *
osmo_sccp_simple_server(void *ctx, uint32_t pc,
			enum osmo_ss7_asp_protocol prot, int local_port,
			const char *local_ip)
{
	struct osmo_ss7_instance *ss7;
	struct osmo_xua_server *xs;

	if (local_port < 0)
		local_port = osmo_ss7_asp_protocol_port(prot);

	/* allocate + initialize SS7 instance */
	ss7 = osmo_ss7_instance_find_or_create(ctx, 1);
	if (!ss7)
		return NULL;
	ss7->cfg.primary_pc = pc;

	xs = osmo_ss7_xua_server_create(ss7, prot, local_port, local_ip);
	if (!xs)
		goto out_ss7;

	/* Allocate SCCP stack */
	ss7->sccp = osmo_sccp_instance_create(ss7, NULL);
	if (!ss7->sccp)
		goto out_xs;

	return ss7->sccp;

out_xs:
	osmo_ss7_xua_server_destroy(xs);
out_ss7:
	osmo_ss7_instance_destroy(ss7);

	return NULL;
}

struct osmo_sccp_instance *
osmo_sccp_simple_server_add_clnt(struct osmo_sccp_instance *inst,
				 enum osmo_ss7_asp_protocol prot,
				 const char *name, uint32_t pc,
				 int local_port, int remote_port,
				 const char *remote_ip)
{
	struct osmo_ss7_instance *ss7 = inst->ss7;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route *rt;
	struct osmo_ss7_asp *asp;
	char *as_name, *asp_name;

	if (local_port < 0)
		local_port = osmo_ss7_asp_protocol_port(prot);

	if (remote_port < 0)
		remote_port = osmo_ss7_asp_protocol_port(prot);

	as_name = talloc_asprintf(ss7, "as-srv-%s", name);
	asp_name = talloc_asprintf(ss7, "asp-srv-%s", name);

	/* application server */
	as = osmo_ss7_as_find_or_create(ss7, as_name, prot);
	if (!as)
		goto out_strings;
	talloc_free(as_name);

	/* route only selected PC to the client */
	rt = osmo_ss7_route_create(ss7->rtable_system, pc, 0xffff, as_name);
	if (!rt)
		goto out_as;

	asp = osmo_ss7_asp_find_or_create(ss7, asp_name, remote_port, local_port, prot);
	if (!asp)
		goto out_rt;
	asp->cfg.is_server = true;
	osmo_ss7_as_add_asp(as, asp_name);
	talloc_free(asp_name);
	osmo_ss7_asp_restart(asp);

	return ss7->sccp;

out_rt:
	osmo_ss7_route_destroy(rt);
out_as:
	osmo_ss7_as_destroy(as);
out_strings:
	talloc_free(as_name);
	talloc_free(asp_name);

	return NULL;
}

struct osmo_ss7_instance *osmo_sccp_get_ss7(struct osmo_sccp_instance *sccp)
{
	return sccp->ss7;
}
