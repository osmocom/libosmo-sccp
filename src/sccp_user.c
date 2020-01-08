/* SCCP User related routines */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
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
#include <string.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/sccp_helpers.h>

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
		if (osmo_ss7_pc_is_valid(scu->pc) && scu->pc == pc && scu->ssn == ssn)
			return scu;
	}

	/* Then try to match on SSN only */
	llist_for_each_entry(scu, &inst->users, list) {
		if (!osmo_ss7_pc_is_valid(scu->pc) && scu->ssn == ssn)
			return scu;
	}

	return NULL;
}

/*! \brief Bind a SCCP User to a given Point Code
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] ssn Sub-System Number to bind to
 *  \param[in] pc Point Code to bind to, or OSMO_SS7_PC_INVALID if none.
 *  \returns Callee-allocated SCCP User on success; negative otherwise */
static struct osmo_sccp_user *
sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		  osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc)
{
	struct osmo_sccp_user *scu;

	scu = sccp_user_find(inst, ssn, pc);
	if (scu) {
		LOGP(DLSCCP, LOGL_ERROR,
		     "Cannot bind user '%s' to SSN=%u PC=%s, this SSN and PC"
		     " is already bound by '%s'\n",
		     name, ssn, osmo_ss7_pointcode_print(inst->ss7, pc), scu->name);
		return NULL;
	}

	LOGP(DLSCCP, LOGL_INFO, "Binding user '%s' to SSN=%u PC=%s\n",
		name, ssn, osmo_ss7_pointcode_print(inst->ss7, pc));

	scu = talloc_zero(inst, struct osmo_sccp_user);
	scu->name = talloc_strdup(scu, name);
	scu->inst = inst;
	scu->prim_cb = prim_cb;
	scu->ssn = ssn;
	scu->pc = pc;
	llist_add_tail(&scu->list, &inst->users);

	return scu;
}

/*! \brief Bind a given SCCP User to a given SSN+PC
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] ssn Sub-System Number to bind to
 *  \param[in] pc Point Code to bind to
 *  \returns Callee-allocated SCCP User on success; negative otherwise */
struct osmo_sccp_user *
osmo_sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		       osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc)
{
	return sccp_user_bind_pc(inst, name, prim_cb, ssn, pc);
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
	return sccp_user_bind_pc(inst, name, prim_cb, ssn, OSMO_SS7_PC_INVALID);
}

/*! \brief Unbind a given SCCP user
 *  \param[in] scu SCCP User which is to be un-bound. Will be destroyed
 *  		at the time this function returns. */
void osmo_sccp_user_unbind(struct osmo_sccp_user *scu)
{
	LOGP(DLSCCP, LOGL_INFO, "Unbinding user '%s' from SSN=%u PC=%s\n",
		scu->name, scu->ssn,
		osmo_ss7_pointcode_print(scu->inst->ss7, scu->pc));
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
		break;
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

/*! \brief derive a basic local SCCP-Address from a given SCCP instance.
 *  \param[out] dest_addr pointer to output address memory
 *  \param[in] inst SCCP instance
 *  \param[in] ssn Subsystem Number */
void osmo_sccp_local_addr_by_instance(struct osmo_sccp_addr *dest_addr,
				      const struct osmo_sccp_instance *inst,
				      uint32_t ssn)
{
	struct osmo_ss7_instance *ss7;

	OSMO_ASSERT(dest_addr);
	OSMO_ASSERT(inst);
	ss7 = inst->ss7;
	OSMO_ASSERT(ss7);

	*dest_addr = (struct osmo_sccp_addr){};

	osmo_sccp_make_addr_pc_ssn(dest_addr, ss7->cfg.primary_pc, ssn);
}

/*! \brief check whether a given SCCP-Address is consistent.
 *  \param[in] addr SCCP address to check
 *  \param[in] presence mask with minimum required address components
 *  \returns true when address data seems plausible */
bool osmo_sccp_check_addr(struct osmo_sccp_addr *addr, uint32_t presence)
{
	/* Minimum requirements do not match */
	if ((addr->presence & presence) != presence)
		return false;

	/* GT ranges */
	if (addr->presence & OSMO_SCCP_ADDR_T_GT) {
		if (addr->gt.gti > 15)
			return false;
		if (addr->gt.npi > 15)
			return false;
		if (addr->gt.nai > 127)
			return false;
	}

	/* Routing by GT, but no GT present */
	if (addr->ri == OSMO_SCCP_RI_GT
	    && !(addr->presence & OSMO_SCCP_ADDR_T_GT))
		return false;

	/* Routing by PC/SSN, but no PC/SSN present */
	if (addr->ri == OSMO_SCCP_RI_SSN_PC) {
		if ((addr->presence & OSMO_SCCP_ADDR_T_PC) == 0)
			return false;
		if ((addr->presence & OSMO_SCCP_ADDR_T_SSN) == 0)
			return false;
	}

	if (addr->ri == OSMO_SCCP_RI_SSN_IP) {
		if ((addr->presence & OSMO_SCCP_ADDR_T_IPv4) == 0 &&
		    (addr->presence & OSMO_SCCP_ADDR_T_IPv6) == 0)
			return false;
	}

	return true;
}

/*! Compare two SCCP Global Titles.
 * \param[in] a  left side.
 * \param[in] b  right side.
 * \return -1 if a < b, 1 if a > b, and 0 if a == b.
 */
int osmo_sccp_gt_cmp(const struct osmo_sccp_gt *a, const struct osmo_sccp_gt *b)
{
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	return memcmp(a, b, sizeof(*a));
}

/*! Compare two SCCP addresses by given presence criteria.
 * Any OSMO_SCCP_ADDR_T_* type not set in presence_criteria is ignored.
 * In case all bits are set in presence_criteria, the comparison is in the order of:
 * OSMO_SCCP_ADDR_T_GT, OSMO_SCCP_ADDR_T_PC, OSMO_SCCP_ADDR_T_IPv4, OSMO_SCCP_ADDR_T_IPv6, OSMO_SCCP_ADDR_T_SSN.
 * The SCCP addresses' Routing Indicator is not compared, see osmo_sccp_addr_ri_cmp().
 * \param[in] a  left side.
 * \param[in] b  right side.
 * \param[in] presence_criteria  A bitmask of OSMO_SCCP_ADDR_T_* values, or 0xffffffff to compare all parts, except the
 *                               routing indicator.
 * \return -1 if a < b, 1 if a > b, and 0 if all checked values match.
 */
int osmo_sccp_addr_cmp(const struct osmo_sccp_addr *a, const struct osmo_sccp_addr *b, uint32_t presence_criteria)
{
	int rc;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	if (presence_criteria & OSMO_SCCP_ADDR_T_GT) {
		if ((a->presence & OSMO_SCCP_ADDR_T_GT) != (b->presence & OSMO_SCCP_ADDR_T_GT))
			return (b->presence & OSMO_SCCP_ADDR_T_GT) ? -1 : 1;
		rc = osmo_sccp_gt_cmp(&a->gt, &b->gt);
		if (rc)
			return rc;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_PC) {
		if ((a->presence & OSMO_SCCP_ADDR_T_PC) != (b->presence & OSMO_SCCP_ADDR_T_PC))
			return (b->presence & OSMO_SCCP_ADDR_T_PC) ? -1 : 1;

		if ((a->presence & OSMO_SCCP_ADDR_T_PC)
		    && a->pc != b->pc)
			return (a->pc < b->pc)? -1 : 1;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_IPv4) {
		if ((a->presence & OSMO_SCCP_ADDR_T_IPv4) != (b->presence & OSMO_SCCP_ADDR_T_IPv4))
			return (b->presence & OSMO_SCCP_ADDR_T_IPv4) ? -1 : 1;
		rc = memcmp(&a->ip.v4, &b->ip.v4, sizeof(a->ip.v4));
		if (rc)
			return rc;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_IPv6) {
		if ((a->presence & OSMO_SCCP_ADDR_T_IPv6) != (b->presence & OSMO_SCCP_ADDR_T_IPv6))
			return (b->presence & OSMO_SCCP_ADDR_T_IPv6) ? -1 : 1;
		rc = memcmp(&a->ip.v6, &b->ip.v6, sizeof(a->ip.v6));
		if (rc)
			return rc;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_SSN) {
		if ((a->presence & OSMO_SCCP_ADDR_T_SSN) != (b->presence & OSMO_SCCP_ADDR_T_SSN))
			return (b->presence & OSMO_SCCP_ADDR_T_SSN) ? -1 : 1;
		if (a->ssn != b->ssn)
			return (a->ssn < b->ssn) ? -1 : 1;
	}

	return 0;
}

/*! Compare the routing information of two SCCP addresses.
 * Compare the ri of a and b, and, if equal, return osmo_sccp_addr_cmp() with presence criteria selected according to
 * ri.
 * \param[in] a  left side.
 * \param[in] b  right side.
 * \return -1 if a < b, 1 if a > b, and 0 if a == b.
 */
int osmo_sccp_addr_ri_cmp(const struct osmo_sccp_addr *a, const struct osmo_sccp_addr *b)
{
	uint32_t presence_criteria;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	if (a->ri != b->ri)
		return (a->ri < b->ri) ? -1 : 1;
	switch (a->ri) {
	case OSMO_SCCP_RI_NONE:
		return 0;
	case OSMO_SCCP_RI_GT:
		presence_criteria = OSMO_SCCP_ADDR_T_GT;
		break;
	case OSMO_SCCP_RI_SSN_PC:
		presence_criteria = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
		break;
	case OSMO_SCCP_RI_SSN_IP:
		/* Pick IPv4 or v6 depending on what a->presence indicates. */
		presence_criteria = OSMO_SCCP_ADDR_T_SSN | (a->presence & (OSMO_SCCP_ADDR_T_IPv4 | OSMO_SCCP_ADDR_T_IPv6));
		break;
	default:
		return 0;
	}

	return osmo_sccp_addr_cmp(a, b, presence_criteria);
}

/*! Compose a human readable string to describe the SCCP user's connection.
 * The output follows ['<scu.name>':]<local-sccp-addr>, e.g.  "'OsmoHNBW':RI=SSN_PC,PC=0.23.5,SSN=RANAP",
 * or just "RI=SSN_PC,PC=0.23.5,SSN=RANAP" if no scu->name is set.
 * This calls osmo_sccp_addr_name(), which returns a static buffer; hence calling this function and
 * osmo_sccp_addr_name() in the same printf statement is likely to conflict. */
const char *osmo_sccp_user_name(struct osmo_sccp_user *scu)
{
	static char buf[128];
	struct osmo_sccp_addr sca;
	/* Interestingly enough, the osmo_sccp_user stores an SSN and PC, but not in an osmo_sccp_addr
	 * struct. To be able to use osmo_sccp_addr_name(), we need to first create an osmo_sccp_addr. */
	osmo_sccp_make_addr_pc_ssn(&sca, scu->pc, scu->ssn);
	snprintf(buf, sizeof(buf),
		 "%s%s%s",
		 scu->name && *scu->name ? scu->name : "",
		 scu->name && *scu->name ? ":" : "",
		 osmo_sccp_addr_name(scu->inst->ss7, &sca));
	buf[sizeof(buf)-1] = '\0';
	return buf;
}

/***********************************************************************
 * Convenience function for CLIENT
 ***********************************************************************/

/*! \brief request an sccp client instance
 *  \param[in] ctx talloc context
 *  \param[in] ss7_id of the SS7/CS7 instance
 *  \param[in] name human readable name
 *  \param[in] default_pc pointcode to be used on missing VTY setting
 *  \param[in] prot protocol to be used (e.g OSMO_SS7_ASP_PROT_M3UA)
 *  \param[in] default_local_port local port to be usd on missing VTY setting
 *  \param[in] default_local_ip local IP-address to be usd on missing VTY setting
 *  \param[in] default_remote_port remote port to be usd on missing VTY setting
 *  \param[in] default_remote_ip remote IP-address to be usd on missing VTY setting
 *  \returns callee-allocated SCCP instance on success; NULL on error */

struct osmo_sccp_instance *
osmo_sccp_simple_client_on_ss7_id(void *ctx, uint32_t ss7_id, const char *name,
				  uint32_t default_pc,
				  enum osmo_ss7_asp_protocol prot,
				  int default_local_port,
				  const char *default_local_ip,
				  int default_remote_port,
				  const char *default_remote_ip)
{
	struct osmo_ss7_instance *ss7;
	bool ss7_created = false;
	struct osmo_ss7_as *as;
	bool as_created = false;
	struct osmo_ss7_route *rt;
	bool rt_created = false;
	struct osmo_ss7_asp *asp;
	bool asp_created = false;
	char *as_name, *asp_name = NULL;

	/*! The function will examine the given CS7 instance and its sub
	 *  components (as, asp, etc.). If necessary it will allocate
	 *  the missing components. If no CS7 instance can be detected
	 *  under the caller supplied ID, a new instance will be created
	 *  beforehand. */

	/* Choose default ports when the caller does not supply valid port
	 * numbers. */
	if (!default_remote_port || default_remote_port < 0)
		default_remote_port = osmo_ss7_asp_protocol_port(prot);
	if (default_local_port < 0)
		default_local_port = osmo_ss7_asp_protocol_port(prot);

	/* Check if there is already an ss7 instance present under
	 * the given id. If not, we will create a new one. */
	ss7 = osmo_ss7_instance_find(ss7_id);
	if (!ss7) {
		LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating SS7 instance\n",
		     name);

		/* Create a new ss7 instance */
		ss7 = osmo_ss7_instance_find_or_create(ctx, ss7_id);
		if (!ss7) {
			LOGP(DLSCCP, LOGL_ERROR,
			     "Failed to find or create SS7 instance\n");
			return NULL;
		}

		/* Setup primary pointcode
		 * NOTE: This means that the user must set the pointcode to a
		 * proper value when a cs7 instance is defined via the VTY. */
		ss7->cfg.primary_pc = default_pc;
		ss7_created = true;
	}

	/* In case no valid point-code has been configured via the VTY, we
	 * will fall back to the default pointcode. */
	if (!osmo_ss7_pc_is_valid(ss7->cfg.primary_pc)) {
		LOGP(DLSCCP, LOGL_ERROR,
		     "SS7 instance %u: no primary point-code set, using default point-code\n",
		     ss7->cfg.id);
		ss7->cfg.primary_pc = default_pc;
	}

	LOGP(DLSCCP, LOGL_NOTICE, "%s: Using SS7 instance %u, pc:%s\n", name,
	     ss7->cfg.id, osmo_ss7_pointcode_print(ss7, ss7->cfg.primary_pc));

	/* Check if there is already an application server that matches
	 * the protocol we intend to use. If not, we will create one. */
	as = osmo_ss7_as_find_by_proto(ss7, prot);
	if (!as) {
		LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating AS instance\n",
		     name);
		as_name = talloc_asprintf(ctx, "as-clnt-%s", name);
		as = osmo_ss7_as_find_or_create(ss7, as_name, prot);
		talloc_free(as_name);
		if (!as)
			goto out_ss7;
		as_created = true;
		as->cfg.routing_key.pc = ss7->cfg.primary_pc;
		as->simple_client_allocated = true;
	}
	LOGP(DLSCCP, LOGL_NOTICE, "%s: Using AS instance %s\n", name,
	     as->cfg.name);

	/* Create a default route if necessary */
	rt = osmo_ss7_route_find_dpc_mask(ss7->rtable_system, 0, 0);
	if (!rt) {
		LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating default route\n", name);
		rt = osmo_ss7_route_create(ss7->rtable_system, 0, 0,
					   as->cfg.name);
		if (!rt)
			goto out_as;
		rt_created = true;
	}

	/* Check if we do already have an application server process
	 * that is associated with the application server we have choosen
	 * the application server process must also match the protocol
	 * we intend to use. */
	asp = osmo_ss7_asp_find_by_proto(as, prot);
	if (!asp) {
		/* Check if the user has already created an ASP elsewhere under
		 * the default asp name. */
		asp_name = talloc_asprintf(ctx, "asp-clnt-%s", name);
		asp = osmo_ss7_asp_find_by_name(ss7, asp_name);
		if (!asp) {
			LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating ASP instance\n",
			     name);
			asp =
			    osmo_ss7_asp_find_or_create(ss7, asp_name,
							default_remote_port,
							default_local_port,
							prot);
			talloc_free(asp_name);
			if (!asp)
				goto out_rt;
			asp_created = true;

			asp->cfg.local.host[0] = NULL;
			asp->cfg.remote.host[0] = NULL;
			if (default_local_ip) {
				asp->cfg.local.host[0] =
				    talloc_strdup(asp, default_local_ip);
			}
			if (default_remote_ip) {
				asp->cfg.remote.host[0] =
				    talloc_strdup(asp, default_remote_ip);
			}
			asp->cfg.local.host_cnt = 1;
			asp->cfg.remote.host_cnt = 1;
			asp->simple_client_allocated = true;
		} else
			talloc_free(asp_name);

		osmo_ss7_as_add_asp(as, asp->cfg.name);
	}

	/* Ensure that the ASP we use is set to client mode. */
	asp->cfg.is_server = false;
	asp->cfg.role = OSMO_SS7_ASP_ROLE_ASP;

	/* Restart ASP */
	if (prot != OSMO_SS7_ASP_PROT_IPA)
		osmo_ss7_asp_use_default_lm(asp, LOGL_DEBUG);
	osmo_ss7_asp_restart(asp);
	LOGP(DLSCCP, LOGL_NOTICE, "%s: Using ASP instance %s\n", name,
	     asp->cfg.name);

	osmo_ss7_ensure_sccp(ss7);
	if (!ss7->sccp)
		goto out_asp;

	return ss7->sccp;

out_asp:
	if (asp_created)
		osmo_ss7_asp_destroy(asp);
out_rt:
	if (rt_created)
		osmo_ss7_route_destroy(rt);
out_as:
	if (as_created)
		osmo_ss7_as_destroy(as);
out_ss7:
	if (ss7_created)
		osmo_ss7_instance_destroy(ss7);

	return NULL;
}

/*! \brief request an sccp client instance
 *  \param[in] ctx talloc context
 *  \param[in] name human readable name
 *  \param[in] default_pc pointcode to be used on missing VTY setting
 *  \param[in] prot protocol to be used (e.g OSMO_SS7_ASP_PROT_M3UA)
 *  \param[in] default_local_port local port to be usd on missing VTY setting
 *  \param[in] default_local_ip local IP-address to be usd on missing VTY setting
 *  \param[in] default_remote_port remote port to be usd on missing VTY setting
 *  \param[in] default_remote_ip remote IP-address to be usd on missing VTY setting
 *  \returns callee-allocated SCCP instance on success; NULL on error */
struct osmo_sccp_instance *
osmo_sccp_simple_client(void *ctx, const char *name, uint32_t default_pc,
			enum osmo_ss7_asp_protocol prot, int default_local_port,
			const char *default_local_ip, int default_remote_port,
			const char *default_remote_ip)
{
	/*! This is simplified version of osmo_sccp_simple_client_on_ss7_id().
	 *  the only difference is that the ID of the CS7 instance will be
	 *  set to 0 statically */

	return osmo_sccp_simple_client_on_ss7_id(ctx, 0, name, default_pc, prot,
						 default_local_port,
						 default_local_ip,
						 default_remote_port,
						 default_remote_ip);
}

/***********************************************************************
 * Convenience function for SERVER
 ***********************************************************************/

struct osmo_sccp_instance *
osmo_sccp_simple_server_on_ss7_id(void *ctx, uint32_t ss7_id, uint32_t pc,
				  enum osmo_ss7_asp_protocol prot,
				  int local_port, const char *local_ip)
{
	struct osmo_ss7_instance *ss7;
	struct osmo_xua_server *xs;
	int rc;

	if (local_port < 0)
		local_port = osmo_ss7_asp_protocol_port(prot);

	/* allocate + initialize SS7 instance */
	ss7 = osmo_ss7_instance_find_or_create(ctx, ss7_id);
	if (!ss7)
		return NULL;
	ss7->cfg.primary_pc = pc;

	xs = osmo_ss7_xua_server_create(ss7, prot, local_port, local_ip);
	if (!xs)
		goto out_ss7;

	rc = osmo_ss7_xua_server_bind(xs);
	if (rc < 0)
		goto out_xs;

	/* Allocate SCCP stack */
	osmo_ss7_ensure_sccp(ss7);
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
osmo_sccp_simple_server(void *ctx, uint32_t pc,
			enum osmo_ss7_asp_protocol prot, int local_port,
			const char *local_ip)
{
	return osmo_sccp_simple_server_on_ss7_id(ctx, 1, pc, prot,
					         local_port, local_ip);
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

	/* route only selected PC to the client */
	rt = osmo_ss7_route_create(ss7->rtable_system, pc, 0xffff, as_name);
	if (!rt)
		goto out_as;

	asp = osmo_ss7_asp_find_or_create(ss7, asp_name, remote_port, local_port, prot);
	if (!asp)
		goto out_rt;
	asp->cfg.is_server = true;
	asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
	osmo_ss7_as_add_asp(as, asp_name);
	talloc_free(asp_name);
	talloc_free(as_name);
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

/*! \brief get the SS7 instance that is related to the given SCCP instance
 *  \param[in] sccp SCCP instance
 *  \returns SS7 instance; NULL if sccp was NULL */
struct osmo_ss7_instance *osmo_sccp_get_ss7(const struct osmo_sccp_instance *sccp)
{
	if (!sccp)
		return NULL;
	return sccp->ss7;
}

/*! \brief get the SCCP instance that is related to the given sccp user
 *  \param[in] scu SCCP user
 *  \returns SCCP instance; NULL if scu was NULL */
struct osmo_sccp_instance *osmo_sccp_get_sccp(const struct osmo_sccp_user *scu)
{
	if (!scu)
		return NULL;
	return scu->inst;
}
