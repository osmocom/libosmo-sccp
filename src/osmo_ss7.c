/* Core SS7 Instance/Linkset/Link/AS/ASP Handling */

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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

#include "sccp_internal.h"
#include "xua_internal.h"
#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"

#define MAX_PC_STR_LEN 32

static bool ss7_initialized = false;

LLIST_HEAD(osmo_ss7_instances);
static int32_t next_rctx = 1;
static int32_t next_l_rk_id = 1;

struct value_string osmo_ss7_as_traffic_mode_vals[] = {
	{ OSMO_SS7_AS_TMOD_BCAST,	"broadcast" },
	{ OSMO_SS7_AS_TMOD_LOADSHARE,	"loadshare" },
	{ OSMO_SS7_AS_TMOD_ROUNDROBIN,	"round-robin" },
	{ OSMO_SS7_AS_TMOD_OVERRIDE,	"override" },
	{ 0, NULL }
};

struct value_string osmo_ss7_asp_protocol_vals[] = {
	{ OSMO_SS7_ASP_PROT_NONE,	"none" },
	{ OSMO_SS7_ASP_PROT_SUA,	"sua" },
	{ OSMO_SS7_ASP_PROT_M3UA,	"m3ua" },
	{ OSMO_SS7_ASP_PROT_IPA,	"ipa" },
	{ 0, NULL }
};

const struct value_string osmo_ss7_asp_role_names[] = {
	{ OSMO_SS7_ASP_ROLE_ASP,	"ASP" },
	{ OSMO_SS7_ASP_ROLE_SG,		"SG" },
	{ OSMO_SS7_ASP_ROLE_IPSP,	"IPSP" },
	{ 0, NULL }
};

static int asp_proto_to_ip_proto(enum osmo_ss7_asp_protocol proto)
{
	switch (proto) {
	case OSMO_SS7_ASP_PROT_IPA:
		return IPPROTO_TCP;
	case OSMO_SS7_ASP_PROT_SUA:
	case OSMO_SS7_ASP_PROT_M3UA:
	default:
		return IPPROTO_SCTP;
	}
}

int osmo_ss7_find_free_rctx(struct osmo_ss7_instance *inst)
{
	int32_t rctx;

	for (rctx = next_rctx; rctx; rctx = ++next_rctx) {
		if (!osmo_ss7_as_find_by_rctx(inst, next_rctx))
			return rctx;
	}
	return -1;
}

static uint32_t find_free_l_rk_id(struct osmo_ss7_instance *inst)
{
	uint32_t l_rk_id;

	for (l_rk_id = next_l_rk_id; next_l_rk_id; l_rk_id = ++next_l_rk_id) {
		if (!osmo_ss7_as_find_by_l_rk_id(inst, next_l_rk_id))
			return l_rk_id;
	}
	return -1;
}


/***********************************************************************
 * SS7 Point Code Parsing / Printing
 ***********************************************************************/

static const struct osmo_ss7_pc_fmt default_pc_fmt = {
	.delimiter = '.',
	.component_len = { 3, 8, 3},
};

/* like strcat() but appends a single character */
static int strnappendchar(char *str, char c, size_t n)
{
	unsigned int curlen = strlen(str);

	if (n < curlen + 2)
		return -1;

	str[curlen] = c;
	str[curlen+1] = '\0';

	return curlen+1;
}

/* generate a format string for formatting a point code. The result can
 * e.g. be used with sscanf() or sprintf() */
static const char *gen_pc_fmtstr(const struct osmo_ss7_pc_fmt *pc_fmt,
				 unsigned int *num_comp_exp)
{
	static char buf[MAX_PC_STR_LEN];
	unsigned int num_comp = 0;

	buf[0] = '\0';
	strcat(buf, "%u");
	num_comp++;

	if (pc_fmt->component_len[1] == 0)
		goto out;
	strnappendchar(buf, pc_fmt->delimiter, sizeof(buf));
	strcat(buf, "%u");
	num_comp++;

	if (pc_fmt->component_len[2] == 0)
		goto out;
	strnappendchar(buf, pc_fmt->delimiter, sizeof(buf));
	strcat(buf, "%u");
	num_comp++;
out:
	if (num_comp_exp)
		*num_comp_exp = num_comp;
	return buf;
}

/* get number of components we expect for a point code, depending on the
 * configuration of this ss7_instance */
static unsigned int num_pc_comp_exp(const struct osmo_ss7_pc_fmt *pc_fmt)
{
	unsigned int num_comp_exp = 1;

	if (pc_fmt->component_len[1])
		num_comp_exp++;
	if (pc_fmt->component_len[2])
		num_comp_exp++;

	return num_comp_exp;
}

/* get the total width (in bits) of the point-codes in this ss7_instance */
uint8_t osmo_ss7_pc_width(const struct osmo_ss7_pc_fmt *pc_fmt)
{
	return pc_fmt->component_len[0] + pc_fmt->component_len[1] + pc_fmt->component_len[2];
}

/* get the number of bits we must shift the given component of a point
 * code in this ss7_instance */
static unsigned int get_pc_comp_shift(const struct osmo_ss7_pc_fmt *pc_fmt,
					unsigned int comp_num)
{
	uint32_t pc_width = osmo_ss7_pc_width(pc_fmt);
	switch (comp_num) {
	case 0:
		return pc_width - pc_fmt->component_len[0];
	case 1:
		return pc_width - pc_fmt->component_len[0] - pc_fmt->component_len[1];
	case 2:
		return 0;
	default:
		/* Invalid number of components */
		OSMO_ASSERT(false);
	}
}

static uint32_t pc_comp_shift_and_mask(const struct osmo_ss7_pc_fmt *pc_fmt,
					unsigned int comp_num, uint32_t pc)
{
	unsigned int shift = get_pc_comp_shift(pc_fmt, comp_num);
	uint32_t mask = (1 << pc_fmt->component_len[comp_num]) - 1;

	return (pc >> shift) & mask;
}

/* parse a point code according to the structure configured for this
 * ss7_instance */
int osmo_ss7_pointcode_parse(struct osmo_ss7_instance *inst, const char *str)
{
	unsigned int component[3];
	const struct osmo_ss7_pc_fmt *pc_fmt = inst ? &inst->cfg.pc_fmt : &default_pc_fmt;
	unsigned int num_comp_exp = num_pc_comp_exp(pc_fmt);
	const char *fmtstr = gen_pc_fmtstr(pc_fmt, &num_comp_exp);
	int i, rc;

	rc = sscanf(str, fmtstr, &component[0], &component[1], &component[2]);
	/* ensure all components were parsed */
	if (rc != num_comp_exp)
		goto err;

	/* check none of the component values exceeds what can be
	 * represented within its bit-width */
	for (i = 0; i < num_comp_exp; i++) {
		if (component[i] >= (1 << pc_fmt->component_len[i]))
			goto err;
	}

	/* shift them all together */
	rc = (component[0] << get_pc_comp_shift(pc_fmt, 0));
	if (num_comp_exp > 1)
		rc |= (component[1] << get_pc_comp_shift(pc_fmt, 1));
	if (num_comp_exp > 2)
		rc |= (component[2] << get_pc_comp_shift(pc_fmt, 2));

	return rc;

err:
	LOGSS7(inst, LOGL_NOTICE, "Error parsing Pointcode '%s'\n", str);
	return -EINVAL;
}

const char *_osmo_ss7_pointcode_print(char *buf, size_t len, const struct osmo_ss7_instance *inst, uint32_t pc)
{
	const struct osmo_ss7_pc_fmt *pc_fmt;
	unsigned int num_comp_exp;
	const char *fmtstr;

	if (!osmo_ss7_pc_is_valid(pc))
		return "(no PC)";

	pc_fmt = inst ? &inst->cfg.pc_fmt : &default_pc_fmt;
	num_comp_exp = num_pc_comp_exp(pc_fmt);
	fmtstr = gen_pc_fmtstr(pc_fmt, &num_comp_exp);
	OSMO_ASSERT(fmtstr);
	snprintf(buf, len, fmtstr,
		 pc_comp_shift_and_mask(pc_fmt, 0, pc),
		 pc_comp_shift_and_mask(pc_fmt, 1, pc),
		 pc_comp_shift_and_mask(pc_fmt, 2, pc));

	return buf;
}


/* print a pointcode according to the structure configured for this
 * ss7_instance */
const char *osmo_ss7_pointcode_print(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	static char buf[MAX_PC_STR_LEN];
	return _osmo_ss7_pointcode_print(buf, sizeof(buf), inst, pc);
}

/* same as osmo_ss7_pointcode_print() but using a separate buffer, useful for multiple point codes in the
 * same LOGP/printf. */
const char *osmo_ss7_pointcode_print2(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	static char buf[MAX_PC_STR_LEN];
	return _osmo_ss7_pointcode_print(buf, sizeof(buf), inst, pc);
}

int osmo_ss7_pointcode_parse_mask_or_len(struct osmo_ss7_instance *inst, const char *in)
{
	unsigned int width = osmo_ss7_pc_width(inst ? &inst->cfg.pc_fmt : &default_pc_fmt);

	if (in[0] == '/') {
		/* parse mask by length */
		int masklen = atoi(in+1);
		if (masklen < 0 || masklen > 32)
			return -EINVAL;
		if (masklen == 0)
			return 0;
		return (0xFFFFFFFF << (width - masklen)) & ((1 << width)-1);
	} else {
		/* parse mask as point code */
		return osmo_ss7_pointcode_parse(inst, in);
	}
}

static const uint16_t prot2port[] = {
	[OSMO_SS7_ASP_PROT_NONE] = 0,
	[OSMO_SS7_ASP_PROT_SUA] = SUA_PORT,
	[OSMO_SS7_ASP_PROT_M3UA] = M3UA_PORT,
	[OSMO_SS7_ASP_PROT_IPA] = 5000,
};

int osmo_ss7_asp_protocol_port(enum osmo_ss7_asp_protocol prot)
{
	if (prot >= ARRAY_SIZE(prot2port))
		return -EINVAL;
	else
		return prot2port[prot];
}

/***********************************************************************
 * SS7 Instance
 ***********************************************************************/

/*! \brief Find a SS7 Instance with given ID
 *  \param[in] id ID for which to search
 *  \returns \ref osmo_ss7_instance on success; NULL on error */
struct osmo_ss7_instance *
osmo_ss7_instance_find(uint32_t id)
{
	OSMO_ASSERT(ss7_initialized);

	struct osmo_ss7_instance *inst;
	llist_for_each_entry(inst, &osmo_ss7_instances, list) {
		if (inst->cfg.id == id)
			return inst;
	}
	return NULL;
}

/*! \brief Find or create a SS7 Instance
 *  \param[in] ctx talloc allocation context to use for allocations
 *  \param[in] id ID of SS7 Instance
 *  \returns \ref osmo_ss7_instance on success; NULL on error */
struct osmo_ss7_instance *
osmo_ss7_instance_find_or_create(void *ctx, uint32_t id)
{
	struct osmo_ss7_instance *inst;

	OSMO_ASSERT(ss7_initialized);

	inst = osmo_ss7_instance_find(id);
	if (inst)
		return inst;

	inst = talloc_zero(ctx, struct osmo_ss7_instance);
	if (!inst)
		return NULL;

	inst->cfg.primary_pc = OSMO_SS7_PC_INVALID;

	inst->cfg.id = id;
	LOGSS7(inst, LOGL_INFO, "Creating SS7 Instance\n");

	INIT_LLIST_HEAD(&inst->linksets);
	INIT_LLIST_HEAD(&inst->as_list);
	INIT_LLIST_HEAD(&inst->asp_list);
	INIT_LLIST_HEAD(&inst->rtable_list);
	INIT_LLIST_HEAD(&inst->xua_servers);
	inst->rtable_system = osmo_ss7_route_table_find_or_create(inst, "system");

	/* default point code structure + formatting */
	inst->cfg.pc_fmt.delimiter = '.';
	inst->cfg.pc_fmt.component_len[0] = 3;
	inst->cfg.pc_fmt.component_len[1] = 8;
	inst->cfg.pc_fmt.component_len[2] = 3;

	llist_add(&inst->list, &osmo_ss7_instances);

	INIT_LLIST_HEAD(&inst->cfg.sccp_address_book);

	return inst;
}

/*! \brief Destroy a SS7 Instance
 *  \param[in] inst SS7 Instance to be destroyed */
void osmo_ss7_instance_destroy(struct osmo_ss7_instance *inst)
{
	struct osmo_ss7_linkset *lset;
	struct osmo_ss7_as *as;
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(inst, LOGL_INFO, "Destroying SS7 Instance\n");

	llist_for_each_entry(asp, &inst->asp_list, list)
		osmo_ss7_asp_destroy(asp);

	llist_for_each_entry(as, &inst->as_list, list)
		osmo_ss7_as_destroy(as);

	llist_for_each_entry(lset, &inst->linksets, list)
		osmo_ss7_linkset_destroy(lset);

	llist_del(&inst->list);
	talloc_free(inst);
}

/*! \brief Set the point code format used in given SS7 instance */
int osmo_ss7_instance_set_pc_fmt(struct osmo_ss7_instance *inst,
				uint8_t c0, uint8_t c1, uint8_t c2)
{
	if (c0+c1+c2 > 32)
		return -EINVAL;

	if (c0+c1+c2 > 14)
		LOGSS7(inst, LOGL_NOTICE, "Point Code Format %u-%u-%u "
			"is longer than 14 bits, odd?\n", c0, c1, c2);

	inst->cfg.pc_fmt.component_len[0] = c0;
	inst->cfg.pc_fmt.component_len[1] = c1;
	inst->cfg.pc_fmt.component_len[2] = c2;

	return 0;
}

/*! Allocate an SCCP instance, if not present yet.
 * \returns inst->sccp. */
struct osmo_sccp_instance *osmo_ss7_ensure_sccp(struct osmo_ss7_instance *inst)
{
	if (inst->sccp)
		return inst->sccp;

	LOGSS7(inst, LOGL_NOTICE, "Creating SCCP instance\n");
	inst->sccp = osmo_sccp_instance_create(inst, NULL);
	return inst->sccp;
}

/***********************************************************************
 * MTP Users (Users of MTP, such as SCCP or ISUP)
 ***********************************************************************/

/*! \brief Register a MTP user for a given service indicator
 *  \param[in] inst SS7 instance for which we register the user
 *  \param[in] service_ind Service (ISUP, SCCP, ...)
 *  \param[in] user SS7 user (including primitive call-back)
 *  \returns 0 on success; negative on error */
int osmo_ss7_user_register(struct osmo_ss7_instance *inst, uint8_t service_ind,
			   struct osmo_ss7_user *user)
{
	if (service_ind >= ARRAY_SIZE(inst->user))
		return -EINVAL;

	if (inst->user[service_ind])
		return -EBUSY;

	DEBUGP(DLSS7, "registering user=%s for SI %u with priv %p\n",
		user->name, service_ind, user->priv);

	user->inst = inst;
	inst->user[service_ind] = user;

	return 0;
}

/*! \brief Unregister a MTP user for a given service indicator
 *  \param[in] inst SS7 instance for which we register the user
 *  \param[in] service_ind Service (ISUP, SCCP, ...)
 *  \param[in] user (optional) SS7 user. If present, we will not
 * 		unregister other users
 *  \returns 0 on success; negative on error */
int osmo_ss7_user_unregister(struct osmo_ss7_instance *inst, uint8_t service_ind,
			     struct osmo_ss7_user *user)
{
	if (service_ind >= ARRAY_SIZE(inst->user))
		return -EINVAL;

	if (!inst->user[service_ind])
		return -ENODEV;

	if (user && (inst->user[service_ind] != user))
		return -EINVAL;

	if (user)
		user->inst = NULL;
	inst->user[service_ind] = NULL;

	return 0;
}

/* deliver to a local MTP user */
int osmo_ss7_mtp_to_user(struct osmo_ss7_instance *inst, struct osmo_mtp_prim *omp)
{
	uint32_t service_ind;
	const struct osmo_ss7_user *osu;

	if (omp->oph.sap != MTP_SAP_USER ||
	    omp->oph.primitive != OSMO_MTP_PRIM_TRANSFER ||
	    omp->oph.operation != PRIM_OP_INDICATION) {
		LOGP(DLSS7, LOGL_ERROR, "Unsupported Primitive\n");
		return -EINVAL;
	}

	service_ind = omp->u.transfer.sio & 0xF;
	osu = inst->user[service_ind];

	if (!osu) {
		LOGP(DLSS7, LOGL_NOTICE, "No MTP-User for SI %u\n", service_ind);
		return -ENODEV;
	}

	DEBUGP(DLSS7, "delivering MTP-TRANSFER.ind to user %s, priv=%p\n",
		osu->name, osu->priv);
	return osu->prim_cb(&omp->oph, (void *) osu->priv);
}

/***********************************************************************
 * SS7 Linkset
 ***********************************************************************/

/*! \brief Destroy a SS7 Linkset
 *  \param[in] lset Linkset to be destroyed */
void osmo_ss7_linkset_destroy(struct osmo_ss7_linkset *lset)
{
	struct osmo_ss7_route *rt, *rt2;
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(lset->inst, LOGL_INFO, "Destroying Linkset %s\n",
		lset->cfg.name);

	/* find any routes pointing to this AS and remove them */
	llist_for_each_entry_safe(rt, rt2, &lset->inst->rtable_system->routes, list) {
		if (rt->dest.linkset == lset)
			osmo_ss7_route_destroy(rt);
	}

	for (i = 0; i < ARRAY_SIZE(lset->links); i++) {
		struct osmo_ss7_link *link = lset->links[i];
		if (!link)
			continue;
		osmo_ss7_link_destroy(link);
	}
	llist_del(&lset->list);
	talloc_free(lset);
}

/*! \brief Find SS7 Linkset by given name
 *  \param[in] inst SS7 Instance in which to look
 *  \param[in] name Name of SS7 Linkset
 *  \returns pointer to linkset on success; NULL on error */
struct osmo_ss7_linkset *
osmo_ss7_linkset_find_by_name(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_linkset *lset;
	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(lset, &inst->linksets, list) {
		if (!strcmp(name, lset->cfg.name))
			return lset;
	}
	return NULL;
}

/*! \brief Find or allocate SS7 Linkset
 *  \param[in] inst SS7 Instance in which we operate
 *  \param[in] name Name of SS7 Linkset
 *  \param[in] pc Adjacent Pointcode
 *  \returns pointer to Linkset on success; NULL on error */
struct osmo_ss7_linkset *
osmo_ss7_linkset_find_or_create(struct osmo_ss7_instance *inst, const char *name, uint32_t pc)
{
	struct osmo_ss7_linkset *lset;

	OSMO_ASSERT(ss7_initialized);
	lset = osmo_ss7_linkset_find_by_name(inst, name);
	if (lset && lset->cfg.adjacent_pc != pc)
		return NULL;

	if (!lset) {
		LOGSS7(inst, LOGL_INFO, "Creating Linkset %s\n", name);
		lset = talloc_zero(inst, struct osmo_ss7_linkset);
		lset->inst = inst;
		lset->cfg.adjacent_pc = pc;
		lset->cfg.name = talloc_strdup(lset, name);
		llist_add_tail(&lset->list, &inst->linksets);
	}

	return lset;
}

/***********************************************************************
 * SS7 Link
 ***********************************************************************/

/*! \brief Destryo SS7 Link
 *  \param[in] link SS7 Link to be destroyed */
void osmo_ss7_link_destroy(struct osmo_ss7_link *link)
{
	struct osmo_ss7_linkset *lset = link->linkset;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(lset->inst, LOGL_INFO, "Destroying Link %s:%u\n",
		lset->cfg.name, link->cfg.id);
	/* FIXME: do cleanup */
	lset->links[link->cfg.id] = NULL;
	talloc_free(link);
}

/*! \brief Find or create SS7 Link with given ID in given Linkset
 *  \param[in] lset SS7 Linkset on which we operate
 *  \param[in] id Link number within Linkset
 *  \returns pointer to SS7 Link on success; NULL on error */
struct osmo_ss7_link *
osmo_ss7_link_find_or_create(struct osmo_ss7_linkset *lset, uint32_t id)
{
	struct osmo_ss7_link *link;

	OSMO_ASSERT(ss7_initialized);
	if (id >= ARRAY_SIZE(lset->links))
		return NULL;

	if (lset->links[id]) {
		link = lset->links[id];
	} else {
		LOGSS7(lset->inst, LOGL_INFO, "Creating Link %s:%u\n",
			lset->cfg.name, id);
		link = talloc_zero(lset, struct osmo_ss7_link);
		if (!link)
			return NULL;
		link->linkset = lset;
		lset->links[id] = link;
		link->cfg.id = id;
	}

	return link;
}


/***********************************************************************
 * SS7 Route Tables
 ***********************************************************************/

struct osmo_ss7_route_table *
osmo_ss7_route_table_find(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_route_table *rtbl;
	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(rtbl, &inst->rtable_list, list) {
		if (!strcmp(rtbl->cfg.name, name))
			return rtbl;
	}
	return NULL;
}

struct osmo_ss7_route_table *
osmo_ss7_route_table_find_or_create(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_route_table *rtbl;

	OSMO_ASSERT(ss7_initialized);
	rtbl = osmo_ss7_route_table_find(inst, name);
	if (!rtbl) {
		LOGSS7(inst, LOGL_INFO, "Creating Route Table %s\n", name);
		rtbl = talloc_zero(inst, struct osmo_ss7_route_table);
		rtbl->inst = inst;
		rtbl->cfg.name = talloc_strdup(rtbl, name);
		INIT_LLIST_HEAD(&rtbl->routes);
		llist_add_tail(&rtbl->list, &inst->rtable_list);
	}
	return rtbl;
}

void osmo_ss7_route_table_destroy(struct osmo_ss7_route_table *rtbl)
{
	llist_del(&rtbl->list);
	/* routes are allocated as children of route table, will be
	 * automatically freed() */
	talloc_free(rtbl);
}

/***********************************************************************
 * SS7 Routes
 ***********************************************************************/

/*! \brief Find a SS7 route for given destination point code in given table */
struct osmo_ss7_route *
osmo_ss7_route_find_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc)
{
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);
	/* we assume the routes are sorted by mask length, i.e. more
	 * specific routes first, and less specific routes with shorter
	 * mask later */
	llist_for_each_entry(rt, &rtbl->routes, list) {
		if ((dpc & rt->cfg.mask) == rt->cfg.pc)
			return rt;
	}
	return NULL;
}

/*! \brief Find a SS7 route for given destination point code + mask in given table */
struct osmo_ss7_route *
osmo_ss7_route_find_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
				uint32_t mask)
{
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);
	/* we assume the routes are sorted by mask length, i.e. more
	 * specific routes first, and less specific routes with shorter
	 * mask later */
	llist_for_each_entry(rt, &rtbl->routes, list) {
		if (dpc == rt->cfg.pc && mask == rt->cfg.mask)
			return rt;
	}
	return NULL;
}

/*! \brief Find a SS7 route for given destination point code in given SS7 */
struct osmo_ss7_route *
osmo_ss7_route_lookup(struct osmo_ss7_instance *inst, uint32_t dpc)
{
	OSMO_ASSERT(ss7_initialized);
	return osmo_ss7_route_find_dpc(inst->rtable_system, dpc);
}

/* insert the route in the ordered list of routes. The list is sorted by
 * mask length, so that the more specific (longer mask) routes are
 * first, while the less specific routes with shorter masks are last.
 * Hence, the first matching route in a linear iteration is the most
 * specific match. */
static void route_insert_sorted(struct osmo_ss7_route_table *rtbl,
				struct osmo_ss7_route *cmp)
{
	struct osmo_ss7_route *rt;

	llist_for_each_entry(rt, &rtbl->routes, list) {
		if (rt->cfg.mask < cmp->cfg.mask) {
			/* insert before the current entry */
			llist_add(&cmp->list, rt->list.prev);
			return;
		}
	}
	/* not added, i.e. no smaller mask length found: we are the
	 * smallest mask and thus should go last */
	llist_add_tail(&cmp->list, &rtbl->routes);
}

/*! \brief Create a new route in the given routing table
 *  \param[in] rtbl Routing Table in which the route is to be created
 *  \param[in] pc Point Code of the destination of the route
 *  \param[in] mask Mask of the destination Point Code \ref pc
 *  \param[in] linkset_name string name of the linkset to be used
 *  \returns caller-allocated + initialized route, NULL on error
 */
struct osmo_ss7_route *
osmo_ss7_route_create(struct osmo_ss7_route_table *rtbl, uint32_t pc,
		      uint32_t mask, const char *linkset_name)
{
	struct osmo_ss7_route *rt;
	struct osmo_ss7_linkset *lset;
	struct osmo_ss7_as *as = NULL;

	OSMO_ASSERT(ss7_initialized);
	lset = osmo_ss7_linkset_find_by_name(rtbl->inst, linkset_name);
	if (!lset) {
		as = osmo_ss7_as_find_by_name(rtbl->inst, linkset_name);
		if (!as)
			return NULL;
	}

	rt = talloc_zero(rtbl, struct osmo_ss7_route);
	if (!rt)
		return NULL;

	rt->cfg.pc = pc;
	rt->cfg.mask = mask;
	rt->cfg.linkset_name = talloc_strdup(rt, linkset_name);
	if (lset) {
		rt->dest.linkset = lset;
		LOGSS7(rtbl->inst, LOGL_INFO, "Creating route: pc=%u=%s mask=0x%x via linkset '%s'\n",
		       pc, osmo_ss7_pointcode_print(rtbl->inst, pc), mask, lset->cfg.name);
	} else {
		rt->dest.as = as;
		LOGSS7(rtbl->inst, LOGL_INFO, "Creating route: pc=%u=%s mask=0x%x via AS '%s'\n",
		       pc, osmo_ss7_pointcode_print(rtbl->inst, pc), mask, as->cfg.name);
	}
	rt->rtable = rtbl;

	route_insert_sorted(rtbl, rt);

	return rt;
}

/*! \brief Destroy a given SS7 route */
void osmo_ss7_route_destroy(struct osmo_ss7_route *rt)
{
	OSMO_ASSERT(ss7_initialized);
	llist_del(&rt->list);
	talloc_free(rt);
}

/* count number of consecutive leading (MSB) bits that are '1' */
static unsigned int count_leading_one_bits(uint32_t inp, unsigned int nbits)
{
	unsigned int i;

	for (i = 0; i < nbits; i++) {
		if (!(inp & (1 << (nbits-1-i))))
			return i;
	}
	return i;
}

/* determine the mask length in number of bits; negative if non-consecutive mask */
static int u32_masklen(uint32_t mask, unsigned int nbits)
{
	unsigned int i;
	unsigned int leading_one_bits = count_leading_one_bits(mask, nbits);

	/* are there any bits set after the initial bits? */
	for (i = leading_one_bits; i < nbits; i++) {
		if (mask & (1 << (nbits-1-i)))
			return -1; /* not a simple prefix mask */
	}
	return leading_one_bits;
}

const char *osmo_ss7_route_print(const struct osmo_ss7_route *rt)
{
	const struct osmo_ss7_instance *inst = rt->rtable->inst;
	unsigned int pc_width = osmo_ss7_pc_width(&inst->cfg.pc_fmt);
	static char buf[64];
	int rc = u32_masklen(rt->cfg.mask, pc_width);

	if (rc < 0)
		snprintf(buf, sizeof(buf), "%s/%s", osmo_ss7_pointcode_print(inst, rt->cfg.pc),
			 osmo_ss7_pointcode_print2(inst, rt->cfg.mask));
	else
		snprintf(buf, sizeof(buf), "%s/%u", osmo_ss7_pointcode_print(inst, rt->cfg.pc), rc);
	return buf;
}


/***********************************************************************
 * SS7 Application Server
 ***********************************************************************/

/*! \brief Find Application Server by given name
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of AS
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_by_name(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(as, &inst->as_list, list) {
		if (!strcmp(name, as->cfg.name))
			return as;
	}
	return NULL;
}

/*! \brief Find Application Server by given routing context
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] rctx Routing Context
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_by_rctx(struct osmo_ss7_instance *inst, uint32_t rctx)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(as, &inst->as_list, list) {
		if (as->cfg.routing_key.context == rctx)
			return as;
	}
	return NULL;
}

/*! \brief Find Application Server by given local routing key ID
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] l_rk_id Local Routing Key ID
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_by_l_rk_id(struct osmo_ss7_instance *inst, uint32_t l_rk_id)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(as, &inst->as_list, list) {
		if (as->cfg.routing_key.l_rk_id == l_rk_id)
			return as;
	}
	return NULL;
}

/*! \brief Find Application Server (AS) by given protocol.
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] proto Protocol identifier that must match
 *  \returns pointer to AS on success; NULL otherwise
 *  If an AS has an ASP also matching the given protocol, that AS is preferred.
 *  If there are multiple matches, return the first matching AS. */
struct osmo_ss7_as *osmo_ss7_as_find_by_proto(struct osmo_ss7_instance *inst,
					      enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;
	struct osmo_ss7_as *as_without_asp = NULL;

	OSMO_ASSERT(ss7_initialized);

	/* Loop through the list with AS and try to find one where the proto
	   matches up */
	llist_for_each_entry(as, &inst->as_list, list) {
		if (as->cfg.proto == proto) {

			/* Put down the first AS that matches the proto, just in
			 * case we will not find any matching ASP */
			if (!as_without_asp)
				as_without_asp = as;

			/* Check if the candicate we have here has any suitable
			 * ASP */
			if (osmo_ss7_asp_find_by_proto(as, proto))
				return as;
		}
	}

	/* Return with the second best find, if there is any */
	return as_without_asp;
}

/*! \brief Find or Create Application Server
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of Application Server
 *  \param[in] proto Protocol of Application Server
 *  \returns pointer to Application Server on suuccess; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			   enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	as = osmo_ss7_as_find_by_name(inst, name);

	if (as && as->cfg.proto != proto)
		return NULL;

	if (!as) {
		as = talloc_zero(inst, struct osmo_ss7_as);
		if (!as)
			return NULL;
		as->inst = inst;
		as->cfg.name = talloc_strdup(as, name);
		as->cfg.proto = proto;
		as->cfg.mode = OSMO_SS7_AS_TMOD_OVERRIDE;
		as->cfg.recovery_timeout_msec = 2000;
		as->cfg.routing_key.l_rk_id = find_free_l_rk_id(inst);
		as->fi = xua_as_fsm_start(as, LOGL_DEBUG);
		llist_add_tail(&as->list, &inst->as_list);
		LOGPAS(as, DLSS7, LOGL_INFO, "Created AS\n");
	}

	return as;
}

/*! \brief Add given ASP to given AS
 *  \param[in] as Application Server to which \ref asp is added
 *  \param[in] asp Application Server Process to be added to \ref as
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_as_add_asp(struct osmo_ss7_as *as, const char *asp_name)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(as->inst, asp_name);
	if (!asp)
		return -ENODEV;

	LOGPAS(as, DLSS7, LOGL_INFO, "Adding ASP %s to AS\n", asp->cfg.name);

	if (osmo_ss7_as_has_asp(as, asp))
		return 0;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (!as->cfg.asps[i]) {
			as->cfg.asps[i] = asp;
			return 0;
		}
	}

	return -ENOSPC;
}

/*! \brief Delete given ASP from given AS
 *  \param[in] as Application Server from which \ref asp is deleted
 *  \param[in] asp Application Server Process to delete from \ref as
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_as_del_asp(struct osmo_ss7_as *as, const char *asp_name)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(as->inst, asp_name);
	if (!asp)
		return -ENODEV;

	LOGPAS(as, DLSS7, LOGL_INFO, "Removing ASP %s from AS\n", asp->cfg.name);

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] == asp) {
			as->cfg.asps[i] = NULL;
			return 0;
		}
	}

	return -EINVAL;
}

/*! \brief Destroy given Application Server
 *  \param[in] as Application Server to destroy */
void osmo_ss7_as_destroy(struct osmo_ss7_as *as)
{
	struct osmo_ss7_route *rt, *rt2;

	OSMO_ASSERT(ss7_initialized);
	LOGPAS(as, DLSS7, LOGL_INFO, "Destroying AS\n");

	if (as->fi)
		osmo_fsm_inst_term(as->fi, OSMO_FSM_TERM_REQUEST, NULL);

	/* find any routes pointing to this AS and remove them */
	llist_for_each_entry_safe(rt, rt2, &as->inst->rtable_system->routes, list) {
		if (rt->dest.as == as)
			osmo_ss7_route_destroy(rt);
	}

	as->inst = NULL;
	llist_del(&as->list);
	talloc_free(as);
}

/*! \brief Determine if given AS contains ASP
 *  \param[in] as Application Server in which to look for \ref asp
 *  \param[in] asp Application Server Process to look for in \ref as
 *  \returns true in case \ref asp is part of \ref as; false otherwise */
bool osmo_ss7_as_has_asp(struct osmo_ss7_as *as,
			 struct osmo_ss7_asp *asp)
{
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] == asp)
			return true;
	}
	return false;
}

/*! Determine if given AS is in the active state.
 *  \param[in] as Application Server.
 *  \returns true in case as is active; false otherwise. */
bool osmo_ss7_as_active(const struct osmo_ss7_as *as)
{
	if (!as->fi)
		return false;
	return as->fi->state == XUA_AS_S_ACTIVE;
}

/***********************************************************************
 * SS7 Application Server Process
 ***********************************************************************/

int osmo_ss7_asp_peer_snprintf(char* buf, size_t buf_len, struct osmo_ss7_asp_peer *peer)
{
	int len = 0, offset = 0, rem = buf_len;
	int ret, i;
	char *after;

	if (buf_len < 3)
		return -EINVAL;

	if (peer->host_cnt > 1) {
		ret = snprintf(buf, rem, "(");
		if (ret < 0)
			return ret;
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}
	for (i = 0; i < peer->host_cnt; i++) {
		if (peer->host_cnt == 1)
			after = "";
		else
			after = (i == (peer->host_cnt - 1)) ? ")" : "|";
		ret = snprintf(buf + offset, rem, "%s%s", peer->host[i] ? : "0.0.0.0", after);
		OSMO_SNPRINTF_RET(ret, rem, offset, len);
	}
	ret = snprintf(buf + offset, rem, ":%u", peer->port);
	if (ret < 0)
		return ret;
	OSMO_SNPRINTF_RET(ret, rem, offset, len);

	return len;
}

struct osmo_ss7_asp *
osmo_ss7_asp_find_by_name(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(asp, &inst->asp_list, list) {
		if (!strcmp(name, asp->cfg.name))
			return asp;
	}
	return NULL;
}

static uint16_t get_in_port(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (((struct sockaddr_in*)sa)->sin_port);
	case AF_INET6:
	        return (((struct sockaddr_in6*)sa)->sin6_port);
	default:
		return 0;
	}
}

/*! \brief Find an ASP definition matching the local+remote IP/PORT of given fd
 *  \param[in] fd socket descriptor of given socket
 *  \returns SS7 ASP in case a matching one is found; NULL otherwise */
static struct osmo_ss7_asp *
osmo_ss7_asp_find_by_socket_addr(int fd)
{
	struct osmo_ss7_instance *inst;
	struct sockaddr sa_l, sa_r;
	socklen_t sa_len_l = sizeof(sa_l);
	socklen_t sa_len_r = sizeof(sa_r);
	char hostbuf_l[64], hostbuf_r[64];
	uint16_t local_port, remote_port;
	int rc;
	int i;

	OSMO_ASSERT(ss7_initialized);
	/* convert local and remote IP to string */
	rc = getsockname(fd, &sa_l, &sa_len_l);
	if (rc < 0)
		return NULL;
	rc = getnameinfo(&sa_l, sa_len_l, hostbuf_l, sizeof(hostbuf_l),
			 NULL, 0, NI_NUMERICHOST);
	if (rc < 0)
		return NULL;
	local_port = ntohs(get_in_port(&sa_l));

	rc = getpeername(fd, &sa_r, &sa_len_r);
	if (rc < 0)
		return NULL;
	rc = getnameinfo(&sa_r, sa_len_r, hostbuf_r, sizeof(hostbuf_r),
			 NULL, 0, NI_NUMERICHOST);
	if (rc < 0)
		return NULL;
	remote_port = ntohs(get_in_port(&sa_r));

	/* check all instances for any ASP definition matching the
	 * address combination of local/remote ip/port */
	llist_for_each_entry(inst, &osmo_ss7_instances, list) {
		struct osmo_ss7_asp *asp;
		llist_for_each_entry(asp, &inst->asp_list, list) {
			if (asp->cfg.local.port != local_port)
				continue;
			if (asp->cfg.remote.port && asp->cfg.remote.port != remote_port)
				continue;

			for (i = 0; i < asp->cfg.local.host_cnt; i++) {
				bool is_any = !asp->cfg.local.host[i] || !strcmp(asp->cfg.local.host[i], "0.0.0.0");
				if (is_any || !strcmp(asp->cfg.local.host[i], hostbuf_l))
					break;
			}
			if (i == asp->cfg.local.host_cnt)
				continue; /* didn't match any local.host */

			/* If no remote host was set, it's probably a server and hence we match any cli src */
			if (asp->cfg.remote.host_cnt) {
				for (i = 0; i < asp->cfg.remote.host_cnt; i++) {
					if (!asp->cfg.remote.host[i] || !strcmp(asp->cfg.remote.host[i], hostbuf_r))
						break;
				}
				if (i == asp->cfg.remote.host_cnt)
					continue; /* didn't match any remote.host */
			}

			return asp;
		}
	}

	return NULL;
}

/*! \brief Find an ASP that matches the given protocol.
 *  \param[in] as Application Server in which to look for \ref asp
 *  \returns SS7 ASP in case a matching one is found; NULL otherwise */
struct osmo_ss7_asp
*osmo_ss7_asp_find_by_proto(struct osmo_ss7_as *as,
			    enum osmo_ss7_asp_protocol proto)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] && as->cfg.asps[i]->cfg.proto == proto)
			return as->cfg.asps[i];
	}

	return NULL;
}

struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			    uint16_t remote_port, uint16_t local_port,
			    enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(inst, name);

	if (asp && (asp->cfg.remote.port != remote_port ||
		    asp->cfg.local.port != local_port ||
		    asp->cfg.proto != proto))
		return NULL;

	if (!asp) {
		/* FIXME: check if local port has SCTP? */
		asp = talloc_zero(inst, struct osmo_ss7_asp);
		asp->inst = inst;
		asp->cfg.remote.port = remote_port;
		asp->cfg.local.port = local_port;
		asp->cfg.proto = proto;
		asp->cfg.name = talloc_strdup(asp, name);
		llist_add_tail(&asp->list, &inst->asp_list);

		/* The SUA code internally needs SCCP to work */
		if (proto == OSMO_SS7_ASP_PROT_SUA)
			osmo_ss7_ensure_sccp(inst);

	}
	return asp;
}

void osmo_ss7_asp_destroy(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	LOGPASP(asp, DLSS7, LOGL_INFO, "Destroying ASP\n");

	if (asp->server)
		osmo_stream_srv_destroy(asp->server);
	if (asp->client)
		osmo_stream_cli_destroy(asp->client);
	if (asp->fi)
		osmo_fsm_inst_term(asp->fi, OSMO_FSM_TERM_REQUEST, NULL);
	if (asp->xua_server)
		llist_del(&asp->siblings);

	/* unlink from all ASs we are part of */
	llist_for_each_entry(as, &asp->inst->as_list, list) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
			if (as->cfg.asps[i] == asp) {
				as->cfg.asps[i] = NULL;
			}
		}
	}
	/* unlink from ss7_instance */
	asp->inst = NULL;
	llist_del(&asp->list);
	/* release memory */
	talloc_free(asp);
}

static int xua_cli_read_cb(struct osmo_stream_cli *conn);
static int ipa_cli_read_cb(struct osmo_stream_cli *conn);
static int xua_cli_connect_cb(struct osmo_stream_cli *cli);

int osmo_ss7_asp_restart(struct osmo_ss7_asp *asp)
{
	int rc;
	char bufloc[512], bufrem[512];

	OSMO_ASSERT(ss7_initialized);
	osmo_ss7_asp_peer_snprintf(bufloc, sizeof(bufloc), &asp->cfg.local);
	osmo_ss7_asp_peer_snprintf(bufrem, sizeof(bufrem), &asp->cfg.remote);
	LOGPASP(asp, DLSS7, LOGL_INFO, "Restarting ASP %s, r=%s<->l=%s\n",
	       asp->cfg.name, bufrem, bufloc);

	if (!asp->cfg.is_server) {
		/* We are in client mode now */
		if (asp->server) {
			/* if we previously were in server mode,
			 * destroy it */
			osmo_stream_srv_destroy(asp->server);
			asp->server = NULL;
		}
		if (!asp->client)
			asp->client = osmo_stream_cli_create(asp);
		if (!asp->client) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Unable to create stream"
				" client for ASP %s\n", asp->cfg.name);
			return -1;
		}
		osmo_stream_cli_set_nodelay(asp->client, true);
		osmo_stream_cli_set_addrs(asp->client, (const char**)asp->cfg.remote.host, asp->cfg.remote.host_cnt);
		osmo_stream_cli_set_port(asp->client, asp->cfg.remote.port);
		osmo_stream_cli_set_local_addrs(asp->client, (const char**)asp->cfg.local.host, asp->cfg.local.host_cnt);
		osmo_stream_cli_set_local_port(asp->client, asp->cfg.local.port);
		osmo_stream_cli_set_proto(asp->client, asp_proto_to_ip_proto(asp->cfg.proto));
		osmo_stream_cli_set_reconnect_timeout(asp->client, 5);
		osmo_stream_cli_set_connect_cb(asp->client, xua_cli_connect_cb);
		if (asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
			osmo_stream_cli_set_read_cb(asp->client, ipa_cli_read_cb);
		else
			osmo_stream_cli_set_read_cb(asp->client, xua_cli_read_cb);
		osmo_stream_cli_set_data(asp->client, asp);
		rc = osmo_stream_cli_open(asp->client);
		if (rc < 0) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Unable to open stream"
				" client for ASP %s, %s ==> %s\n", asp->cfg.name, bufloc, bufrem);
			/* we don't return error in here because osmo_stream_cli_open()
			   will continue to retry (due to timeout being explicitly set with
			   osmo_stream_cli_set_reconnect_timeout() above) to connect so the error is transient */
		}
	} else {
		/* We are in server mode now */
		if (asp->client) {
			/* if we previously were in client mode,
			 * destroy it */
			osmo_stream_cli_destroy(asp->client);
			asp->client = NULL;
		}
		/* FIXME: ensure we have a SCTP server */
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "ASP Restart for server "
			"not implemented yet!\n");
	}

	/* (re)start the ASP FSM */
	if (asp->fi)
		osmo_fsm_inst_term(asp->fi, OSMO_FSM_TERM_REQUEST, NULL);
	asp->fi = xua_asp_fsm_start(asp, asp->cfg.role, LOGL_DEBUG);

	return 0;
}

bool osmo_ss7_asp_active(const struct osmo_ss7_asp *asp)
{
	if (!asp->fi)
		return false;
	return asp->fi->state == XUA_ASP_S_ACTIVE;
}

/***********************************************************************
 * libosmo-netif integration for SCTP stream server/client
 ***********************************************************************/

static const struct value_string sctp_assoc_chg_vals[] = {
	{ SCTP_COMM_UP,		"COMM_UP" },
	{ SCTP_COMM_LOST,	"COMM_LOST" },
	{ SCTP_RESTART,		"RESTART" },
	{ SCTP_SHUTDOWN_COMP,	"SHUTDOWN_COMP" },
	{ SCTP_CANT_STR_ASSOC,	"CANT_STR_ASSOC" },
	{ 0, NULL }
};

static const struct value_string sctp_sn_type_vals[] = {
	{ SCTP_ASSOC_CHANGE,		"ASSOC_CHANGE" },
	{ SCTP_PEER_ADDR_CHANGE,	"PEER_ADDR_CHANGE" },
	{ SCTP_SHUTDOWN_EVENT, 		"SHUTDOWN_EVENT" },
	{ SCTP_SEND_FAILED,		"SEND_FAILED" },
	{ SCTP_REMOTE_ERROR,		"REMOTE_ERROR" },
	{ SCTP_PARTIAL_DELIVERY_EVENT,	"PARTIAL_DELIVERY_EVENT" },
	{ SCTP_ADAPTATION_INDICATION,	"ADAPTATION_INDICATION" },
#ifdef SCTP_AUTHENTICATION_INDICATION
	{ SCTP_AUTHENTICATION_INDICATION, "AUTHENTICATION_INDICATION" },
#endif
#ifdef SCTP_SENDER_DRY_EVENT
	{ SCTP_SENDER_DRY_EVENT,	"SENDER_DRY_EVENT" },
#endif
	{ 0, NULL }
};

static int get_logevel_by_sn_type(int sn_type)
{
	switch (sn_type) {
	case SCTP_ADAPTATION_INDICATION:
	case SCTP_PEER_ADDR_CHANGE:
#ifdef SCTP_AUTHENTICATION_INDICATION
	case SCTP_AUTHENTICATION_INDICATION:
#endif
#ifdef SCTP_SENDER_DRY_EVENT
	case SCTP_SENDER_DRY_EVENT:
#endif
		return LOGL_INFO;
	case SCTP_ASSOC_CHANGE:
		return LOGL_NOTICE;
	case SCTP_SHUTDOWN_EVENT:
	case SCTP_PARTIAL_DELIVERY_EVENT:
		return LOGL_NOTICE;
	case SCTP_SEND_FAILED:
	case SCTP_REMOTE_ERROR:
		return LOGL_ERROR;
	default:
		return LOGL_NOTICE;
	}
}

static void log_sctp_notification(struct osmo_ss7_asp *asp, const char *pfx,
				  union sctp_notification *notif)
{
	int log_level;

	LOGPASP(asp, DLSS7, LOGL_INFO, "%s SCTP NOTIFICATION %u flags=0x%0x\n",
		pfx, notif->sn_header.sn_type,
		notif->sn_header.sn_flags);

	log_level = get_logevel_by_sn_type(notif->sn_header.sn_type);

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		LOGPASP(asp, DLSS7, log_level, "%s SCTP_ASSOC_CHANGE: %s\n",
			pfx, get_value_string(sctp_assoc_chg_vals,
				notif->sn_assoc_change.sac_state));
		break;
	default:
		LOGPASP(asp, DLSS7, log_level, "%s %s\n",
			pfx, get_value_string(sctp_sn_type_vals,
				notif->sn_header.sn_type));
		break;
	}
}

/* netif code tells us we can read something from the socket */
static int ipa_srv_conn_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_ss7_asp *asp = osmo_stream_srv_get_data(conn);
	struct msgb *msg = NULL;
	int rc;

	/* read IPA message from socket and process it */
	rc = ipa_msg_recv_buffered(ofd->fd, &msg, &asp->pending_msg);
	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): ipa_msg_recv_buffered() returned %d\n",
		__func__, rc);
	if (rc <= 0) {
		if (rc == -EAGAIN) {
			/* more data needed */
			return 0;
		}
		osmo_stream_srv_destroy(conn);
		return rc;
	}
	if (osmo_ipa_process_msg(msg) < 0) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Bad IPA message\n");
		osmo_stream_srv_destroy(conn);
		msgb_free(msg);
		return -1;
	}
	msg->dst = asp;

	return ipa_rx_msg(asp, msg);
}

/* netif code tells us we can read something from the socket */
static int xua_srv_conn_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct osmo_ss7_asp *asp = osmo_stream_srv_get_data(conn);
	struct msgb *msg = m3ua_msgb_alloc("xUA Server Rx");
	struct sctp_sndrcvinfo sinfo;
	unsigned int ppid;
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read xUA message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		__func__, rc, flags);
	if (rc < 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else if (rc == 0) {
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);

		log_sctp_notification(asp, "xUA SRV", notif);

		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
			break;
		case SCTP_ASSOC_CHANGE:
			if (notif->sn_assoc_change.sac_state == SCTP_RESTART)
				xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RESTART,
							     PRIM_OP_INDICATION);
			rc = 0;
			break;
		default:
			rc = 0;
			break;
		}
		goto out;
	}

	ppid = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_ppid(msg) = ppid;
	msgb_sctp_stream(msg) = sinfo.sinfo_stream;
	msg->dst = asp;

	if (ppid == SUA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA)
		rc = sua_rx_msg(asp, msg);
	else if (ppid == M3UA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA)
		rc = m3ua_rx_msg(asp, msg);
	else
		rc = ss7_asp_rx_unknown(asp, ppid, msg);

out:
	msgb_free(msg);
	return rc;
}

/* client has established SCTP connection to server */
static int xua_cli_connect_cb(struct osmo_stream_cli *cli)
{
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(cli);
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(cli);

	/* update the socket name */
	if (asp->sock_name)
		talloc_free(asp->sock_name);
	asp->sock_name = osmo_sock_get_name(asp, ofd->fd);

	LOGPASP(asp, DLSS7, LOGL_INFO, "Client connected %s\n", asp->sock_name);

	if (asp->lm && asp->lm->prim_cb) {
		/* Notify layer manager that a connection has been
		 * established */
		xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION);
	} else {
		/* directly as the ASP FSM to start by sending an ASP-UP ... */
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
	}

	return 0;
}

static void xua_cli_close(struct osmo_stream_cli *cli)
{
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(cli);

	osmo_stream_cli_close(cli);
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_COMM_DOWN_IND, asp);
	/* send M-SCTP_RELEASE.ind to XUA Layer Manager */
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION);
}

static void xua_cli_close_and_reconnect(struct osmo_stream_cli *cli)
{
	xua_cli_close(cli);
	osmo_stream_cli_reconnect(cli);
}

/* read call-back for IPA/SCCPlite socket */
static int ipa_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(conn);
	struct msgb *msg = NULL;
	int rc;

	/* read IPA message from socket and process it */
	rc = ipa_msg_recv_buffered(ofd->fd, &msg, &asp->pending_msg);
	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): ipa_msg_recv_buffered() returned %d\n",
		__func__, rc);
	if (rc <= 0) {
		if (rc == -EAGAIN) {
			/* more data needed */
			return 0;
		}
		xua_cli_close_and_reconnect(conn);
		return rc;
	}
	if (osmo_ipa_process_msg(msg) < 0) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Bad IPA message\n");
		xua_cli_close_and_reconnect(conn);
		msgb_free(msg);
		return -1;
	}
	msg->dst = asp;
	return ipa_rx_msg(asp, msg);
}

static int xua_cli_read_cb(struct osmo_stream_cli *conn)
{
	struct osmo_fd *ofd = osmo_stream_cli_get_ofd(conn);
	struct osmo_ss7_asp *asp = osmo_stream_cli_get_data(conn);
	struct msgb *msg = m3ua_msgb_alloc("xUA Client Rx");
	struct sctp_sndrcvinfo sinfo;
	unsigned int ppid;
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	/* read xUA message from socket and process it */
	rc = sctp_recvmsg(ofd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
		__func__, rc, flags);
	if (rc < 0) {
		xua_cli_close_and_reconnect(conn);
		goto out;
	} else if (rc == 0) {
		xua_cli_close_and_reconnect(conn);
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);

		log_sctp_notification(asp, "xUA CLNT", notif);

		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			xua_cli_close_and_reconnect(conn);
			break;
		case SCTP_ASSOC_CHANGE:
			if (notif->sn_assoc_change.sac_state == SCTP_RESTART)
				xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RESTART,
							     PRIM_OP_INDICATION);
		default:
			break;
		}
		rc = 0;
		goto out;
	}

	if (rc == 0)
		goto out;

	ppid = ntohl(sinfo.sinfo_ppid);
	msgb_sctp_ppid(msg) = ppid;
	msgb_sctp_stream(msg) = sinfo.sinfo_stream;
	msg->dst = asp;

	if (ppid == SUA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA)
		rc = sua_rx_msg(asp, msg);
	else if (ppid == M3UA_PPID && asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA)
		rc = m3ua_rx_msg(asp, msg);
	else
		rc = ss7_asp_rx_unknown(asp, ppid, msg);

out:
	msgb_free(msg);
	return rc;
}

static int xua_srv_conn_closed_cb(struct osmo_stream_srv *srv)
{
	struct osmo_ss7_asp *asp = osmo_stream_srv_get_data(srv);

	LOGP(DLSS7, LOGL_INFO, "%s: SCTP connection closed\n",
		asp ? asp->cfg.name : "?");

	if (!asp)
		return 0;

	/* notify ASP FSM and everyone else */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_COMM_DOWN_IND, NULL);

	/* delete any RKM-dynamically allocated ASs for this ASP */
	xua_rkm_cleanup_dyn_as_for_asp(asp);

	/* send M-SCTP_RELEASE.ind to Layer Manager */
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION);

	/* if we were dynamically allocated at accept_cb() time, let's
	 * self-destruct now.  A new connection will re-create the ASP. */
	if (asp->dyn_allocated) {
		/* avoid re-entrance via osmo_stream_srv_destroy() which
		 * called us */
		asp->server = NULL;
		osmo_ss7_asp_destroy(asp);
	}

	return 0;
}


/* server has accept()ed a new SCTP association, let's find the ASP for
 * it (if any) */
static int xua_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct osmo_xua_server *oxs = osmo_stream_srv_link_get_data(link);
	struct osmo_stream_srv *srv;
	struct osmo_ss7_asp *asp;
	int i;
	char *sock_name = osmo_sock_get_name(link, fd);
	const char *proto_name = get_value_string(osmo_ss7_asp_protocol_vals, oxs->cfg.proto);

	LOGP(DLSS7, LOGL_INFO, "%s: New %s connection accepted\n", sock_name, proto_name);

	if (oxs->cfg.proto == OSMO_SS7_ASP_PROT_IPA) {
		srv = osmo_stream_srv_create(oxs, link, fd,
					     ipa_srv_conn_cb,
					     xua_srv_conn_closed_cb, NULL);
	} else {
		srv = osmo_stream_srv_create(oxs, link, fd,
					     xua_srv_conn_cb,
					     xua_srv_conn_closed_cb, NULL);
	}
	if (!srv) {
		LOGP(DLSS7, LOGL_ERROR, "%s: Unable to create stream server "
		     "for connection\n", sock_name);
		close(fd);
		talloc_free(sock_name);
		return -1;
	}

	asp = osmo_ss7_asp_find_by_socket_addr(fd);
	if (asp) {
		LOGP(DLSS7, LOGL_INFO, "%s: matched connection to ASP %s\n",
			sock_name, asp->cfg.name);
	} else {
		if (!oxs->cfg.accept_dyn_reg) {
			LOGP(DLSS7, LOGL_NOTICE, "%s: %s connection without matching "
			     "ASP definition and no dynamic registration enabled, terminating\n",
			     sock_name, proto_name);
		} else {
			char namebuf[32];
			static uint32_t dyn_asp_num = 0;
			snprintf(namebuf, sizeof(namebuf), "asp-dyn-%u", dyn_asp_num++);
			asp = osmo_ss7_asp_find_or_create(oxs->inst, namebuf, 0, 0,
							  oxs->cfg.proto);
			if (asp) {
				char hostbuf[INET6_ADDRSTRLEN];
				char portbuf[16];

				osmo_sock_get_ip_and_port(fd, hostbuf, sizeof(hostbuf), portbuf, sizeof(portbuf), false);
				LOGP(DLSS7, LOGL_INFO, "%s: created dynamic ASP %s\n",
					sock_name, asp->cfg.name);
				asp->cfg.is_server = true;
				asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
				asp->cfg.local.port = oxs->cfg.local.port;
				for (i = 0; i < oxs->cfg.local.host_cnt; i++)
					asp->cfg.local.host[i] = talloc_strdup(asp, oxs->cfg.local.host[i]);
				asp->cfg.local.host_cnt = oxs->cfg.local.host_cnt;
				asp->cfg.remote.port = atoi(portbuf);
				asp->cfg.remote.host[0] = talloc_strdup(asp, hostbuf);
				asp->cfg.remote.host_cnt = 1;
				asp->dyn_allocated = true;
				asp->server = srv;
				osmo_ss7_asp_restart(asp);
			}
		}
		if (!asp) {
			osmo_stream_srv_destroy(srv);
			talloc_free(sock_name);
			return -1;
		}
	}

	/* update the ASP reference back to the server over which the
	 * connection came in */
	asp->server = srv;
	asp->xua_server = oxs;
	llist_add_tail(&asp->siblings, &oxs->asp_list);
	/* update the ASP socket name */
	if (asp->sock_name)
		talloc_free(asp->sock_name);
	asp->sock_name = talloc_reparent(link, asp, sock_name);
	/* make sure the conn_cb() is called with the asp as private
	 * data */
	osmo_stream_srv_set_data(srv, asp);

	/* send M-SCTP_ESTABLISH.ind to Layer Manager */
	osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_SCTP_EST_IND, 0);
	xua_asp_send_xlm_prim_simple(asp, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION);

	return 0;
}

/*! \brief send a fully encoded msgb via a given ASP
 *  \param[in] asp Application Server Process through which to send
 *  \param[in] msg message buffer to transmit. Ownership transferred.
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_asp_send(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	OSMO_ASSERT(ss7_initialized);

	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_SUA:
		msgb_sctp_ppid(msg) = SUA_PPID;
		break;
	case OSMO_SS7_ASP_PROT_M3UA:
		msgb_sctp_ppid(msg) = M3UA_PPID;
		break;
	case OSMO_SS7_ASP_PROT_IPA:
		break;
	default:
		OSMO_ASSERT(0);
	}

	if (asp->cfg.is_server) {
		if (!asp->server) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Cannot transmit, no asp->server\n");
			/* FIXME: what to do here? delete the route? send DUNA? */
			msgb_free(msg);
			return -EIO;
		}
		osmo_stream_srv_send(asp->server, msg);
	} else {
		if (!asp->client) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Cannot transmit, no asp->client\n");
			/* FIXME: what to do here? delete the route? send DUNA? */
			msgb_free(msg);
			return -EIO;
		}
		if (!osmo_stream_cli_is_connected(asp->client)) {
			LOGPASP(asp, DLSS7, LOGL_ERROR, "Cannot transmit, asp->client not connected\n");
			msgb_free(msg);
			return -EIO;
		}
		osmo_stream_cli_send(asp->client, msg);
	}

	return 0;
}

void osmo_ss7_asp_disconnect(struct osmo_ss7_asp *asp)
{
	if (asp->server)
		osmo_stream_srv_destroy(asp->server);
		/* the close_cb() will handle the remaining cleanup here */
	else if (asp->client)
		xua_cli_close_and_reconnect(asp->client);
}

/***********************************************************************
 * SS7 xUA Server
 ***********************************************************************/

struct osmo_xua_server *
osmo_ss7_xua_server_find(struct osmo_ss7_instance *inst, enum osmo_ss7_asp_protocol proto,
			 uint16_t local_port)
{
	struct osmo_xua_server *xs;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(xs, &inst->xua_servers, list) {
		if (proto == xs->cfg.proto &&
		    local_port == xs->cfg.local.port)
			return xs;
	}
	return NULL;
}

/*! \brief create a new xUA server configured with given ip/port
 *  \param[in] ctx talloc allocation context
 *  \param[in] proto protocol (xUA variant) to use
 *  \param[in] local_port local SCTP port to bind/listen to
 *  \param[in] local_host local IP address to bind/listen to (optional)
 *  \returns callee-allocated \ref osmo_xua_server in case of success
 */
struct osmo_xua_server *
osmo_ss7_xua_server_create(struct osmo_ss7_instance *inst, enum osmo_ss7_asp_protocol proto,
			   uint16_t local_port, const char *local_host)
{
	struct osmo_xua_server *oxs = talloc_zero(inst, struct osmo_xua_server);

	OSMO_ASSERT(ss7_initialized);
	if (!oxs)
		return NULL;

	LOGP(DLSS7, LOGL_INFO, "Creating %s Server %s:%u\n",
		get_value_string(osmo_ss7_asp_protocol_vals, proto), local_host, local_port);

	INIT_LLIST_HEAD(&oxs->asp_list);

	oxs->cfg.proto = proto;
	oxs->cfg.local.port = local_port;

	oxs->server = osmo_stream_srv_link_create(oxs);
	osmo_stream_srv_link_set_data(oxs->server, oxs);
	osmo_stream_srv_link_set_accept_cb(oxs->server, xua_accept_cb);

	osmo_stream_srv_link_set_nodelay(oxs->server, true);
	osmo_stream_srv_link_set_port(oxs->server, oxs->cfg.local.port);
	osmo_stream_srv_link_set_proto(oxs->server, asp_proto_to_ip_proto(proto));

	osmo_ss7_xua_server_set_local_host(oxs, local_host);

	LOGP(DLSS7, LOGL_INFO, "Created %s server on %s:%" PRIu16 "\n",
		get_value_string(osmo_ss7_asp_protocol_vals, proto), local_host, local_port);

	oxs->inst = inst;
	llist_add_tail(&oxs->list, &inst->xua_servers);

	/* The SUA code internally needs SCCP to work */
	if (proto == OSMO_SS7_ASP_PROT_SUA)
		osmo_ss7_ensure_sccp(inst);

	return oxs;
}

/*! \brief Set the xUA server to bind/listen to the currently configured ip/port
 *  \param[in] xs xUA server to operate
 *  \returns 0 on success, negative value on error.
 */
int
osmo_ss7_xua_server_bind(struct osmo_xua_server *xs)
{
	char buf[512];
	int rc;
	const char *proto = get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto);

	rc = osmo_ss7_asp_peer_snprintf(buf, sizeof(buf), &xs->cfg.local);
	if (rc < 0) {
		LOGP(DLSS7, LOGL_INFO, "Failed parsing %s Server osmo_ss7_asp_peer\n", proto);
	} else {
		LOGP(DLSS7, LOGL_INFO, "(Re)binding %s Server to %s\n",
		     proto, buf);
	}
	return osmo_stream_srv_link_open(xs->server);
}

int
osmo_ss7_xua_server_set_local_host(struct osmo_xua_server *xs, const char *local_host)
{
	osmo_ss7_xua_server_set_local_hosts(xs, &local_host, 1);
	return 0;
}

int
osmo_ss7_xua_server_set_local_hosts(struct osmo_xua_server *xs, const char **local_hosts, size_t local_host_cnt)
{
	int i = 0;
	OSMO_ASSERT(ss7_initialized);

	if (local_host_cnt > ARRAY_SIZE(xs->cfg.local.host))
		return -EINVAL;

	for (; i < local_host_cnt; i++)
		osmo_talloc_replace_string(xs, &xs->cfg.local.host[i], local_hosts[i]);
	for (; i < xs->cfg.local.host_cnt; i++) {
			talloc_free(xs->cfg.local.host[i]);
			xs->cfg.local.host[i] = NULL;
	}

	xs->cfg.local.host_cnt = local_host_cnt;

	osmo_stream_srv_link_set_addrs(xs->server, (const char **)xs->cfg.local.host, xs->cfg.local.host_cnt);

	return 0;
}

int
osmo_ss7_xua_server_add_local_host(struct osmo_xua_server *xs, const char *local_host)
{
	int i;
	bool new_is_any = !local_host || !strcmp(local_host, "0.0.0.0");
	bool iter_is_any;

	/* Makes no sense to have INET_ANY and specific addresses in the set */
	for (i = 0; i < xs->cfg.local.host_cnt; i++) {
			iter_is_any = !xs->cfg.local.host[i] ||
				      !strcmp(xs->cfg.local.host[i], "0.0.0.0");
			if (new_is_any && iter_is_any)
				return -EINVAL;
			if (!new_is_any && iter_is_any)
				return -EINVAL;
	}
	/* Makes no sense to have INET_ANY many times */
	if (new_is_any && xs->cfg.local.host_cnt)
		return -EINVAL;

	osmo_talloc_replace_string(xs, &xs->cfg.local.host[xs->cfg.local.host_cnt], local_host);
	xs->cfg.local.host_cnt++;

	osmo_stream_srv_link_set_addrs(xs->server, (const char **)xs->cfg.local.host, xs->cfg.local.host_cnt);
	return 0;
}

void osmo_ss7_xua_server_destroy(struct osmo_xua_server *xs)
{
	struct osmo_ss7_asp *asp, *asp2;

	if (xs->server) {
		osmo_stream_srv_link_close(xs->server);
		osmo_stream_srv_link_destroy(xs->server);
	}
	/* iterate and close all connections established in relation
	 * with this server */
	llist_for_each_entry_safe(asp, asp2, &xs->asp_list, siblings)
		osmo_ss7_asp_destroy(asp);

	llist_del(&xs->list);
	talloc_free(xs);
}

bool osmo_ss7_pc_is_local(struct osmo_ss7_instance *inst, uint32_t pc)
{
	OSMO_ASSERT(ss7_initialized);
	if (osmo_ss7_pc_is_valid(inst->cfg.primary_pc) && pc == inst->cfg.primary_pc)
		return true;
	/* FIXME: Secondary and Capability Point Codes */
	return false;
}

int osmo_ss7_init(void)
{
	if (ss7_initialized)
		return 1;
	osmo_fsm_register(&sccp_scoc_fsm);
	osmo_fsm_register(&xua_as_fsm);
	osmo_fsm_register(&xua_asp_fsm);
	osmo_fsm_register(&ipa_asp_fsm);
	osmo_fsm_register(&xua_default_lm_fsm);
	ss7_initialized = true;
	return 0;
}

int osmo_ss7_tmode_to_xua(enum osmo_ss7_as_traffic_mode tmod)
{
	switch (tmod) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
		return M3UA_TMOD_OVERRIDE;
	case OSMO_SS7_AS_TMOD_LOADSHARE:
		return M3UA_TMOD_LOADSHARE;
	case OSMO_SS7_AS_TMOD_BCAST:
		return M3UA_TMOD_BCAST;
	default:
		return -1;
	}
}

enum osmo_ss7_as_traffic_mode osmo_ss7_tmode_from_xua(uint32_t in)
{
	switch (in) {
	case M3UA_TMOD_OVERRIDE:
		return OSMO_SS7_AS_TMOD_OVERRIDE;
	case M3UA_TMOD_LOADSHARE:
		return OSMO_SS7_AS_TMOD_LOADSHARE;
	case M3UA_TMOD_BCAST:
		return OSMO_SS7_AS_TMOD_BCAST;
	default:
		OSMO_ASSERT(false);
	}
}

bool osmo_ss7_as_tmode_compatible_xua(struct osmo_ss7_as *as, uint32_t m3ua_tmt)
{
	if (!as->cfg.mode_set_by_vty && !as->cfg.mode_set_by_peer)
		return true;

	switch (m3ua_tmt) {
	case M3UA_TMOD_OVERRIDE:
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_OVERRIDE)
			return true;
		break;
	case M3UA_TMOD_LOADSHARE:
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_LOADSHARE ||
		    as->cfg.mode == OSMO_SS7_AS_TMOD_ROUNDROBIN)
			return true;
		break;
	case M3UA_TMOD_BCAST:
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_BCAST)
			return true;
		break;
	default:
		break;
	}
	return false;
}

static osmo_ss7_asp_rx_unknown_cb *g_osmo_ss7_asp_rx_unknown_cb;

int ss7_asp_rx_unknown(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg)
{
	if (g_osmo_ss7_asp_rx_unknown_cb)
		return (*g_osmo_ss7_asp_rx_unknown_cb)(asp, ppid_mux, msg);

	switch(asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_IPA:
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Rx IPA for unknown Stream ID 0x%02x: %s\n",
			ppid_mux, msgb_hexdump(msg));
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Rx SCTP chunk for unknown PPID %u: %s\n",
			ppid_mux, msgb_hexdump(msg));
		break;
	}
	return 0;
}

/*! Register a call-back function for unknown SCTP PPID / IPA Stream ID */
void osmo_ss7_register_rx_unknown_cb(osmo_ss7_asp_rx_unknown_cb *cb)
{
	g_osmo_ss7_asp_rx_unknown_cb = cb;
}
