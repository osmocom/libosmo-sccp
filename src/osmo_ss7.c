/* Core SS7 Instance/Linkset/Link/AS/ASP Handling */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/netif/sctp.h>

#include "sccp_internal.h"
#include "xua_internal.h"
#include "ss7_internal.h"
#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"

#define MAX_PC_STR_LEN 32

bool ss7_initialized = false;

LLIST_HEAD(osmo_ss7_instances);
static int32_t next_rctx = 1;
static int32_t next_l_rk_id = 1;

const struct value_string mtp_unavail_cause_vals[] = {
	{ MTP_UNAVAIL_C_UNKNOWN,		"unknown" },
	{ MTP_UNAVAIL_C_UNEQUIP_REM_USER,	"unequipped-remote-user" },
	{ MTP_UNAVAIL_C_INACC_REM_USER,		"inaccessible-remote-user" },
	{ 0, NULL }
};

struct value_string osmo_ss7_as_traffic_mode_vals[] = {
	{ OSMO_SS7_AS_TMOD_BCAST,	"broadcast" },
	{ OSMO_SS7_AS_TMOD_LOADSHARE,	"loadshare" },
	{ OSMO_SS7_AS_TMOD_ROUNDROBIN,	"round-robin" },
	{ OSMO_SS7_AS_TMOD_OVERRIDE,	"override" },
	{ 0, NULL }
};

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

/* truncate pc or mask to maximum permitted length. This solves
 * callers specifying arbitrary large masks which then evade duplicate
 * detection with longer mask lengths */
uint32_t osmo_ss7_pc_normalize(const struct osmo_ss7_pc_fmt *pc_fmt, uint32_t pc)
{
	uint32_t mask = (1 << osmo_ss7_pc_width(pc_fmt))-1;
	return pc & mask;
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

const char *osmo_ss7_pointcode_print_buf(char *buf, size_t len, const struct osmo_ss7_instance *inst, uint32_t pc)
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
	return osmo_ss7_pointcode_print_buf(buf, sizeof(buf), inst, pc);
}

/* same as osmo_ss7_pointcode_print() but using a separate buffer, useful for multiple point codes in the
 * same LOGP/printf. */
const char *osmo_ss7_pointcode_print2(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	static char buf[MAX_PC_STR_LEN];
	return osmo_ss7_pointcode_print_buf(buf, sizeof(buf), inst, pc);
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

	llist_add_tail(&inst->list, &osmo_ss7_instances);

	INIT_LLIST_HEAD(&inst->cfg.sccp_address_book);

	return inst;
}

/*! \brief Destroy a SS7 Instance
 *  \param[in] inst SS7 Instance to be destroyed */
void osmo_ss7_instance_destroy(struct osmo_ss7_instance *inst)
{
	struct osmo_ss7_linkset *lset, *lset2;
	struct osmo_ss7_as *as, *as2;
	struct osmo_ss7_asp *asp, *asp2;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(inst, LOGL_INFO, "Destroying SS7 Instance\n");

	llist_for_each_entry_safe(asp, asp2, &inst->asp_list, list)
		osmo_ss7_asp_destroy(asp);

	llist_for_each_entry_safe(as, as2, &inst->as_list, list)
		osmo_ss7_as_destroy(as);

	llist_for_each_entry_safe(lset, lset2, &inst->linksets, list)
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

/*! \brief Destroy SS7 Link
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

	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);

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
	mask = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, mask);
	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);

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

	/* truncate mask to maximum.  Let's avoid callers specifying arbitrary large
	 * masks to ensure we don't fail duplicate detection with longer mask lengths */
	mask = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, mask);
	pc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, pc);

	OSMO_ASSERT(ss7_initialized);
	lset = osmo_ss7_linkset_find_by_name(rtbl->inst, linkset_name);
	if (!lset) {
		as = osmo_ss7_as_find_by_name(rtbl->inst, linkset_name);
		if (!as)
			return NULL;
	}

	/* check for duplicates */
	rt = osmo_ss7_route_find_dpc_mask(rtbl, pc, mask);
	if (rt && !strcmp(rt->cfg.linkset_name, linkset_name)) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Refusing to create duplicate route: "
			"pc=%u=%s mask=0x%x via linkset/AS '%s'\n",
			pc, osmo_ss7_pointcode_print(rtbl->inst, pc), mask, linkset_name);
		return rt;
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
	struct osmo_ss7_route_table *rtbl = rt->rtable;

	OSMO_ASSERT(ss7_initialized);

	LOGSS7(rtbl->inst, LOGL_INFO, "Destroying route: pc=%u=%s mask=0x%x via linkset/ASP '%s'\n",
	       rt->cfg.pc, osmo_ss7_pointcode_print(rtbl->inst, rt->cfg.pc), rt->cfg.mask, rt->cfg.linkset_name);

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

static const struct rate_ctr_desc ss7_as_rcd[] = {
	[SS7_AS_CTR_RX_MSU_TOTAL] = { "rx:msu:total", "Total number of MSU received" },
	[SS7_AS_CTR_TX_MSU_TOTAL] = { "tx:msu:total", "Total number of MSU transmitted" },
};

static const struct rate_ctr_group_desc ss7_as_rcgd = {
	.group_name_prefix = "sigtran_as",
	.group_description = "SIGTRAN Application Server",
	.num_ctr = ARRAY_SIZE(ss7_as_rcd),
	.ctr_desc = ss7_as_rcd,
};
static unsigned int g_ss7_as_rcg_idx;

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

/*! \brief Allocate an Application Server
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of Application Server
 *  \param[in] proto Protocol of Application Server
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *ss7_as_alloc(struct osmo_ss7_instance *inst, const char *name,
				 enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;

	as = talloc_zero(inst, struct osmo_ss7_as);
	if (!as)
		return NULL;
	as->ctrg = rate_ctr_group_alloc(as, &ss7_as_rcgd, g_ss7_as_rcg_idx++);
	if (!as->ctrg) {
		talloc_free(as);
		return NULL;
	}
	rate_ctr_group_set_name(as->ctrg, name);
	as->inst = inst;
	as->cfg.name = talloc_strdup(as, name);
	as->cfg.proto = proto;
	as->cfg.mode = OSMO_SS7_AS_TMOD_OVERRIDE;
	as->cfg.recovery_timeout_msec = 2000;
	as->cfg.routing_key.l_rk_id = find_free_l_rk_id(inst);
	as->fi = xua_as_fsm_start(as, LOGL_DEBUG);
	llist_add_tail(&as->list, &inst->as_list);

	return as;
}

/*! \brief Find or Create Application Server
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of Application Server
 *  \param[in] proto Protocol of Application Server
 *  \returns pointer to Application Server on success; NULL otherwise */
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
		as = ss7_as_alloc(inst, name, proto);
		if (!as)
			return NULL;
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
	rate_ctr_group_free(as->ctrg);
	talloc_free(as);
}

/*! \brief Determine if given AS contains ASP
 *  \param[in] as Application Server in which to look for \ref asp
 *  \param[in] asp Application Server Process to look for in \ref as
 *  \returns true in case \ref asp is part of \ref as; false otherwise */
bool osmo_ss7_as_has_asp(const struct osmo_ss7_as *as,
			 const struct osmo_ss7_asp *asp)
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

/*! Determine if given AS is in the down state.
 *  \param[in] as Application Server.
 *  \returns true in case as is down; false otherwise. */
bool osmo_ss7_as_down(const struct osmo_ss7_as *as)
{
	OSMO_ASSERT(as);

	if (!as->fi)
		return true;
	return as->fi->state == XUA_AS_S_DOWN;
}

bool ss7_ipv6_sctp_supported(const char *host, bool bind)
{
	int rc;
	struct addrinfo hints;
	struct addrinfo *result;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_protocol = 0; /* Any protocol */

	if (bind)  /* For wildcard IP address */
		hints.ai_flags |= AI_PASSIVE;

	/* man getaddrinfo: Either node or service, but not both, may be NULL. */
	OSMO_ASSERT(host);
	rc = getaddrinfo(host, NULL, &hints, &result);
	if (rc != 0) {
		LOGP(DLSS7, LOGL_NOTICE, "Default IPv6 address %s not supported: %s\n",
		     host, gai_strerror(rc));
		return false;
	}
	freeaddrinfo(result);
	return true;
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
osmo_ss7_asp_find(struct osmo_ss7_instance *inst, const char *name,
		  uint16_t remote_port, uint16_t local_port,
		  enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(inst, name);
	if (!asp)
		return NULL;

	if ((asp->cfg.remote.port != remote_port || asp->cfg.local.port != local_port || asp->cfg.proto != proto))
		return NULL;

	return asp;
}

struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			    uint16_t remote_port, uint16_t local_port,
			    enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(inst, name);
	if (asp) {
		if (asp->cfg.remote.port != remote_port ||
		    asp->cfg.local.port != local_port ||
		    asp->cfg.proto != proto)
			return NULL;
		return asp;
	}

	return ss7_asp_alloc(inst, name, remote_port, local_port, proto);
}

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
	int rc;

	if (ss7_initialized)
		return 1;
	rc = osmo_fsm_register(&sccp_scoc_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&xua_as_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&xua_asp_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&ipa_asp_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&xua_default_lm_fsm);
	if (rc < 0)
		return rc;

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
