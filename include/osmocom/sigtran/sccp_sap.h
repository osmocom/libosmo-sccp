#pragma once

/* SCCP User SAP description */

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
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/sigtran_sap.h>

#include <netinet/in.h>

/* detailed coding of primitives at the SAP_SCCP_USER */

/*! \brief SCCP-User primitives as per Q.711 */
enum osmo_scu_prim_type {
	/* connection oriented, 6.1.1 */
	OSMO_SCU_PRIM_N_CONNECT,
	OSMO_SCU_PRIM_N_DATA,
	OSMO_SCU_PRIM_N_EXPEDITED_DATA,
	OSMO_SCU_PRIM_N_DISCONNECT,
	OSMO_SCU_PRIM_N_RESET,
	OSMO_SCU_PRIM_N_INFORM,
	/* connectionless, 6.2.2 */
	OSMO_SCU_PRIM_N_UNITDATA,
	OSMO_SCU_PRIM_N_NOTICE,
	/* management */
	OSMO_SCU_PRIM_N_COORD,
	OSMO_SCU_PRIM_N_STATE,
	OSMO_SCU_PRIM_N_PCSTATE,
};

#define OSMO_SCCP_ADDR_T_GT	0x0001 /* global title */
#define OSMO_SCCP_ADDR_T_PC	0x0002 /* signalling point code */
#define OSMO_SCCP_ADDR_T_SSN	0x0004 /* subsystem number */
#define OSMO_SCCP_ADDR_T_IPv4	0x0008
#define OSMO_SCCP_ADDR_T_IPv6	0x0010

/* Q.713 3.4.1 + RFC 3868 3.10.2.3 */
enum osmo_sccp_routing_ind {
	OSMO_SCCP_RI_NONE,
	OSMO_SCCP_RI_GT,
	OSMO_SCCP_RI_SSN_PC,
	OSMO_SCCP_RI_SSN_IP,
};

extern const struct value_string osmo_sccp_routing_ind_names[];
static inline const char *osmo_sccp_routing_ind_name(enum osmo_sccp_routing_ind val)
{ return get_value_string(osmo_sccp_routing_ind_names, val); }


/* Q.713 3.4.1 + RFC 3868 3.10.2.3 */
enum osmo_sccp_gti {
	OSMO_SCCP_GTI_NO_GT,
	OSMO_SCCP_GTI_NAI_ONLY,
	OSMO_SCCP_GTI_TT_ONLY,
	OSMO_SCCP_GTI_TT_NPL_ENC,
	OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
};

extern const struct value_string osmo_sccp_gti_names[];
static inline const char *osmo_sccp_gti_name(enum osmo_sccp_gti val)
{ return get_value_string(osmo_sccp_gti_names, val); }

/* RFC 3868 3.10.2.3 */
enum osmo_sccp_npi {
	OSMO_SCCP_NPI_UNKNOWN = 0,
	OSMO_SCCP_NPI_E164_ISDN		= 1,
	OSMO_SCCP_NPI_GEERIC		= 2,
	OSMO_SCCP_NPI_X121_DATA		= 3,
	OSMO_SCCP_NPI_F69_TELEX		= 4,
	OSMO_SCCP_NPI_E210_MARITIME	= 5,
	OSMO_SCCP_NPI_E212_LAND		= 6,
	OSMO_SCCP_NPI_E214_ISDN_MOBILE	= 7,
	OSMO_SCCP_NPI_PRIVATE		= 14,
};

/* Q.713 3.4.2.3.1 + RFC 3868 3.10.2.3 */
enum osmo_sccp_nai {
	OSMO_SCCP_NAI_UNKNOWN		= 0,
	OSMO_SCCP_NAI_SUBSCR		= 1,
	OSMO_SCCP_NAI_RES_NAT_USE	= 2,
	OSMO_SCCP_NAI_NATL		= 3,
	OSMO_SCCP_NAI_INTL		= 4,
	/* 5.. 255: Spare */
};

/* Q.713 3.4.2.2 */
enum osmo_sccp_ssn {
	/* globally standardised for GSM/UMTS: 1-31 */
	OSMO_SCCP_SSN_MGMT		= 1,
	OSMO_SCCP_SSN_ISUP		= 3,
	OSMO_SCCP_SSN_OMAP		= 4,
	OSMO_SCCP_SSN_MAP		= 5,
	OSMO_SCCP_SSN_HLR		= 6,
	OSMO_SCCP_SSN_VLR		= 7,
	OSMO_SCCP_SSN_MSC		= 8,
	OSMO_SCCP_SSN_EIR		= 9,
	OSMO_SCCP_SSN_AUC		= 0x0a,
	/* Q.713 */
	OSMO_SCCP_SSN_ISDN_SS		= 0x0b,
	OSMO_SCCP_SSN_RES_INTL		= 0x0c,
	OSMO_SCCP_SSN_BISDN		= 0x0d,
	OSMO_SCCP_SSN_TC_TEST		= 0x0e,
	/* national network SSN for wihin and between GSM/UMTS: 129-150 */
	OSMO_SCCP_SSN_RANAP		= 142,
	OSMO_SCCP_SSN_RNSAP		= 143,
	OSMO_SCCP_SSN_GMLC_MAP		= 145,
	OSMO_SCCP_SSN_CAP		= 146,
	OSMO_SCCP_SSN_gsmSCF_MAP	= 147,
	OSMO_SCCP_SSN_SIWF_MAP		= 148,
	OSMO_SCCP_SSN_SGSN_MAP		= 149,
	OSMO_SCCP_SSN_GGSN_MAP		= 150,
	/* national network SSN within GSM/UMTS: 32-128 + 151-254 */
	OSMO_SCCP_SSN_PCAP		= 249,
	OSMO_SCCP_SSN_BSC_BSSAP		= 250,
	OSMO_SCCP_SSN_MSC_BSSAP		= 251,
	OSMO_SCCP_SSN_SMLC_BSSAP	= 252,
	OSMO_SCCP_SSN_BSS_OAM		= 253,
};

extern const struct value_string osmo_sccp_ssn_names[];
static inline const char *osmo_sccp_ssn_name(enum osmo_sccp_ssn val)
{ return get_value_string(osmo_sccp_ssn_names, val); }

struct osmo_sccp_gt {
	uint8_t gti;
	uint8_t tt;
	uint32_t npi;
	uint32_t nai;
	char digits[32];
};

struct osmo_sccp_addr {
	uint32_t presence;
	enum osmo_sccp_routing_ind ri;
	struct osmo_sccp_gt gt;
	uint32_t pc;
	uint32_t ssn;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
	/* we don't do hostnames */
};

/* OSMO_SCU_PRIM_N_CONNECT */
struct osmo_scu_connect_param {
	struct osmo_sccp_addr called_addr;
	struct osmo_sccp_addr calling_addr;
	struct osmo_sccp_addr responding_addr;
	//struct osmo_sccp_qos_pars qos_pars;
	uint32_t sccp_class;
	uint32_t importance;
	uint32_t conn_id;
	/* user data */
};

/* OSMO_SCU_PRIM_N_DATA / OSMO_SCU_PRIM_N_EXPEDITED_DATA */
struct osmo_scu_data_param {
	uint32_t conn_id;
	uint32_t importance;
	/* user data */
};

enum osmo_sccp_originator {
	OSMO_SCCP_ORIG_NS_PROVIDER,
	OSMO_SCCP_ORIG_NS_USER,
	OSMO_SCCP_ORIG_UNDEFINED,
};

/* OSMO_SCU_PRIM_N_DISCONNECT */
struct osmo_scu_disconn_param {
	enum osmo_sccp_originator originator;
	struct osmo_sccp_addr responding_addr;
	uint32_t cause;
	uint32_t conn_id;
	uint32_t importance;
	/* user data */
};

/* OSMO_SCU_PRIM_N_RESET */
struct osmo_scu_reset_param {
	enum osmo_sccp_originator originator;
	uint32_t cause;
	uint32_t conn_id;
};

/* OSMO_SCU_PRIM_N_UNITDATA */
struct osmo_scu_unitdata_param {
	struct osmo_sccp_addr called_addr;
	struct osmo_sccp_addr calling_addr;
	uint32_t in_sequence_control;
	uint32_t return_option;
	uint32_t importance;
	/* user data */
};

/* OSMO_SCU_PRIM_N_NOTICE */
struct osmo_scu_notice_param {
	struct osmo_sccp_addr called_addr;
	struct osmo_sccp_addr calling_addr;
	uint32_t cause;
	uint32_t importance;
	/* user data */
};

struct osmo_scu_prim {
	struct osmo_prim_hdr oph;
	union {
		struct osmo_scu_connect_param connect;
		struct osmo_scu_data_param data;
		struct osmo_scu_disconn_param disconnect;
		struct osmo_scu_reset_param reset;
		struct osmo_scu_unitdata_param unitdata;
		struct osmo_scu_notice_param notice;
	} u;
};

#define msgb_scu_prim(msg) ((struct osmo_scu_prim *)(msg)->l1h)

char *osmo_scu_prim_name(struct osmo_prim_hdr *oph);

struct osmo_ss7_instance;
struct osmo_sccp_instance;
struct osmo_sccp_user;

void osmo_sccp_vty_init(void);

struct osmo_sccp_instance *
osmo_sccp_instance_create(struct osmo_ss7_instance *ss7, void *priv);
void osmo_sccp_instance_destroy(struct osmo_sccp_instance *inst);
struct osmo_ss7_instance *osmo_sccp_get_ss7(struct osmo_sccp_instance *sccp);

void osmo_sccp_user_unbind(struct osmo_sccp_user *scu);
void osmo_sccp_user_set_priv(struct osmo_sccp_user *scu, void *priv);
void *osmo_sccp_user_get_priv(struct osmo_sccp_user *scu);

struct osmo_sccp_user *
osmo_sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		       osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc);

struct osmo_sccp_user *
osmo_sccp_user_bind(struct osmo_sccp_instance *inst, const char *name,
		    osmo_prim_cb prim_cb, uint16_t ssn);

int osmo_sccp_user_sap_down(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph);

struct osmo_ss7_instance *
osmo_sccp_addr_by_name(struct osmo_sccp_addr *dest_addr,
		       const char *name);

const char *osmo_sccp_name_by_addr(const struct osmo_sccp_addr *addr);

void osmo_sccp_local_addr_by_instance(struct osmo_sccp_addr *dest_addr,
				      const struct osmo_sccp_instance *inst,
				      uint32_t ssn);

bool osmo_sccp_check_addr(struct osmo_sccp_addr *addr, uint32_t presence);
