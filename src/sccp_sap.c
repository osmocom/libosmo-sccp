/* SCCP User SAP related routines */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
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
 */

#include <string.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/prim.h>

#include <osmocom/sigtran/sccp_sap.h>

const struct value_string osmo_scu_prim_names[] = {
	{ OSMO_SCU_PRIM_N_CONNECT,		"N-CONNECT" },
	{ OSMO_SCU_PRIM_N_DATA,			"N-DATA" },
	{ OSMO_SCU_PRIM_N_EXPEDITED_DATA,	"N-EXPEDITED-DATA" },
	{ OSMO_SCU_PRIM_N_DISCONNECT,		"N-DISCONNECT" },
	{ OSMO_SCU_PRIM_N_RESET,		"N-RESET" },
	{ OSMO_SCU_PRIM_N_INFORM,		"N-INFORM" },
	{ OSMO_SCU_PRIM_N_UNITDATA,		"N-UNITDATA" },
	{ OSMO_SCU_PRIM_N_NOTICE,		"N-NOTICE" },
	/* management */
	{ OSMO_SCU_PRIM_N_COORD,		"N-COORD" },
	{ OSMO_SCU_PRIM_N_STATE,		"N-STATE" },
	{ OSMO_SCU_PRIM_N_PCSTATE,		"N-PCSATE" },
	{ 0, NULL }
};

static char prim_name_buf[128];

char *osmo_scu_prim_name(struct osmo_prim_hdr *oph)
{
	const char *name = get_value_string(osmo_scu_prim_names, oph->primitive);

	snprintf(prim_name_buf, sizeof(prim_name_buf), "%s.%s", name,
		 get_value_string(osmo_prim_op_names, oph->operation));

	return prim_name_buf;
}


#include <osmocom/sigtran/sigtran_sap.h>

const struct value_string osmo_xlm_prim_names[] = {
	{ OSMO_XLM_PRIM_M_SCTP_ESTABLISH,	"M-SCTP_ESTABLISH" },
	{ OSMO_XLM_PRIM_M_SCTP_RELEASE,		"M-SCTP_RELEASE" },
	{ OSMO_XLM_PRIM_M_SCTP_RESTART,		"M-SCTP_RESTART" },
	{ OSMO_XLM_PRIM_M_SCTP_STATUS,		"M-SCTP_STATUS" },
	{ OSMO_XLM_PRIM_M_ASP_STATUS,		"M-ASP_STATUS" },
	{ OSMO_XLM_PRIM_M_AS_STATUS,		"M-AS_STATUS" },
	{ OSMO_XLM_PRIM_M_NOTIFY,		"M-NOTIFY" },
	{ OSMO_XLM_PRIM_M_ERROR,		"M-ERROR" },
	{ OSMO_XLM_PRIM_M_ASP_UP,		"M-ASP_UP" },
	{ OSMO_XLM_PRIM_M_ASP_DOWN,		"M-ASP_DOWN" },
	{ OSMO_XLM_PRIM_M_ASP_ACTIVE,		"M-ASP_ACTIVE" },
	{ OSMO_XLM_PRIM_M_ASP_INACTIVE,		"M-ASP_INACTIVE" },
	{ OSMO_XLM_PRIM_M_AS_ACTIVE,		"M-AS_ACTIVE" },
	{ OSMO_XLM_PRIM_M_AS_INACTIVE,		"M-AS_INACTIVE" },
	{ OSMO_XLM_PRIM_M_AS_DOWN,		"M-AS_DOWN" },
	/* optional as per spec, not implemented yet */
	{ OSMO_XLM_PRIM_M_RK_REG,		"M-RK_REG" },
	{ OSMO_XLM_PRIM_M_RK_DEREG,		"M-RK_DEREG" },
	{ 0, NULL },
};

char *osmo_xlm_prim_name(struct osmo_prim_hdr *oph)
{
	const char *name = get_value_string(osmo_xlm_prim_names, oph->primitive);

	snprintf(prim_name_buf, sizeof(prim_name_buf), "%s.%s", name,
		 get_value_string(osmo_prim_op_names, oph->operation));

	return prim_name_buf;
}

const struct value_string osmo_sccp_routing_ind_names[] = {
	{ OSMO_SCCP_RI_NONE,	"NONE" },
	{ OSMO_SCCP_RI_GT,	"GT" },
	{ OSMO_SCCP_RI_SSN_PC,	"SSN_PC" },
	{ OSMO_SCCP_RI_SSN_IP,	"SSN_IP" },
	{ 0, NULL }
};

const struct value_string osmo_sccp_gti_names[] = {
	{ OSMO_SCCP_GTI_NO_GT,		"NO_GT" },
	{ OSMO_SCCP_GTI_NAI_ONLY,	"NAI_ONLY" },
	{ OSMO_SCCP_GTI_TT_ONLY,	"TT_ONLY" },
	{ OSMO_SCCP_GTI_TT_NPL_ENC,	"TT_NPL_ENC" },
	{ OSMO_SCCP_GTI_TT_NPL_ENC_NAI,	"TT_NPL_ENC_NAI" },
	{ 0, NULL }
};

const struct value_string osmo_sccp_ssn_names[] = {
	{ OSMO_SCCP_SSN_MGMT,		"MGMT" },
	{ OSMO_SCCP_SSN_ISUP,		"ISUP" },
	{ OSMO_SCCP_SSN_OMAP,		"OMAP" },
	{ OSMO_SCCP_SSN_MAP,		"MAP" },
	{ OSMO_SCCP_SSN_HLR,		"HLR" },
	{ OSMO_SCCP_SSN_VLR,		"VLR" },
	{ OSMO_SCCP_SSN_MSC,		"MSC" },
	{ OSMO_SCCP_SSN_EIR,		"EIR" },
	{ OSMO_SCCP_SSN_AUC,		"AUC" },
	{ OSMO_SCCP_SSN_ISDN_SS,	"ISDN_SS" },
	{ OSMO_SCCP_SSN_RES_INTL,	"RES_INTL" },
	{ OSMO_SCCP_SSN_BISDN,		"BISDN" },
	{ OSMO_SCCP_SSN_TC_TEST,	"TC_TEST" },
	{ OSMO_SCCP_SSN_RANAP,		"RANAP" },
	{ OSMO_SCCP_SSN_RNSAP,		"RNSAP" },
	{ OSMO_SCCP_SSN_GMLC_MAP,	"GMLC_MAP" },
	{ OSMO_SCCP_SSN_CAP,		"CAP" },
	{ OSMO_SCCP_SSN_gsmSCF_MAP,	"gsmSCF_MAP" },
	{ OSMO_SCCP_SSN_SIWF_MAP,	"SIWF_MAP" },
	{ OSMO_SCCP_SSN_SGSN_MAP,	"SGSN_MAP" },
	{ OSMO_SCCP_SSN_GGSN_MAP,	"GGSN_MAP" },
	{ OSMO_SCCP_SSN_PCAP,		"PCAP" },
	{ OSMO_SCCP_SSN_BSC_BSSAP_LE,	"BSC_BSSAP_LE" },
	{ OSMO_SCCP_SSN_MSC_BSSAP_LE,	"MSC_BSSAP_LE" },
	{ OSMO_SCCP_SSN_SMLC_BSSAP,	"SMLC_BSSAP" },
	{ OSMO_SCCP_SSN_BSS_OAM,	"BSS_OAM" },
	{ OSMO_SCCP_SSN_BSSAP,		"BSSAP" },
	{ 0, NULL }
};
