/* RFC 3868 SUA SCCP User Adaption */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <stdint.h>

#include <osmocom/sigtran/protocol/m3ua.h>

#define SUA_VERSION	1
#define SUA_PPID	4
#define SUA_PORT 	14001

/* 3.1.2 Message Classes */
#define SUA_MSGC_MGMT	0
#define SUA_MSGC_SNM	2
#define SUA_MSGC_ASPSM	3
#define SUA_MSGC_ASPTM	4
#define SUA_MSGC_CL	7
#define SUA_MSGC_CO	8
#define SUA_MSGC_RKM	9

/* 3.1.3 Message Types */
#define SUA_MGMT_ERR	0
#define SUA_MGMT_NTFY	1

#define SUA_SNM_DUNA	1
#define SUA_SNM_DAVA	2
#define SUA_SNM_DAUD	3
#define SUA_SNM_SCON	4
#define SUA_SNM_DUPU	5
#define SUA_SNM_DRST	6

#define SUA_ASPSM_UP		1
#define SUA_ASPSM_DOWN		2
#define SUA_ASPSM_BEAT		3
#define SUA_ASPSM_UP_ACK 	4
#define SUA_ASPSM_DOWN_ACK	5
#define SUA_ASPSM_BEAT_ACK	6

#define SUA_ASPTM_ACTIVE	1
#define SUA_ASPTM_INACTIVE	2
#define SUA_ASPTM_ACTIVE_ACK	3
#define SUA_ASPTM_INACTIVE_ACK	4

#define SUA_RKM_REG_REQ		1
#define SUA_RKM_REG_RSP		2
#define SUA_RKM_DEREG_REQ	3
#define SUA_RKM_DEREG_RSP	4

#define SUA_CL_CLDT	 	1
#define SUA_CL_CLDR	 	2

#define SUA_CO_CORE		1
#define SUA_CO_COAK		2
#define SUA_CO_COREF		3
#define SUA_CO_RELRE		4
#define SUA_CO_RELCO		5
#define SUA_CO_RESCO		6
#define SUA_CO_RESRE		7
#define SUA_CO_CODT		8
#define SUA_CO_CODA		9
#define SUA_CO_COERR		10
#define SUA_CO_COIT		11 /* Connection Oriented Inactiviy Test */

#define SUA_IEI_INFO_STRING	M3UA_IEI_INFO_STRING
#define SUA_IEI_ROUTE_CTX	M3UA_IEI_ROUTE_CTX
#define SUA_IEI_DIAG_INFO	M3UA_IEI_DIAG_INFO
#define SUA_IEI_HEARTBT_DATA	M3UA_IEI_HEARDBT_DATA
#define SUA_IEI_TRAF_MODE_TYP	M3UA_IEI_TRAF_MODE_TYP
#define SUA_IEI_ERR_CODE	M3UA_IEI_ERR_CODE
#define SUA_IEI_STATUS		M3UA_IEI_STATUS
#define SUA_IEI_ASP_ID		M3UA_IEI_ASP_ID
#define SUA_IEI_AFFECTED_PC	M3UA_IEI_AFFECTED_PC
#define SUA_IEI_CORR_ID		M3UA_IEI_CORR_ID
#define SUA_IEI_REG_RESULT	0x0014
#define SUA_IEI_DEREG_RESULT	0x0015

/* 3.10 SUA specific parameters */

#define SUA_IEI_S7_HOP_CTR	0x0101
#define SUA_IEI_SRC_ADDR	0x0102
#define SUA_IEI_DEST_ADDR	0x0103
#define SUA_IEI_SRC_REF		0x0104
#define SUA_IEI_DEST_REF	0x0105
#define SUA_IEI_CAUSE		0x0106
#define SUA_IEI_SEQ_NR		0x0107
#define SUA_IEI_RX_SEQ_NR	0x0108
#define SUA_IEI_ASP_CAPA	0x0109
#define SUA_IEI_CREDIT		0x010A
#define SUA_IEI_DATA		0x010B
#define SUA_IEI_USER_CAUSE	0x010C
#define SUA_IEI_NET_APPEARANCE	0x010D
#define SUA_IEI_ROUTING_KEY	0x010E
#define SUA_IEI_DRN		0x010F
#define SUA_IEI_TID		0x0110
#define SUA_IEI_SMI		0x0112
#define SUA_IEI_IMPORTANCE	0x0113
#define SUA_IEI_MSG_PRIO	0x0114
#define SUA_IEI_PROTO_CLASS	0x0115
#define SUA_IEI_SEQ_CTRL	0x0116
#define SUA_IEI_SEGMENTATION	0x0117
#define SUA_IEI_CONG_LEVEL	0x0118

#define SUA_IEI_GT	0x8001
#define SUA_IEI_PC	0x8002
#define SUA_IEI_SSN	0x8003
#define SUA_IEI_IPv4	0x8004
#define SUA_IEI_HOST	0x8005
#define SUA_IEI_IPv6	0x8006

#define SUA_RI_GT	1
#define SUA_RI_SSN_PC	2
#define SUA_RI_HOST	3
#define SUA_RI_SSN_IP	4

#define SUA_CAUSE_T_MASK	0xff00
#define SUA_CAUSE_T_RETURN	0x0100
#define SUA_CAUSE_T_REFUSAL	0x0200
#define SUA_CAUSE_T_RELEASE	0x0300
#define SUA_CAUSE_T_RESET	0x0400
#define SUA_CAUSE_T_ERROR	0x0500

/* 3.9.12 Error: Identical to M3UA, extended by two at the bottom */
#define SUA_ERR_INVALID_VERSION		M3UA_ERR_INVALID_VERSION
#define SUA_ERR_UNSUPP_MSG_CLASS	M3UA_ERR_UNSUPP_MSG_CLASS
#define SUA_ERR_UNSUPP_MSG_TYPE		M3UA_ERR_UNSUPP_MSG_TYPE
#define SUA_ERR_UNSUPP_TRAF_MOD_TYP	M3UA_ERR_UNSUPP_TRAF_MOD_TYP
#define SUA_ERR_UNEXPECTED_MSG		M3UA_ERR_UNEXPECTED_MSG
#define SUA_ERR_PROTOCOL_ERR		M3UA_ERR_PROTOCOL_ERR
#define SUA_ERR_INVAL_STREAM_ID		M3UA_ERR_INVAL_STREAM_ID
#define SUA_ERR_REFUSED_MGMT_BLOCKING	M3UA_ERR_REFUSED_MGMT_BLOCKING
#define SUA_ERR_ASP_ID_REQD		M3UA_ERR_ASP_ID_REQD
#define SUA_ERR_INVAL_ASP_ID		M3UA_ERR_INVAL_ASP_ID
#define SUA_ERR_INVAL_PARAM_VAL		M3UA_ERR_INVAL_PARAM_VAL
#define SUA_ERR_PARAM_FIELD_ERR		M3UA_ERR_PARAM_FIELD_ERR
#define SUA_ERR_UNEXP_PARAM		M3UA_ERR_UNEXP_PARAM
#define SUA_ERR_DEST_STATUS_UNKN	M3UA_ERR_DEST_STATUS_UNKN
#define SUA_ERR_INVAL_NET_APPEAR	M3UA_ERR_INVAL_NET_APPEAR
#define SUA_ERR_MISSING_PARAM		M3UA_ERR_MISSING_PARAM
#define SUA_ERR_INVAL_ROUT_CTX		M3UA_ERR_INVAL_ROUT_CTX
#define SUA_ERR_NO_CONFGD_AS_FOR_ASP	M3UA_ERR_NO_CONFGD_AS_FOR_ASP
#define SUA_ERR_SUBSYS_STATUS_UNKN	0x1b
#define SUA_ERR_INVAL_LOADSH_LEVEL	0x1c
