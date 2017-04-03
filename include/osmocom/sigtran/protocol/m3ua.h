/* RFC 4666 M3UA SCCP User Adaption */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <stdint.h>

#define M3UA_VERSION	1
#define M3UA_PPID	3
#define M3UA_PORT	2905

/* 3.1.2 Message Classes */
#define M3UA_MSGC_MGMT	0
#define M3UA_MSGC_XFER	1
#define M3UA_MSGC_SNM	2
#define M3UA_MSGC_ASPSM	3
#define M3UA_MSGC_ASPTM	4
#define M3UA_MSGC_RKM	9

/* 3.1.3 Message Types */
#define M3UA_MGMT_ERR	0
#define M3UA_MGMT_NTFY	1

#define M3UA_XFER_DATA	1

#define M3UA_SNM_DUNA	1
#define M3UA_SNM_DAVA	2
#define M3UA_SNM_DAUD	3
#define M3UA_SNM_SCON	4
#define M3UA_SNM_DUPU	5
#define M3UA_SNM_DRST	6

#define M3UA_ASPSM_UP		1
#define M3UA_ASPSM_DOWN		2
#define M3UA_ASPSM_BEAT		3
#define M3UA_ASPSM_UP_ACK 	4
#define M3UA_ASPSM_DOWN_ACK	5
#define M3UA_ASPSM_BEAT_ACK	6

#define M3UA_ASPTM_ACTIVE	1
#define M3UA_ASPTM_INACTIVE	2
#define M3UA_ASPTM_ACTIVE_ACK	3
#define M3UA_ASPTM_INACTIVE_ACK	4

#define M3UA_RKM_REG_REQ	1
#define M3UA_RKM_REG_RSP	2
#define M3UA_RKM_DEREG_REQ	3
#define M3UA_RKM_DEREG_RSP	4

#define M3UA_IEI_INFO_STRING	0x0004
#define M3UA_IEI_ROUTE_CTX	0x0006
#define M3UA_IEI_DIAG_INFO	0x0007
#define M3UA_IEI_HEARDBT_DATA	0x0009
#define M3UA_IEI_TRAF_MODE_TYP	0x000b
#define M3UA_IEI_ERR_CODE	0x000c
#define M3UA_IEI_STATUS		0x000d
#define M3UA_IEI_ASP_ID		0x0011
#define M3UA_IEI_AFFECTED_PC	0x0012
#define M3UA_IEI_CORR_ID	0x0013

/* 3.2 M3UA specific parameters */

#define M3UA_IEI_NET_APPEAR	0x0200
#define M3UA_IEI_USER_CAUSE	0x0204
#define M3UA_IEI_CONG_IND	0x0205
#define M3UA_IEI_CONC_DEST	0x0206
#define M3UA_IEI_ROUT_KEY	0x0207
#define M3UA_IEI_REG_RESULT	0x0208
#define M3UA_IEI_DEREG_RESULT	0x0209
#define M3UA_IEI_LOC_RKEY_ID	0x020a
#define M3UA_IEI_DEST_PC	0x020b
#define M3UA_IEI_SVC_IND	0x020c
#define M3UA_IEI_ORIG_PC	0x020e
#define M3UA_IEI_PROT_DATA	0x0210
#define M3UA_IEI_REG_STATUS	0x0212
#define M3UA_IEI_DEREG_STATUS	0x0213

/* 3.3.1 Payload Data Message */
struct m3ua_data_hdr {
	uint32_t opc;	/* Originating Point Code */
	uint32_t dpc;	/* Destination Point Code */
	uint8_t si;	/* Service Indicator */
	uint8_t ni;	/* Network Indicator */
	uint8_t mp;	/* Message Priority */
	uint8_t sls;	/* Signalling Link Selection */
} __attribute__ ((packed));

/* 3.8.2 Notify */

#define M3UA_NOTIFY(type, info)	((info) << 16 | (type))
#define M3UA_NOTIFY_T_STATCHG	1
#define M3UA_NOTIFY_T_OTHER	2

#define M3UA_NOTIFY_I_RESERVED	1
#define M3UA_NOTIFY_I_AS_INACT	2
#define M3UA_NOTIFY_I_AS_ACT	3
#define M3UA_NOTIFY_I_AS_PEND	4

#define M3UA_NOTIFY_I_OT_INS_RES	1
#define M3UA_NOTIFY_I_OT_ALT_ASP_ACT	2
#define M3UA_NOTIFY_I_OT_ASP_FAILURE	3

/* 3.8.1 Error */
enum m3ua_error_code {
	M3UA_ERR_INVALID_VERSION	= 0x01,
	/* not used in M3UA */
	M3UA_ERR_UNSUPP_MSG_CLASS	= 0x03,
	M3UA_ERR_UNSUPP_MSG_TYPE	= 0x04,
	M3UA_ERR_UNSUPP_TRAF_MOD_TYP	= 0x05,
	M3UA_ERR_UNEXPECTED_MSG		= 0x06,
	M3UA_ERR_PROTOCOL_ERR		= 0x07,
	/* not used in M3UA */
	M3UA_ERR_INVAL_STREAM_ID	= 0x09,
	/* not used in M3UA */
	/* not used in M3UA */
	/* not used in M3UA */
	M3UA_ERR_REFUSED_MGMT_BLOCKING	= 0x0d,
	M3UA_ERR_ASP_ID_REQD		= 0x0e,
	M3UA_ERR_INVAL_ASP_ID		= 0x0f,
	/* not used in M3UA */
	M3UA_ERR_INVAL_PARAM_VAL	= 0x11,
	M3UA_ERR_PARAM_FIELD_ERR	= 0x12,
	M3UA_ERR_UNEXP_PARAM		= 0x13,
	M3UA_ERR_DEST_STATUS_UNKN	= 0x14,
	M3UA_ERR_INVAL_NET_APPEAR	= 0x15,
	M3UA_ERR_MISSING_PARAM		= 0x16,
	/* not used in M3UA */
	/* not used in M3UA */
	M3UA_ERR_INVAL_ROUT_CTX		= 0x19,
	M3UA_ERR_NO_CONFGD_AS_FOR_ASP	= 0x1a,
};
