#pragma once

/* SCCP Management as per Section 5.3 of ITU-T Q.713 */

enum sccp_scmg_msg_type {
	SCCP_SCMG_MSGT_SSA	= 0x01,	/* Subsystem Allowed */
	SCCP_SCMG_MSGT_SSP	= 0x02,	/* Subsystem Prohibited */
	SCCP_SCMG_MSGT_SST	= 0x03,	/* Subsystem Status Test */
	SCCP_SCMG_MSGT_SOR	= 0x04,	/* Subsystem Out-of-service Request */
	SCCP_SCMG_MSGT_SOG	= 0x05,	/* Subsystem Out-of-service Grant */
	SCCP_SCMG_MSGT_SSC	= 0x06,	/* Subsystem Congested */
};

struct sccp_scmg_msg {
	uint8_t msg_type;	/* enum sccp_scmg_msg_type */
	uint8_t affected_ssn;
	uint16_t affected_pc;
	uint8_t smi;
	/* one octet, only in case of SSC */
	uint8_t ssc_congestion_lvl[0];
} __attribute__ ((packed));

extern const struct value_string sccp_scmg_msgt_names[];
static inline const char *sccp_scmg_msgt_name(enum sccp_scmg_msg_type msgt)
{ return get_value_string(sccp_scmg_msgt_names, msgt); }
