#pragma once

#include <osmocom/core/utils.h>

/* Chapter 15.17.4 of Q.704 + RFC4666 3.4.5. */
/* Section 5.1 of ETSI EG 201 693: MTP SI code allocations (for NI= 00) */
enum mtp_si_ni00 {
	MTP_SI_SNM	= 0,
	MTP_SI_STM	= 1,
	MTP_SI_SCCP	= 3,
	MTP_SI_TUP	= 4,
	MTP_SI_ISUP	= 5,
	MTP_SI_DUP	= 6, /* call related */
	MTP_SI_DUP_FAC	= 7, /* facility related */
	MTP_SI_TESTING	= 8,
	MTP_SI_B_ISUP	= 9,
	MTP_SI_SAT_ISUP = 10,
	MTP_SI_SPEECH	= 11, /* speech processing element */
	MTP_SI_AAL2_SIG	= 12,
	MTP_SI_BICC	= 13,
	MTP_SI_GCP	= 14,
};

extern const struct value_string mtp_si_vals[];


/* Chapter 15.17.5 of Q.705 */
enum mtp_unavail_cause {
	MTP_UNAVAIL_C_UNKNOWN		= 0x0,
	MTP_UNAVAIL_C_UNEQUIP_REM_USER	= 0x1,
	MTP_UNAVAIL_C_INACC_REM_USER	= 0x2,
	/* reserved */
};

extern const struct value_string mtp_unavail_cause_vals[];

static inline const char *mtp_unavail_cause_str(enum mtp_unavail_cause cs) {
	return get_value_string(mtp_unavail_cause_vals, cs);
}
