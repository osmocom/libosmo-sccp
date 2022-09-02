#pragma once

/**
 * Types found in the M2PA RFC 4165
 */

#include <stdint.h>
#include <osmocom/sigtran/xua_types.h>

/* Section 2.1.1 */
#define M2PA_VERSION	1

/* Section 2.1.2 */
#define M2PA_SPARE	0

/* Section 2.1.3 */
#define M2PA_CLS_M2PA	11

/* Section 2.1.4 */
#define M2PA_MSGT_USER_DATA	1
#define M2PA_MSGT_LINK_STATUS	2

/* Section 2.2 */
struct m2pa_specific_header {
	uint32_t	bsn;	/* only lower 24 bits used */
	uint32_t	fsn;	/* only lower 24 bits used */
} __attribute__ ((packed));

/* Section 2.1 + 2.2 */
struct m2pa_header {
	struct xua_common_header 	common;
	struct m2pa_secific_header	m2pa;
	uint8_t				data[0];
} __attribute__ ((packed));


/* Section 2.3.2 */
enum m2pa_link_status {
	M2PA_LSTS_ALIGNMENT		= 1,
	M2PA_LSTS_PROVING_NORMAL	= 2,
	M2PA_LSTS_PROVING_EMERGENCY	= 3,
	M2PA_LSTS_READY			= 4,
	M2PA_LSTS_PROCESSOR_OUTAGE	= 5,
	M2PA_LSTS_PROCESSOR_RECOVERED	= 6,
	M2PA_LSTS_BUSY			= 7,
	M2PA_LSTS_BUSY_ENDED		= 8,
	M2PA_LSTS_OUT_OF_SERVICE	= 9,
};
