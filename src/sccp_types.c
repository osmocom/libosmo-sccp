#include <osmocom/sccp/sccp_types.h>

/* Table 1/Q.713 - SCCP message types */
const struct value_string osmo_sccp_msg_type_names[] = {
	{ SCCP_MSG_TYPE_CR, "Connection request" },
	{ SCCP_MSG_TYPE_CC, "Connection confirm" },
	{ SCCP_MSG_TYPE_CREF, "Connection refused" },
	{ SCCP_MSG_TYPE_RLSD, "Released" },
	{ SCCP_MSG_TYPE_RLC, "Release complete" },
	{ SCCP_MSG_TYPE_DT1, "Data form 1" },
	{ SCCP_MSG_TYPE_DT2, "Data form 2" },
	{ SCCP_MSG_TYPE_AK, "Data acknowledgement" },
	{ SCCP_MSG_TYPE_UDT, "Unitdata" },
	{ SCCP_MSG_TYPE_UDTS, "Unitdata service" },
	{ SCCP_MSG_TYPE_ED, "Expedited data" },
	{ SCCP_MSG_TYPE_EA, "Expedited data acknowledgement" },
	{ SCCP_MSG_TYPE_RSR, "Reset request" },
	{ SCCP_MSG_TYPE_RSC, "Reset confirmation" },
	{ SCCP_MSG_TYPE_ERR, "Protocol data unit error" },
	{ SCCP_MSG_TYPE_IT, "Inactivity test" },
	{ SCCP_MSG_TYPE_XUDT, "Extended unitdata" },
	{ SCCP_MSG_TYPE_XUDTS, "Extended unitdata service" },
	{ SCCP_MSG_TYPE_LUDT, "Long unitdata" },
	{ SCCP_MSG_TYPE_LUDTS, "Long unitdata service" },
	{}
};
