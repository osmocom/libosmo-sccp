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

/* Table 2/Q.713 - SCCP parameter name codes */
const struct value_string osmo_sccp_pnc_names[] = {
	{ SCCP_PNC_END_OF_OPTIONAL, "End of optional parameters" },
	{ SCCP_PNC_DESTINATION_LOCAL_REFERENCE, "Destination local reference" },
	{ SCCP_PNC_SOURCE_LOCAL_REFERENCE, "Source local reference" },
	{ SCCP_PNC_CALLED_PARTY_ADDRESS, "Called party address" },
	{ SCCP_PNC_CALLING_PARTY_ADDRESS, "Calling party address" },
	{ SCCP_PNC_PROTOCOL_CLASS, "Protocol class" },
	{ SCCP_PNC_SEGMENTING, "Segmenting/reassembling" },
	{ SCCP_PNC_RECEIVE_SEQ_NUMBER, "Receive sequence number" },
	{ SCCP_PNC_SEQUENCING, "Sequencing/segmenting" },
	{ SCCP_PNC_CREDIT, "Credit" },
	{ SCCP_PNC_RELEASE_CAUSE, "Release cause" },
	{ SCCP_PNC_RETURN_CAUSE, "Return cause" },
	{ SCCP_PNC_RESET_CAUSE, "Reset cause" },
	{ SCCP_PNC_ERROR_CAUSE, "Error cause" },
	{ SCCP_PNC_REFUSAL_CAUSE, "Refusal cause" },
	{ SCCP_PNC_DATA, "Data" },
	{ SCCP_PNC_SEGMENTATION, "Segmentation" },
	{ SCCP_PNC_HOP_COUNTER, "Hop counter" },
	{ SCCP_PNC_IMPORTANCE, "Importance" },
	{ SCCP_PNC_LONG_DATA, "Long data" },
	{}
};
