#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/prim.h>

extern struct llist_head osmo_ss7_instances;

struct osmo_ss7_instance;
struct osmo_ss7_user;
struct osmo_sccp_instance;
struct osmo_mtp_prim;
struct osmo_xua_layer_manager;

int osmo_ss7_init(void);
int osmo_ss7_find_free_rctx(struct osmo_ss7_instance *inst);

bool osmo_ss7_pc_is_local(struct osmo_ss7_instance *inst, uint32_t pc);
int osmo_ss7_pointcode_parse(struct osmo_ss7_instance *inst, const char *str);
int osmo_ss7_pointcode_parse_mask_or_len(struct osmo_ss7_instance *inst, const char *in);
const char *osmo_ss7_pointcode_print(struct osmo_ss7_instance *inst, uint32_t pc);
const char *osmo_ss7_pointcode_print2(struct osmo_ss7_instance *inst, uint32_t pc);

/***********************************************************************
 * SS7 Routing Tables
 ***********************************************************************/

struct osmo_ss7_route_table {
	/*! member in list of routing tables */
	struct llist_head list;
	/*! \ref osmo_ss7_instance to which we belong */
	struct osmo_ss7_instance *inst;
	/*! list of \ref osmo_ss7_route */
	struct llist_head routes;

	struct {
		char *name;
		char *description;
	} cfg;
};

struct osmo_ss7_route_table *
osmo_ss7_route_table_find(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_route_table *
osmo_ss7_route_table_find_or_create(struct osmo_ss7_instance *inst, const char *name);
void osmo_ss7_route_table_destroy(struct osmo_ss7_route_table *rtbl);

/***********************************************************************
 * SS7 Instances
 ***********************************************************************/

struct osmo_ss7_pc_fmt {
	char delimiter;
	uint8_t component_len[3];
};

struct osmo_ss7_instance {
	/*! member of global list of instances */
	struct llist_head list;
	/*! list of \ref osmo_ss7_linkset */
	struct llist_head linksets;
	/*! list of \ref osmo_ss7_as */
	struct llist_head as_list;
	/*! list of \ref osmo_ss7_asp */
	struct llist_head asp_list;
	/*! list of \ref osmo_ss7_route_table */
	struct llist_head rtable_list;
	/*! list of \ref osmo_xua_servers */
	struct llist_head xua_servers;
	/* array for faster lookup of user (indexed by service
	 * indicator) */
	const struct osmo_ss7_user *user[16];

	struct osmo_ss7_route_table *rtable_system;

	struct osmo_sccp_instance *sccp;

	struct {
		uint32_t id;
		char *name;
		char *description;
		uint32_t primary_pc;
		/* secondary PCs */
		/* capability PCs */
		uint8_t network_indicator;
		struct osmo_ss7_pc_fmt pc_fmt;
		bool permit_dyn_rkm_alloc;
		struct llist_head sccp_address_book;
	} cfg;
};

struct osmo_ss7_instance *osmo_ss7_instance_find(uint32_t id);
struct osmo_ss7_instance *
osmo_ss7_instance_find_or_create(void *ctx, uint32_t id);
void osmo_ss7_instance_destroy(struct osmo_ss7_instance *inst);
int osmo_ss7_instance_set_pc_fmt(struct osmo_ss7_instance *inst,
				uint8_t c0, uint8_t c1, uint8_t c2);

/***********************************************************************
 * MTP Users (Users of MTP, such as SCCP or ISUP)
 ***********************************************************************/

struct osmo_ss7_user {
	/* pointer back to SS7 instance */
	struct osmo_ss7_instance *inst;
	/* name of the user */
	const char *name;
	/* primitive call-back for incoming MTP primitives */
	osmo_prim_cb prim_cb;
	/* private data */
	void *priv;
};

int osmo_ss7_user_register(struct osmo_ss7_instance *inst, uint8_t service_ind,
			   struct osmo_ss7_user *user);

int osmo_ss7_user_unregister(struct osmo_ss7_instance *inst, uint8_t service_ind,
			     struct osmo_ss7_user *user);

int osmo_ss7_mtp_to_user(struct osmo_ss7_instance *inst, struct osmo_mtp_prim *omp);

/* SS7 User wants to issue MTP-TRANSFER.req */
int osmo_ss7_user_mtp_xfer_req(struct osmo_ss7_instance *inst,
				struct osmo_mtp_prim *omp);

/***********************************************************************
 * SS7 Links
 ***********************************************************************/

enum osmo_ss7_link_adm_state {
	OSMO_SS7_LS_SHUTDOWN,
	OSMO_SS7_LS_INHIBITED,
	OSMO_SS7_LS_ENABLED,
	_NUM_OSMO_SS7_LS
};

struct osmo_ss7_linkset;
struct osmo_ss7_link;

struct osmo_ss7_link {
	/*! \ref osmo_ss7_linkset to which we belong */
	struct osmo_ss7_linkset *linkset;
	struct {
		char *name;
		char *description;
		uint32_t id;

		enum osmo_ss7_link_adm_state adm_state;
	} cfg;
};

void osmo_ss7_link_destroy(struct osmo_ss7_link *link);
struct osmo_ss7_link *
osmo_ss7_link_find_or_create(struct osmo_ss7_linkset *lset, uint32_t id);

/***********************************************************************
 * SS7 Linksets
 ***********************************************************************/

struct osmo_ss7_linkset {
	struct llist_head list;
	/*! \ref osmo_ss7_instance to which we belong */
	struct osmo_ss7_instance *inst;
	/*! array of \ref osmo_ss7_link */
	struct osmo_ss7_link *links[16];

	struct {
		char *name;
		char *description;
		uint32_t adjacent_pc;
		uint32_t local_pc;
	} cfg;
};

void osmo_ss7_linkset_destroy(struct osmo_ss7_linkset *lset);
struct osmo_ss7_linkset *
osmo_ss7_linkset_find_by_name(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_linkset *
osmo_ss7_linkset_find_or_create(struct osmo_ss7_instance *inst, const char *name, uint32_t pc);


/***********************************************************************
 * SS7 Routes
 ***********************************************************************/

struct osmo_ss7_route {
	/*! member in \ref osmo_ss7_route_table.routes */
	struct llist_head list;
	/*! \ref osmo_ss7_route_table to which we belong */
	struct osmo_ss7_route_table *rtable;

	struct {
		/*! pointer to linkset (destination) of route */
		struct osmo_ss7_linkset *linkset;
		/*! pointer to Application Server */
		struct osmo_ss7_as *as;
	} dest;

	struct {
		/* FIXME: presence? */
		uint32_t pc;
		uint32_t mask;
		/*! human-specified linkset name */
		char *linkset_name;
		/*! lower priority is higher */
		uint32_t priority;
		uint8_t qos_class;
	} cfg;
};

struct osmo_ss7_route *
osmo_ss7_route_find_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc);
struct osmo_ss7_route *
osmo_ss7_route_find_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			     uint32_t mask);
struct osmo_ss7_route *
osmo_ss7_route_lookup(struct osmo_ss7_instance *inst, uint32_t dpc);
struct osmo_ss7_route *
osmo_ss7_route_create(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			uint32_t mask, const char *linkset_name);
void osmo_ss7_route_destroy(struct osmo_ss7_route *rt);


/***********************************************************************
 * SS7 Application Servers
 ***********************************************************************/

struct osmo_ss7_routing_key {
	uint32_t context;
	uint32_t l_rk_id;

	uint32_t pc;
	uint8_t si;
	uint32_t ssn;
	/* FIXME: more complex routing keys */
};

enum osmo_ss7_as_traffic_mode {
	OSMO_SS7_AS_TMOD_OVERRIDE = 0,	/* default */
	OSMO_SS7_AS_TMOD_BCAST,
	OSMO_SS7_AS_TMOD_LOADSHARE,
	OSMO_SS7_AS_TMOD_ROUNDROBIN,
	_NUM_OSMO_SS7_ASP_TMOD
};

extern struct value_string osmo_ss7_as_traffic_mode_vals[];

static inline const char *
osmo_ss7_as_traffic_mode_name(enum osmo_ss7_as_traffic_mode mode)
{
	return get_value_string(osmo_ss7_as_traffic_mode_vals, mode);
}

enum osmo_ss7_asp_protocol {
	OSMO_SS7_ASP_PROT_NONE,
	OSMO_SS7_ASP_PROT_SUA,
	OSMO_SS7_ASP_PROT_M3UA,
	OSMO_SS7_ASP_PROT_IPA,
	_NUM_OSMO_SS7_ASP_PROT
};

extern struct value_string osmo_ss7_asp_protocol_vals[];

static inline const char *
osmo_ss7_asp_protocol_name(enum osmo_ss7_asp_protocol mode)
{
	return get_value_string(osmo_ss7_asp_protocol_vals, mode);
}

int osmo_ss7_asp_protocol_port(enum osmo_ss7_asp_protocol prot);

struct osmo_ss7_as {
	/*! entry in 'ref osmo_ss7_instance.as_list */
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	/*! AS FSM */
	struct osmo_fsm_inst *fi;

	/*! Were we dynamically allocated by RKM? */
	bool rkm_dyn_allocated;

	struct {
		char *name;
		char *description;
		enum osmo_ss7_asp_protocol proto;
		struct osmo_ss7_routing_key routing_key;
		enum osmo_ss7_as_traffic_mode mode;
		uint32_t recovery_timeout_msec;
		uint8_t qos_class;
		struct {
			uint32_t dpc;
		} pc_override;

		struct osmo_ss7_asp *asps[16];
	} cfg;
};

struct osmo_ss7_as *
osmo_ss7_as_find_by_name(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_as *
osmo_ss7_as_find_by_rctx(struct osmo_ss7_instance *inst, uint32_t rctx);
struct osmo_ss7_as *
osmo_ss7_as_find_by_l_rk_id(struct osmo_ss7_instance *inst, uint32_t l_rk_id);
struct osmo_ss7_as *
osmo_ss7_as_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			  enum osmo_ss7_asp_protocol proto);
int osmo_ss7_as_add_asp(struct osmo_ss7_as *as, const char *asp_name);
int osmo_ss7_as_del_asp(struct osmo_ss7_as *as, const char *asp_name);
void osmo_ss7_as_destroy(struct osmo_ss7_as *as);
bool osmo_ss7_as_has_asp(struct osmo_ss7_as *as,
			 struct osmo_ss7_asp *asp);
void osmo_ss7_asp_disconnect(struct osmo_ss7_asp *asp);


/***********************************************************************
 * SS7 Application Server Processes
 ***********************************************************************/

struct osmo_ss7_asp_peer {
	char *host;
	uint16_t port;
};

enum osmo_ss7_asp_admin_state {
	/*! no SCTP association with peer */
	OSMO_SS7_ASP_ADM_S_SHUTDOWN,
	/*! SCP association, but reject ASP-ACTIVE */
	OSMO_SS7_ASP_ADM_S_BLOCKED,
	/*! in normal operation */
	OSMO_SS7_ASP_ADM_S_ENABLED,
};

struct osmo_ss7_asp {
	/*! entry in \ref osmo_ss7_instance.asp_list */
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	/*! ASP FSM */
	struct osmo_fsm_inst *fi;

	/*! \ref osmo_xua_server over which we were established */
	struct osmo_xua_server *xua_server;
	struct llist_head siblings;

	/*! osmo_stream / libosmo-netif handles */
	struct osmo_stream_cli *client;
	struct osmo_stream_srv *server;
	/*! pre-formatted human readable local/remote socket name */
	char *sock_name;

	/* ASP Identifier for ASP-UP + NTFY */
	uint32_t asp_id;
	bool asp_id_present;

	/* Layer Manager to which we talk */
	const struct osmo_xua_layer_manager *lm;
	void *lm_priv;

	/*! Were we dynamically allocated */
	bool dyn_allocated;

	/*! Pending message for non-blocking IPA read */
	struct msgb *pending_msg;

	struct {
		char *name;
		char *description;
		enum osmo_ss7_asp_protocol proto;
		enum osmo_ss7_asp_admin_state adm_state;
		bool is_server;

		struct osmo_ss7_asp_peer local;
		struct osmo_ss7_asp_peer remote;
		uint8_t qos_class;
	} cfg;
};

struct osmo_ss7_asp *
osmo_ss7_asp_find_by_name(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			    uint16_t remote_port, uint16_t local_port,
			    enum osmo_ss7_asp_protocol proto);
void osmo_ss7_asp_destroy(struct osmo_ss7_asp *asp);
int osmo_ss7_asp_send(struct osmo_ss7_asp *asp, struct msgb *msg);
int osmo_ss7_asp_restart(struct osmo_ss7_asp *asp);
int osmo_ss7_asp_use_default_lm(struct osmo_ss7_asp *asp, int log_level);

#define LOGPASP(asp, subsys, level, fmt, args ...)		\
	LOGP(subsys, level, "asp-%s: " fmt, (asp)->cfg.name, ## args)

/***********************************************************************
 * xUA Servers
 ***********************************************************************/

struct osmo_xua_layer_manager {
	osmo_prim_cb prim_cb;
};

struct osmo_xua_server {
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	/* list of ASPs established via this server */
	struct llist_head asp_list;

	struct osmo_stream_srv_link *server;

	struct {
		bool accept_dyn_reg;
		struct osmo_ss7_asp_peer local;
		enum osmo_ss7_asp_protocol proto;
	} cfg;
};

struct osmo_xua_server *
osmo_ss7_xua_server_find(struct osmo_ss7_instance *inst, enum osmo_ss7_asp_protocol proto,
			 uint16_t local_port);

struct osmo_xua_server *
osmo_ss7_xua_server_create(struct osmo_ss7_instance *inst, enum osmo_ss7_asp_protocol proto,
			   uint16_t local_port, const char *local_host);

int
osmo_ss7_xua_server_set_local_host(struct osmo_xua_server *xs, const char *local_host);

void osmo_ss7_xua_server_destroy(struct osmo_xua_server *xs);


struct osmo_sccp_instance *
osmo_sccp_simple_client(void *ctx, const char *name, uint32_t pc,
			enum osmo_ss7_asp_protocol prot, int local_port,
			const char *local_ip, int remote_port, const char *remote_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_client_on_ss7_id(void *ctx, uint32_t ss7_id, const char *name,
				  uint32_t pc, enum osmo_ss7_asp_protocol prot,
				  int local_port, const char *local_ip,
				  int remote_port, const char *remote_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_server(void *ctx, uint32_t pc,
			enum osmo_ss7_asp_protocol prot, int local_port,
			const char *local_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_server_on_ss7_id(void *ctx, uint32_t ss7_id, uint32_t pc,
				  enum osmo_ss7_asp_protocol prot,
				  int local_port, const char *local_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_server_add_clnt(struct osmo_sccp_instance *inst,
				 enum osmo_ss7_asp_protocol prot,
				 const char *name, uint32_t pc,
				 int local_port, int remote_port,
				 const char *remote_ip);

enum osmo_ss7_as_traffic_mode osmo_ss7_tmode_from_xua(uint32_t in);
int osmo_ss7_tmode_to_xua(enum osmo_ss7_as_traffic_mode tmod);

/* VTY related */
struct vty;
void osmo_ss7_set_vty_alloc_ctx(void *ctx);
void osmo_ss7_vty_init_asp(void);
void osmo_ss7_vty_init_sg(void);
int osmo_ss7_vty_go_parent(struct vty *vty);
int osmo_ss7_is_config_node(struct vty *vty, int node);
