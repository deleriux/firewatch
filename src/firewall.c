#include "common.h"

#include "config.h"
#include "quota.h"
#include "firewall.h"
#include "nf.h"
#include <ev.h>

#define O_STATE_NONE             0x00
#define O_STATE_TABLE_CREATED    0x01
#define O_STATE_TABLE_DELETED    0x02
#define O_STATE_CHAIN_CREATED      0x04
#define O_STATE_CHAIN_DELETED      0x08

#define OBJ_STATE(x,y) ((x & (y)) == (y))
#define OBJ_NO_STATE(x) ((x | O_STATE_NONE) ? 0 : 1)
#define OBJ_SET_STATE(x,y) (x |= (y))
#define OBJ_UNSET_STATE(x,y) (x &= (~y))

LOGSET("firewall")

static struct state {
  ev_periodic pe;
  ev_io io;
  nf_t nf;
  nf_t tx;
  uint8_t state;

  const char *name;
  int32_t priority;
  int table_h;
  int chain_h;
  char **devices;

  int devices_len;
  quota_t *quotas;
  int quotas_len;
}

state = 
{
  .pe = {0},
  .io = {0},
  .nf = NULL,
  .tx = NULL,
  .state = O_STATE_NONE,

  .name = NULL,
  .priority = 10,
  .table_h = -1,
  .chain_h = -1,
  .quotas = NULL,

  .quotas_len = 0,
  .devices = NULL,
  .devices_len = 0,
};

static void load_config(void);
void firewall_destroy(void);
static void firewall_recv(EV_P_ ev_io *io, int revents);
static void reset_quotas(EV_P_ ev_periodic *pe, int revents);
static void resolve_deleted_state(void);
static void resolve_created_state(void);
static void load_firewall_state(void);
static void handle_new_table_event(struct nftnl_table *tbl);
static void handle_del_table_event(struct nftnl_table *tbl);
static void handle_new_chain_event(struct nftnl_chain *cha);
static void handle_del_chain_event(struct nftnl_chain *cha);
static void handle_gen_event(struct nftnl_gen *gen);
static void handle_state_message(struct nlmsghdr *hdr);
static void handle_nflog_subsystem_message(struct nlmsghdr *hdr);
static void handle_netfilter_subsystem_message(struct nlmsghdr *hdr);


static void handle_new_table_event(
    struct nftnl_table *tbl)
{
  uint64_t handle;
  const char *table;

  handle = nftnl_table_get_u64(tbl, NFTNL_TABLE_HANDLE);
  table = nftnl_table_get_str(tbl, NFTNL_TABLE_NAME);

  if (handle == state.table_h || state.table_h == -1) {
    if (strcmp(table, state.name) != 0)
      return;

    OBJ_SET_STATE(state.state, O_STATE_TABLE_CREATED);
    ELOG(VERBOSE, "Table %s has been created, handle %d", state.name, handle);
    state.table_h = handle;
  }
}


static void handle_del_table_event(
    struct nftnl_table *tbl)
{
  int32_t handle;

  handle = nftnl_table_get_u32(tbl, NFTNL_TABLE_HANDLE);

  if (handle != state.table_h)
    return;

  OBJ_SET_STATE(state.state, O_STATE_TABLE_DELETED);
  ELOG(VERBOSE, "Table %s has been deleted, handle %d", state.name, handle);
  state.table_h = -1;
}


static void handle_new_chain_event(
    struct nftnl_chain *cha)
{
  uint64_t handle;
  const char *table;
  const char *chain;

  handle = nftnl_chain_get_u64(cha, NFTNL_CHAIN_HANDLE);
  table = nftnl_chain_get_str(cha, NFTNL_CHAIN_TABLE);
  chain = nftnl_chain_get_str(cha, NFTNL_CHAIN_NAME);

  if (state.chain_h == handle || state.chain_h == -1) {
    if (strcmp(table, state.name) != 0)
      return;

    if (strcmp(chain, CHAIN_NAME) != 0)
      return;

    OBJ_SET_STATE(state.state, O_STATE_CHAIN_CREATED);
    ELOG(VERBOSE, "Chain %s has been created, handle %d", state.name, handle);
    state.chain_h = handle;
  }
}


static void handle_del_chain_event(
    struct nftnl_chain *cha)
{
  uint64_t handle;

  handle = nftnl_chain_get_u64(cha, NFTNL_CHAIN_HANDLE);

  if (handle != state.chain_h)
    return;

  OBJ_SET_STATE(state.state, O_STATE_CHAIN_DELETED);
  ELOG(VERBOSE, "Chain %s has been deleted, handle %d", state.name, handle);
  state.chain_h = -1;
}


static void handle_gen_event(
    struct nftnl_gen *gen)
{
  uint32_t generation;

  generation = nftnl_gen_get_u32(gen, NFTNL_GEN_ID);
  nf_set_genid(state.nf, generation);


  ELOG(VERBOSE, "Transaction complete: Generation %lu. Resolving state.", generation);

  resolve_deleted_state();
  resolve_created_state();
}

static void handle_state_message(
    struct nlmsghdr *hdr)
{
  struct nftnl_table *tbl = NULL;
  struct nftnl_chain *cha = NULL;
  struct nftnl_gen *gen = NULL;
  
  int type = NFNL_MSG_TYPE(hdr->nlmsg_type);
  switch (type) {
    case NFT_MSG_NEWTABLE:
    case NFT_MSG_DELTABLE:
      tbl = nftnl_table_alloc();
      if (nftnl_table_nlmsg_parse(hdr, tbl) < 0) {
        ELOGERR(ERROR, "Cannot parse table message");
        goto err;
      }
      if (type == NFT_MSG_NEWTABLE) {
        handle_new_table_event(tbl);
      }
      else {
        handle_del_table_event(tbl);
      }
    break;

    case NFT_MSG_NEWCHAIN:
    case NFT_MSG_DELCHAIN:
      cha = nftnl_chain_alloc();
      if (nftnl_chain_nlmsg_parse(hdr, cha) < 0) {
        ELOGERR(ERROR, "Cannot parse chain message");
        goto err;
      }
      if (type == NFT_MSG_NEWCHAIN) {
        handle_new_chain_event(cha);
      }
      else {
        handle_del_chain_event(cha);
      }
    break;

    case NFT_MSG_NEWGEN:
      gen = nftnl_gen_alloc();
      if (nftnl_gen_nlmsg_parse(hdr, gen) < 0) {
        ELOGERR(ERROR, "Cannot parse generation message");
        goto err;
      }
      handle_gen_event(gen);
    break;
  }

err:
  if (tbl) nftnl_table_free(tbl);
  if (cha) nftnl_chain_free(cha);
  if (gen) nftnl_gen_free(gen);
}

static void handle_nflog_subsystem_message(
    struct nlmsghdr *hdr)
{
  int i;
  for (i=0; i < state.quotas_len; i++) {
    if (quota_handle_log_message(state.quotas[i], hdr))
      return;
  }
}

static void handle_netfilter_subsystem_message(
    struct nlmsghdr *hdr)
{
  int i;
  int type = NFNL_MSG_TYPE(hdr->nlmsg_type);

  switch (type) {
    /* We only ever work with anonymous sets, so we ignore these 
     * message types */
    case NFT_MSG_DELSET:
    case NFT_MSG_NEWSET:
    case NFT_MSG_NEWSETELEM:
    break;

    case NFT_MSG_DELTABLE:
    case NFT_MSG_DELCHAIN:
    case NFT_MSG_NEWTABLE:
    case NFT_MSG_NEWCHAIN:
    case NFT_MSG_NEWGEN:
      handle_state_message(hdr);
    break;

    case NFT_MSG_NEWRULE:
    case NFT_MSG_NEWOBJ:
    case NFT_MSG_DELRULE:
    case NFT_MSG_DELOBJ:
      for (i=0; i < state.quotas_len; i++) {
        if (quota_handle_message(state.quotas[i], hdr))
          break;
      }
    break;

    default:
      ELOG(WARNING, "Received unhandled message type (%s). Ignoring",
           nf_nlmsg_type(hdr->nlmsg_type));
      return;
  }
}

static void reset_quotas(
    EV_P_ ev_periodic *pe,
    int revents)
{
  int i;

  ELOG(INFO, "Resetting quotas.");
  for (i=0; i < state.quotas_len; i++)
    quota_reset(state.quotas[i], state.tx);
  return;
}

static void firewall_recv(
    EV_P_ ev_io *io,
    int revents)
{
  nf_t nf = io->data;
  struct nlmsghdr *hdrs = NULL, *hdr;
  int len, nmsgs;

  len = nf_recv(nf, &hdrs, &nmsgs);
  if (len < 0) {
    ELOGERR(ERROR, "Error receiving netlink message");
    return;
  }

  hdr = hdrs;
  /* Begin callback loop */

  while (mnl_nlmsg_ok(hdr, len)) {
    int subsys = NFNL_SUBSYS_ID(hdr->nlmsg_type);
    
    switch (hdr->nlmsg_type) {
      case NLMSG_NOOP:
      case NLMSG_ERROR:
      case NLMSG_DONE:
        ELOG(WARNING, "Received a bad netlink message type which shouldn't "
                       "arrive over the monitor: (%d)", hdr->nlmsg_type);
        hdr = mnl_nlmsg_next(hdr, &len);
        continue;
      break;
    }

    switch (subsys) {
      case NFNL_SUBSYS_NFTABLES:
        handle_netfilter_subsystem_message(hdr);
      break;

      case NFNL_SUBSYS_ACCT:
        ELOG(WARNING, "Received a netlink quota message we dont know how to "
                      "handle yet.");
      break;

      case NFNL_SUBSYS_ULOG:
        handle_nflog_subsystem_message(hdr);
      break;

      default:
        ELOG(WARNING, "Received a netlink message type (%s) with "
                      "no compatible subsystem", nf_nlmsg_type(hdr->nlmsg_type));
      break;
    }

    hdr = mnl_nlmsg_next(hdr, &len);
    
  }
  free(hdrs);
  return;
}

static void resolve_created_state(
    void)
{
  int i;

  if (OBJ_STATE(state.state, O_STATE_TABLE_CREATED)) {
    OBJ_UNSET_STATE(state.state, O_STATE_TABLE_CREATED);
  }

  if (OBJ_STATE(state.state, O_STATE_CHAIN_CREATED)) {
    OBJ_UNSET_STATE(state.state, O_STATE_CHAIN_CREATED);
  }

  for (i=0; i < state.quotas_len; i++) {
    quota_resolve_created_state(state.quotas[i], state.tx);
  } 
}


static void resolve_deleted_state(
    void)
{
  int i;
  nf_t nf = state.tx;
  struct nftnl_table *tbl = NULL;
  struct nftnl_chain *cha = NULL;

  if (!nf_txn_begin(nf)) {
    ELOGERR(ERROR, "Cannot begin transaction");
    goto err;
  }

  if (OBJ_STATE(state.state, O_STATE_TABLE_DELETED|O_STATE_CHAIN_DELETED)) {
    /* Need to recreate table or chain */
    if (OBJ_STATE(state.state, O_STATE_TABLE_DELETED)) {
      ELOG(INFO, "Table %s does not exist. Creating.", state.name);
      tbl = nf_table_create(nf, TABLE_FAMILY, state.name);
      if (!tbl) {
        ELOGERR(ERROR, "Cannot create table %s", state.name);
        goto err;
      }
      OBJ_UNSET_STATE(state.state, O_STATE_TABLE_DELETED);
    }

    if (!tbl) {
      tbl = nftnl_table_alloc();
      nftnl_table_set_str(tbl, NFTNL_TABLE_NAME, state.name);
      nftnl_table_set_u32(tbl, NFTNL_TABLE_FAMILY, NFPROTO_INET);
    }

    if (OBJ_STATE(state.state, O_STATE_CHAIN_DELETED)) {
      ELOG(INFO, "Chain %s does not exist. Creating.", CHAIN_NAME);
      cha = nf_chain_create(nf, tbl, CHAIN_NAME, "forward", 
                            "filter", state.priority, "accept");
      if (!cha) {
        ELOGERR(ERROR, "Cannot create chain %s", CHAIN_NAME);
        goto err;
      }
      OBJ_UNSET_STATE(state.state, O_STATE_CHAIN_DELETED);
    }
  }

  /* Check quota objects for consistency */
  for (i=0; i < state.quotas_len; i++) 
    quota_resolve_deleted_state(state.quotas[i], nf);

  if (!nf_txn_commit(nf)) {
    ELOGERR(ERROR, "Cannot commit transaction");
    goto err;
  }

  if (!nf_transact(nf)) {
    ELOGERR(ERROR, "Cannot transact");
  }

  if (tbl) nftnl_table_free(tbl);
  if (cha) nftnl_chain_free(cha);
  return;

err:
  nf_txn_abort(nf);
  if (tbl) nftnl_table_free(tbl);
  if (cha) nftnl_chain_free(cha);
  return;
}


static void inspect_firewall_state(
    void)
{
  int i;
  struct nftnl_table *tbl = NULL;
  struct nftnl_chain *cha = NULL;

  nf_t nf = state.tx;

  tbl = nf_table_get(nf, TABLE_FAMILY, state.name);
  if (tbl) 
    state.table_h = nftnl_table_get_u64(tbl, NFTNL_TABLE_HANDLE);
  else 
    OBJ_SET_STATE(state.state, O_STATE_TABLE_DELETED);

  cha = nf_chain_get(nf, tbl, CHAIN_NAME);
  if (cha) 
    state.chain_h = nftnl_chain_get_u64(cha, NFTNL_CHAIN_HANDLE);
  else 
    OBJ_SET_STATE(state.state, O_STATE_CHAIN_DELETED);

  for (i=0; i < state.quotas_len; i++)
    quota_inspect_firewall_state(state.quotas[i], nf);

  if (tbl) nftnl_table_free(tbl);
  if (cha) nftnl_chain_free(cha);
  return;
}

static void load_firewall_state(
    void)
{
  /* Initializes the states and sets the flags needed */
  inspect_firewall_state();

  /* Attempt now to meet the desired state */
  resolve_deleted_state();
}

static void load_config(
    void)
{
  int n;

  /* Grab table details from config */
  state.quotas_len = config_get_table_num_quotas();
  state.name = config_get_table_name();
  state.priority = config_get_table_priority();

  /* Initialize device names */
  state.devices_len = config_get_table_num_devices();
  state.devices = calloc(state.devices_len, sizeof(char *));
  if (!state.devices) {
    ELOGERR(ERROR, "Out of memory");
    goto err;
  }

  for (n=0; n < state.devices_len; n++) {
    state.devices[n] = strdup(config_get_table_device_name(n));
    if (!state.devices[n]) {
      ELOGERR(ERROR, "Out of memory");
      goto err;
    }
  }

  /* Initialize quotas */
  state.quotas = calloc(state.quotas_len, sizeof(struct quota));
  if (!state.quotas) {
    ELOGERR(ERROR, "Out of memory");
    goto err;
  }

  for (n=0; n < state.quotas_len; n++) {
    state.quotas[n] = quota_init(n);
    if (!state.quotas[n])
      goto err;
  }

  return;
err:
  firewall_destroy();
  ELOG(CRITICAL, "Cannot load firewall state. Aborting.");
  exit(EXIT_FAILURE);
}


void firewall_destroy(
    void)
{
  int i;
  nf_close(state.nf);
  state.nf = NULL;
  nf_close(state.tx);
  state.tx = NULL;
  ev_io_stop(EV_DEFAULT, &state.io);

  if (state.devices) {
    for (i=0; i < state.devices_len; i++)
      free(state.devices[i]);
  }

  if (state.quotas) {
    for (i=0; i < state.quotas_len; i++)
      quota_destroy(state.quotas[i]);
  
    free(state.quotas);
  }
}

void firewall_load(
    void)
{
  time_t reset;
  load_config();

  state.tx = nf_open(0, SOCK_CLOEXEC);
  if (!state.tx) {
    ELOGERR(ERROR, "Cannot create netfilter socket");
    goto err;
  }

  state.nf = nf_open(NF_NFTABLES, SOCK_CLOEXEC);
  if (!state.nf) {
    ELOGERR(ERROR, "Cannot create netfilter socket");
    goto err;
  }

  /* Setup log reception */
  if (!nf_nflog_bind(state.nf, state.priority, 1, 10, NF_COPY_NONE, 0)) {
    ELOGERR(ERROR, "Cannot set log binding");
    goto err;
  }

  /* Add to the event loop */
  ev_io_init(&state.io, firewall_recv, nf_get_fd(state.nf), EV_READ);
  state.io.data = state.nf;
  ev_io_start(EV_DEFAULT, &state.io);

  /* Set periodic timer */
  reset = mktime(config_get_table_reset_quota_time()) % PERIODIC_INTERVAL;
  ev_periodic_init(&state.pe, reset_quotas, (ev_tstamp)reset, PERIODIC_INTERVAL, 0);
  state.pe.data = state.nf;
  ev_periodic_start(EV_DEFAULT, &state.pe);
  ELOG(VERBOSE, "Resetting quotas on the %dth second of the %dth second interval",
                reset, PERIODIC_INTERVAL);

  load_firewall_state();

  ELOG(INFO, "Loaded firewall");
  return;

err:
  firewall_destroy();
  exit(EXIT_FAILURE);
}
