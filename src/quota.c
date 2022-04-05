#include "common.h"
#include "config.h"
#include "nf.h"
#include "quota.h"

#include <linux/if_ether.h>
#include <linux/netfilter/nf_tables.h>

#define COMMENT_FORMAT "%s rule for %s"

LOGSET("quota")

__attribute__((constructor)) static void init_quotas(void);
__attribute__((destructor)) static void free_quotas(void);

static struct nftnl_table *tbl = NULL;
static struct nftnl_chain *cha = NULL;
static struct nftnl_obj *quo = NULL;
static int config_copy_lists(quota_t q, int n);
static struct nftnl_table * table_name(const quota_t q);
static struct nftnl_chain * chain_name(const quota_t q);
static struct nftnl_rule * find_rule(const quota_t q, const char *type, 
                                     struct nftnl_rule **rules, int nrules);
static void rearm_rule_timer(quota_t q, struct nftnl_rule *rul);
static void timer_expired(EV_P_ ev_timer *t, int revents);
static bool delete_quota_rules(quota_t q);

__attribute__((constructor))
static void init_quotas(
    void)
{
  tbl = nftnl_table_alloc();
  cha = nftnl_chain_alloc();
  quo = nftnl_obj_alloc();
  if (!tbl || !cha || !quo) {
    err(EXIT_FAILURE, "Cannot initialize quotas");
  }

  nftnl_table_set_u32(tbl, NFTNL_TABLE_FAMILY, NFPROTO_INET);
  nftnl_chain_set_u32(cha, NFTNL_CHAIN_FAMILY, NFPROTO_INET);
  nftnl_obj_set_u32(quo, NFTNL_OBJ_FAMILY, NFPROTO_INET);
  nftnl_obj_set_u32(quo, NFTNL_OBJ_TYPE, NFT_OBJECT_QUOTA);
}

__attribute__((destructor))
static void free_quotas(
    void)
{
  nftnl_table_free(tbl);
  nftnl_chain_free(cha);
  nftnl_obj_free(quo);
}

static void timer_expired(
    EV_P_ ev_timer *t, 
    int revents)
{
  quota_t q = t->data;
  ELOG(INFO, "Quota rules for %s have expired. Deleting rules", q->name);

  if (!delete_quota_rules(q))
    ELOGERR(ERROR, "Unable to delete quota rules!");

  ev_timer_stop(EV_A, t);
  return;
}

static struct nftnl_table * table_name(
    const quota_t q)
{
  nftnl_table_set_str(tbl, NFTNL_TABLE_NAME, q->table_name);
  nftnl_chain_set_str(cha, NFTNL_CHAIN_TABLE, q->table_name);
  return tbl;
}

static struct nftnl_chain * chain_name(
    const quota_t q)
{
  nftnl_chain_set_str(cha, NFTNL_CHAIN_NAME, q->chain_name);
  nftnl_chain_set_str(cha, NFTNL_CHAIN_TABLE, q->table_name);
  return cha;
}

static struct nftnl_obj * quota_name(
    const quota_t q)
{
  nftnl_obj_set_str(quo, NFTNL_OBJ_NAME, q->name);
  nftnl_obj_set_str(quo, NFTNL_OBJ_TABLE, q->table_name);
  return quo;
}

static void rearm_rule_timer(
    quota_t q,
    struct nftnl_rule *rul)
{
  time_t now, then;
  assert(rul);

  now = time(NULL);
  then = nf_rule_get_timestamp(rul);

  if ((now - then) < CONFIG_TIMEOUT_RULE) {
    ev_timer_set(&q->expiry, (now-then) + CONFIG_TIMEOUT_RULE, 0);
    ev_timer_start(EV_DEFAULT, &q->expiry);
  }
  else {
    ELOG(INFO, "Found stray quota rules for %s (timeout was %d seconds ago)."
               " Deleting", q->name, (now-then));
    ev_feed_event(EV_DEFAULT, &q->expiry, EV_TIMER);
  }
}

static struct nftnl_rule * find_rule(
    const quota_t q,
    const char *type,
    struct nftnl_rule **rules,
    int nrules)
{
  int i;
  char rulebuf[NFT_USERDATA_MAXLEN] = {0};
  const char *comment;

  snprintf(rulebuf, NFT_USERDATA_MAXLEN-1, COMMENT_FORMAT, type, q->name);

  for (i=0; i < nrules; i++) {
    comment = nf_rule_get_comment(rules[i]);
    if (!comment)
      continue;

    if (strcmp(comment, rulebuf) == 0)
      return rules[i];
  }

  return NULL;
}

static int config_copy_lists(
    quota_t q,
    int n)
{
  int i;
  /* Copy hosts */
  q->hosts_len = config_get_quota_num_hosts(n);
  q->hosts = calloc(q->hosts_len, sizeof(struct sockaddr));
  if (!q->hosts)
    goto err;

  for (i=0; i < q->hosts_len; i++)
    memcpy(&q->hosts[i], config_get_quota_host(n, i), sizeof(struct sockaddr));

  q->macs_len = config_get_quota_num_macs(n);
  q->macs = calloc(q->macs_len, ETH_ALEN);
  if (!q->macs)
    goto err;

  for (i=0; i < q->macs_len; i++)
    memcpy(&q->macs[i], config_get_quota_mac_address(n, i), ETH_ALEN);

  return true;

err:
  if (q->hosts)
    free(q->hosts);
  if (q->macs)
    free(q->macs);

  return false;
}

static bool delete_quota_rules(
    struct quota *q)
{
  nf_t nf = NULL;
  struct nftnl_rule *rul = NULL;

  nf = nf_open(0, SOCK_CLOEXEC);
  rul = nftnl_rule_alloc();
  if (!nf || !rul)
    goto err;

  /* Build rule template */
  nftnl_rule_set_str(rul, NFTNL_RULE_TABLE, q->table_name);
  nftnl_rule_set_str(rul, NFTNL_RULE_CHAIN, q->chain_name);
  nftnl_rule_set_u32(rul, NFTNL_RULE_FAMILY, NFPROTO_INET);

  if (!nf_txn_begin(nf)) {
    ELOGERR(ERROR, "Error beginning transaction %s", strerror(errno));
    goto err;
  }

  nftnl_rule_set_u64(rul, NFTNL_RULE_HANDLE, q->in_h);
  if (!nf_rule_delete(nf, rul)) {
    ELOGERR(ERROR, "Error deleting inbound rule for %s", q->name);
    goto err;
  }

  nftnl_rule_set_u64(rul, NFTNL_RULE_HANDLE, q->out_h);
  if (!nf_rule_delete(nf, rul)) {
    ELOGERR(ERROR, "Error deleting outbound rule for %s", q->name);
    goto err;
  }

  if (!nf_txn_commit(nf)) {
    ELOGERR(ERROR, "Error committing transaction");
    goto err;
  }

  if (!nf_transact(nf)) {
    ELOGERR(ERROR, "Transaction error: %s", strerror(errno));
    goto err;
  }

  if (ev_is_active(&q->expiry))
    ev_timer_stop(EV_DEFAULT, &q->expiry);

  nftnl_rule_free(rul);
  return true;

err:
  if (nf) {
    nf_txn_abort(nf);
    nf_close(nf);
  }
  if (rul) nftnl_rule_free(rul);

  return false;
}

static struct nftnl_rule * create_quota_rule(
    quota_t q,
    nf_t nf,
    int direction,
    int handle_id)
{
  int i;
  const char *dev;
  char comment[NFT_USERDATA_MAXLEN] = {0};
  struct nftnl_rule *rul = NULL;
  struct nftnl_set *sets[2] = {0};

  /* Create initial rule */
  snprintf(comment, NFT_USERDATA_MAXLEN-1, COMMENT_FORMAT, 
                    direction ? "Outbound" : "Inbound", q->name);
  rul = nf_rule_init(nf, chain_name(q), comment);
  if (!rul)
    goto err;

  /* If handle is supplied, add it to this rule */
  if (handle_id >= 0)
    nftnl_rule_set_u64(rul, NFTNL_RULE_HANDLE, handle_id);

  /* Insert a userspace attribute marking the time this rule was created */
  nf_rule_set_timestamp(rul);

  /* Populate host list */
  sets[0] = nf_set_init(nf, table_name(q), NULL, "ip");
  if (!sets[0])
    goto err;

  for (i=0; i < q->hosts_len; i++) {
    if (!nf_set_add(sets[0], &q->hosts[i].s_addr, 4))
      goto err;
  }

  /* Populate device list */
  sets[1] = nf_set_init(nf, table_name(q), NULL, "ifname");
  if (!sets[1])
    goto err;

  for (i=0; i < config_get_table_num_devices(); i++) {
    dev = config_get_table_device_name(i);
    if (!nf_set_add(sets[1], dev, strlen(dev)))
      goto err;
  }

  /* Compare interface name to device set */
  if (!nf_rule_add_set(rul, direction, sets[1]))
    goto err;

  /* Compare IP address to IP set */
  if (!nf_rule_add_set(rul, direction, sets[0]))
    goto err;

  /* Apply the user quota */
  if (!nf_rule_add_quota(rul, quota_name(q)))
    goto err;

  if (!nf_rule_verdict(rul, "reject"))
    goto err;

  /* Creates buffers */
  if (!nf_set_create(nf, sets[0]))
    goto err;

  if (!nf_set_create(nf, sets[1]))
    goto err;

  if (handle_id >= 0) {
    if (!nf_rule_replace(nf, rul))
      goto err;
  }
  else {
    if (!nf_rule_create(nf, rul))
      goto err;
  }

  return rul;

err:
  if (sets[0]) nftnl_set_free(sets[0]);
  if (sets[1]) nftnl_set_free(sets[1]);
  if (rul) nftnl_rule_free(rul);
  return NULL;
}

static struct nftnl_rule * create_log_rule(
    quota_t q,
    nf_t nf)
{
  int i;
  struct nftnl_rule *rul = NULL;
  struct nftnl_set *set = NULL;
  char comment[NFT_USERDATA_MAXLEN] = {0};

  /* Create initial rule */
  snprintf(comment, NFT_USERDATA_MAXLEN-1, COMMENT_FORMAT, "Log", q->name);
  rul = nf_rule_init(nf, chain_name(q), comment);
  if (!rul)
    goto err;

  /* Create set */
  set = nf_set_init(nf, table_name(q), NULL, "lladdr");
  if (!set)
    goto err;

  for (i=0; i < q->macs_len; i++) {
    if (!nf_set_add(set, &q->macs[i], ETH_ALEN))
      goto err;
  }

  if (!nf_rule_add_set(rul, NF_SRC, set))
    goto err;

  /* Add a rate limit */
  if (!nf_rule_add_limit(rul, 1, 180))
    goto err;

  /* Add log rule */
  if (!nf_rule_add_log(rul, LOG_GROUP, q->name))
    goto err;

  if (!nf_set_create(nf, set))
    goto err;

  //nf_debug_rule(rul);

  if (!nf_rule_create(nf, rul))
    goto err;

  return rul;
err:
  if (set) nftnl_set_free(set);
  if (rul) nftnl_rule_free(rul);
  return NULL;
}


void quota_resolve_created_state(
    quota_t q,
    nf_t nf)
{
  if (OBJ_STATE(q->state, O_STATE_QUOTA_CREATED)) {
    OBJ_UNSET_STATE(q->state, O_STATE_QUOTA_CREATED);
  }

  if (OBJ_STATE(q->state, O_STATE_LOG_CREATED)) {
    OBJ_UNSET_STATE(q->state, O_STATE_LOG_CREATED);
  }

  if (OBJ_STATE(q->state, O_STATE_ORULE_CREATED)) {
    OBJ_UNSET_STATE(q->state, O_STATE_ORULE_CREATED);
  }

  if (OBJ_STATE(q->state, O_STATE_IRULE_CREATED)) {
    OBJ_UNSET_STATE(q->state, O_STATE_IRULE_CREATED);
  }
  return;
}

void quota_resolve_deleted_state(
    quota_t q,
    nf_t nf)
{
  struct nftnl_obj *quo = NULL;
  struct nftnl_rule *rul = NULL;

  /* May fail but is idempotent in this case */
  nf_txn_begin(nf);

  /* The quota was a replacement, make no changes */
  if (OBJ_STATE(q->state, O_STATE_QUOTA_DELETED|O_STATE_QUOTA_CREATED)) {
    OBJ_UNSET_STATE(q->state, O_STATE_QUOTA_DELETED);
  }
  else if (OBJ_STATE(q->state, O_STATE_QUOTA_DELETED)) {
    ELOG(INFO, "Quota %s does not exist. Creating.", q->name);
    quo = nf_quota_create(nf, table_name(q), q->name, q->limit, q->used);
    if (!quo) {
      ELOGERR(ERROR, "Cannot create quota %s", q->name);
      goto err;
    }
    OBJ_UNSET_STATE(q->state, O_STATE_QUOTA_DELETED);
  }

  if (OBJ_STATE(q->state, O_STATE_LOG_DELETED)) {
    ELOG(INFO, "Log rule for %s does not exist. Creating.", q->name);
    rul = create_log_rule(q, nf);
    if (!rul) {
      ELOGERR(ERROR, "Cannot create log rule %s", q->name);
      goto err;
    }
    OBJ_UNSET_STATE(q->state, O_STATE_LOG_DELETED);
    nftnl_rule_free(rul); rul = NULL;
  }

  /* If the rule timer was active the rules should
   * exist. So, regenerate the rules */
  if (ev_is_active(&q->expiry)) {

    /* The rule was a replacement, make no changes */
    if (OBJ_STATE(q->state, O_STATE_IRULE_DELETED|O_STATE_IRULE_CREATED)) {
      OBJ_UNSET_STATE(q->state, O_STATE_IRULE_DELETED);
    }
    else if (OBJ_STATE(q->state, O_STATE_IRULE_DELETED)) {
      ELOG(INFO, "Inbound rule for %s does not exist. Creating.", q->name);
      rul = create_quota_rule(q, nf, 0, -1);
      if (!rul) {
        ELOGERR(ERROR, "Cannot create inbound rule %s", q->name);
        goto err;
      }
      OBJ_UNSET_STATE(q->state, O_STATE_IRULE_DELETED);
      q->in_h = -1;
      nftnl_rule_free(rul); rul = NULL;
    }

    /* The rule was a replacement, make no changes */
    if (OBJ_STATE(q->state, O_STATE_ORULE_DELETED|O_STATE_ORULE_CREATED)) {
      OBJ_UNSET_STATE(q->state, O_STATE_ORULE_DELETED);
    }
    else if (OBJ_STATE(q->state, O_STATE_ORULE_DELETED)) {
      ELOG(INFO, "Outbound rule for %s does not exist. Creating.", q->name);
      rul = create_quota_rule(q, nf, 1, -1);
      if (!rul) {
        ELOGERR(ERROR, "Cannot create outbound rule %s", q->name);
        goto err;
      }
      OBJ_UNSET_STATE(q->state, O_STATE_ORULE_DELETED);
      q->out_h = -1;
      nftnl_rule_free(rul); rul = NULL;
    }
  }
  /* Do the accounting on the rules if the timer is now inactive */
  else {
    if (OBJ_STATE(q->state, O_STATE_IRULE_DELETED)) {
      OBJ_UNSET_STATE(q->state, O_STATE_IRULE_DELETED);
      q->in_h = -1;
    }

    if (OBJ_STATE(q->state, O_STATE_ORULE_DELETED)) {
      OBJ_UNSET_STATE(q->state, O_STATE_ORULE_DELETED);
      q->out_h = -1;
    }
  }

  if (rul) nftnl_rule_free(rul);
  if (quo) nftnl_obj_free(quo);
  return;

err:
  nf_txn_abort(nf);
  if (rul) nftnl_rule_free(rul);
  if (quo) nftnl_obj_free(quo);
}


static bool handle_new_obj_event(
    quota_t q,
    struct nftnl_obj *obj)
{
  /* First need to search through our list and identify if we own this */
  int32_t handle;
  const char *name;
  const char *table;
  int32_t type;

  name = nftnl_obj_get_str(obj, NFTNL_OBJ_NAME);
  table = nftnl_obj_get_str(obj, NFTNL_OBJ_TABLE);
  type = nftnl_obj_get_u32(obj, NFTNL_OBJ_TYPE);
  handle = nftnl_obj_get_u32(obj, NFTNL_OBJ_HANDLE);

  if (type != NFT_OBJECT_QUOTA)
    goto err;

  if (handle == q->quota_h || q->quota_h == -1) {
    if (strcmp(table, q->table_name) != 0)
      goto err;
    if (strcmp(name, q->name) != 0)
      goto err;

    OBJ_SET_STATE(q->state, O_STATE_QUOTA_CREATED);
    ELOG(VERBOSE, "Quota %s has been created, handle %d", q->name, handle);
    q->quota_h = handle;

    return true;
  }

err:
  return false;
}

static bool handle_del_obj_event(
    quota_t q,
    struct nftnl_obj *obj)
{
  int32_t handle;

  handle = nftnl_obj_get_u32(obj, NFTNL_OBJ_HANDLE);

  if (handle != q->quota_h)
    goto err;

  /* Update our limits and usage */
  q->limit = nftnl_obj_get_u64(obj, NFTNL_OBJ_QUOTA_BYTES);
  q->used = nftnl_obj_get_u64(obj, NFTNL_OBJ_QUOTA_CONSUMED);

  OBJ_SET_STATE(q->state, O_STATE_QUOTA_DELETED);
  ELOG(VERBOSE, "Quota %s has been deleted, handle %d", q->name, handle);
  q->quota_h = -1;

  return true;

err:
  return false;
}

static bool handle_new_rule_event(
    quota_t q,
    struct nftnl_rule *rul)
{
  /* First need to search through our list and identify if we own this */
  uint64_t handle;
  const char *table;
  const char *chain;
  const char *comment;
  char name[32] = {0}, type[32] = {0};

  chain = nftnl_rule_get_str(rul, NFTNL_RULE_CHAIN);
  table = nftnl_rule_get_str(rul, NFTNL_RULE_TABLE);
  handle = nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE);
  comment = nf_rule_get_comment(rul);

  if (strcmp(table, q->table_name) != 0)
    return false;

  if (strcmp(chain, q->chain_name) != 0)
    return false;

  if (sscanf(comment, COMMENT_FORMAT, type, name) != 2)
    return false;

  if (strcmp(name, q->name) != 0)
    return false;

  if (strcmp(type, "Log") == 0) {
    OBJ_SET_STATE(q->state, O_STATE_LOG_CREATED);
    q->log_h = handle;

    return true;
  }
  else if (strcmp(type, "Inbound") == 0) {
    OBJ_SET_STATE(q->state, O_STATE_IRULE_CREATED);
    q->in_h = handle;
    rearm_rule_timer(q, rul);

    return true;
  }
  else if (strcmp(type, "Outbound") == 0) {
    OBJ_SET_STATE(q->state, O_STATE_ORULE_CREATED);
    q->out_h = handle;
    rearm_rule_timer(q, rul);

    return true;
  }
  else
    return false;

}

static bool handle_del_rule_event(
    quota_t q,
    struct nftnl_rule *rul)
{
  uint64_t handle;

  handle = nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE);

  if (handle == q->log_h) {
    OBJ_SET_STATE(q->state, O_STATE_LOG_DELETED);
    return true;
  }
  else if (handle == q->in_h) {
    OBJ_SET_STATE(q->state, O_STATE_IRULE_DELETED);
    return true;
  }
  else if (handle == q->out_h) {
    OBJ_SET_STATE(q->state, O_STATE_ORULE_DELETED);
    return true;
  }

  return false;
}


bool quota_reset(
    quota_t q,
    nf_t nf)
{
  if (!nf_quota_reset(nf, quota_name(q)))
    return false;

  q->used = 0;
  return true;
}


void quota_inspect_firewall_state(
    quota_t q, 
    nf_t nf)
{
  int i, n=0;
  struct nftnl_obj *quo = NULL;
  struct nftnl_rule *rul;
  struct nftnl_rule **rules = NULL;

  /* Get quota state */
  quo = nf_quota_get(nf, table_name(q), q->name);
  if (quo)
    q->quota_h = nftnl_obj_get_u64(quo, NFTNL_OBJ_HANDLE);
  else
    OBJ_SET_STATE(q->state, O_STATE_QUOTA_DELETED);

  /* Get the list of rules */
  if (!nf_rule_list(nf, chain_name(q), &rules, &n)) {
    ELOG(CRITICAL, "Cannot obtain list of rules for chain %s. Aborting.",
         q->chain_name);
    exit(EXIT_FAILURE);
  }

  /* Inspect each rule for matching comment */
  rul = find_rule(q, "Log", rules, n);
  if (rul)
    q->log_h = nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE);
  else 
    OBJ_SET_STATE(q->state, O_STATE_LOG_DELETED);

  rul = find_rule(q, "Inbound", rules, n);
  if (rul)
    q->in_h = nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE);
  else
    OBJ_SET_STATE(q->state, O_STATE_IRULE_DELETED);

  rul = find_rule(q, "Outbound", rules, n);
  if (rul)
    q->out_h = nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE);
  else
    OBJ_SET_STATE(q->state, O_STATE_ORULE_DELETED);

  /* Rearm rule timer */
  if (rul) {
    rearm_rule_timer(q, rul);
  }

  if (quo) nftnl_obj_free(quo);
  if (rules) {
    for (i=0; i < n; i++) {
      if (rules[i]) nftnl_rule_free(rules[i]);
    }
    free(rules);
  }
}

bool quota_handle_log_message(
    quota_t q,
    struct nlmsghdr *hdr)
{
  bool activate = false;
  const char *prefix;
  struct nftnl_rule *rul = NULL;
  nf_t nf = NULL;

  prefix = nf_nflog_prefix(hdr);
  if (!prefix)
    goto err;

  /* Prefix not this quota */
  if (strcmp(prefix, q->name) != 0)
    goto err;

  nf = nf_open(0, SOCK_CLOEXEC);
  if (!nf) {
    ELOGERR(ERROR, "Cannot open netfilter socket");
    goto err;
  }

  ELOG(INFO, "Log matched on %s. %s quotas.", q->name,
                 q->in_h < 0 ? "Activating" : "Reactivating");

  if (!nf_txn_begin(nf)) {
    ELOGERR(ERROR, "Cannot begin transaction");
    goto err;
  }

  /* Dont make rules between states, prevents overflows */
  if (!OBJ_STATE(q->state, O_STATE_IRULE_CREATED)) {
    rul = create_quota_rule(q, nf, 0, q->in_h);
    if (!rul) {
      ELOGERR(ERROR, "Cannot establish inbound quota rule for %s", q->name);
      goto err;
    }
    OBJ_SET_STATE(q->state, O_STATE_IRULE_CREATED);
    activate = true;
    nftnl_rule_free(rul); rul = NULL;

    if (q->in_h > -1)
      ELOG(VERBOSE, "Reactivating inbound rule for %s, handle %d", q->name, q->in_h);
  }

  /* Dont make rules between states, prevents overflows */
  if (!OBJ_STATE(q->state, O_STATE_ORULE_CREATED)) {
    rul = create_quota_rule(q, nf, 1, q->out_h);
    if (!rul) {
      ELOGERR(ERROR, "Cannot establish outbound quota rule for %s", q->name);
      goto err;
    }
    OBJ_SET_STATE(q->state, O_STATE_ORULE_CREATED);
    activate = true;
    nftnl_rule_free(rul); rul = NULL;

    if (q->out_h > -1)
      ELOG(VERBOSE, "Reactivating outbound rule for %s, handle %d", q->name, q->out_h);
  }

  if (activate) {
    if (!nf_txn_commit(nf)) {
      ELOGERR(ERROR, "Cannot commit transaction");
      goto err;
    }

    if (!nf_transact(nf)) {
      ELOGERR(ERROR, "Cannot transact");
      goto err;
    }

    /* Reset the timer */
    ev_timer_stop(EV_DEFAULT, &q->expiry);
    ev_timer_set(&q->expiry, CONFIG_TIMEOUT_RULE, 0.0);
    ev_timer_start(EV_DEFAULT, &q->expiry);
  }
  else {
    nf_txn_abort(nf);
    nf_close(nf);
    return true;
  }

  nf_close(nf);
  return true;

err:
  if (rul)
    nftnl_rule_free(rul);
  if (nf) {
    nf_txn_abort(nf);
    nf_close(nf);
  }
  return false;
}


bool quota_handle_message(
    quota_t q, 
    struct nlmsghdr *hdr)
{
  bool rc = false;
  int type = NFNL_MSG_TYPE(hdr->nlmsg_type);
  struct nftnl_rule *rul = NULL; 
  struct nftnl_obj *obj = NULL;

  switch (type) {
    case NFT_MSG_NEWRULE:
    case NFT_MSG_DELRULE:
      rul = nftnl_rule_alloc();
      if (!rul)
        goto err;

      if (nftnl_rule_nlmsg_parse(hdr, rul) < 0)
        goto err;

      if (type == NFT_MSG_NEWRULE)
        rc = handle_new_rule_event(q, rul);
      else 
        rc = handle_del_rule_event(q, rul);
    break;

    case NFT_MSG_NEWOBJ:
    case NFT_MSG_DELOBJ:
      obj = nftnl_obj_alloc();
      if (!obj)
        goto err;

      if (nftnl_obj_nlmsg_parse(hdr, obj) < 0)
        goto err;

      if (type == NFT_MSG_NEWOBJ) 
        rc = handle_new_obj_event(q, obj);
      else 
        rc = handle_del_obj_event(q, obj);
    break;
  }

err:
  if (rul) nftnl_rule_free(rul);
  if (obj) nftnl_obj_free(obj);

  return rc;
}


void quota_destroy(
    quota_t q)
{
  if (!q) return;

  if (q->name) free(q->name);

  if (q->hosts) free(q->hosts);
  if (q->macs) free(q->macs);

  ev_timer_stop(EV_DEFAULT, &q->expiry);
  free(q);
}



quota_t quota_init(
    int n)
{
  quota_t q = NULL;

  const char *name;
  if (n < 0 || n > config_get_table_num_quotas()) {
    errno = EINVAL;
    goto err;
  }

  name = config_get_quota_name(n);
  if (!name) {
    errno = EINVAL;
    goto err;
  }

  q = malloc(sizeof(struct quota));
  if (!q)
    goto err;

  q->table_name = config_get_table_name();
  q->chain_name = CHAIN_NAME;

  q->name = strdup(name);
  if (!q->name)
    goto err;

  q->quota_h = -1;
  q->quota_h = -1;
  q->in_h = -1;
  q->out_h = -1;
  q->limit = config_get_quota_limit(n);
  q->used = 0;
  q->state = O_STATE_NONE;

  ev_timer_init(&q->expiry, timer_expired, CONFIG_TIMEOUT_RULE, 0.0);
  q->expiry.data = q;

  /* This tricks into enabling rules immediate, for test */
  // ev_timer_start(EV_DEFAULT, &q->expiry);

  if (!config_copy_lists(q, n))
    goto err;

  return q;

err:
  if (q)
    quota_destroy(q);
  return NULL;
}
