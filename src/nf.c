#include "nf.h"
#include "common.h"

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


enum datatypes {
	TYPE_INVALID,
	TYPE_VERDICT,
	TYPE_NFPROTO,
	TYPE_BITMASK,
	TYPE_INTEGER,
	TYPE_STRING,
	TYPE_LLADDR,
	TYPE_IPADDR,
	TYPE_IP6ADDR,
	TYPE_ETHERADDR,
	TYPE_ETHERTYPE,
	TYPE_ARPOP,
	TYPE_INET_PROTOCOL,
	TYPE_INET_SERVICE,
	TYPE_ICMP_TYPE,
	TYPE_TCP_FLAG,
	TYPE_DCCP_PKTTYPE,
	TYPE_MH_TYPE,
	TYPE_TIME,
	TYPE_MARK,
	TYPE_IFINDEX,
	TYPE_ARPHRD,
	TYPE_REALM,
	TYPE_CLASSID,
	TYPE_UID,
	TYPE_GID,
	TYPE_CT_STATE,
	TYPE_CT_DIR,
	TYPE_CT_STATUS,
	TYPE_ICMP6_TYPE,
	TYPE_CT_LABEL,
	TYPE_PKTTYPE,
	TYPE_ICMP_CODE,
	TYPE_ICMPV6_CODE,
	TYPE_ICMPX_CODE,
	TYPE_DEVGROUP,
	TYPE_DSCP,
	TYPE_ECN,
	TYPE_FIB_ADDR,
	TYPE_BOOLEAN,
	TYPE_CT_EVENTBIT,
	TYPE_IFNAME,
	TYPE_IGMP_TYPE,
	TYPE_TIME_DATE,
	TYPE_TIME_HOUR,
	TYPE_TIME_DAY,
	TYPE_CGROUPV2,
	__TYPE_MAX
};
#define TYPE_MAX		(__TYPE_MAX - 1)

#define TYPE_BITS		6
#define TYPE_MASK		((1 << TYPE_BITS) - 1)

enum byteorder {
        BYTEORDER_INVALID,
        BYTEORDER_HOST_ENDIAN,
        BYTEORDER_BIG_ENDIAN,
};

typedef bool (*set_comparator)(struct nftnl_rule *rul, int direction);

struct set_type {
  int type;
  const char *typestr;
  unsigned char element_len;
  const int byteorder;
  set_comparator cmp;
};

static bool load_lladdr(struct nftnl_rule *rul, int dir);
static bool load_ifname(struct nftnl_rule *rul, int dir);
static bool load_ip(struct nftnl_rule *rul, int dir);

const static struct set_type data_types[] = {
  { .type = TYPE_INVALID, .typestr = "invalid", .element_len = 0, 
    .byteorder = BYTEORDER_INVALID, .cmp = NULL },
  { .type = TYPE_LLADDR, .typestr = "lladdr", .element_len = 6,
     .byteorder = BYTEORDER_BIG_ENDIAN, .cmp = load_lladdr },
  { .type = TYPE_IPADDR, .typestr = "ip", .element_len = 4, 
    .byteorder = BYTEORDER_BIG_ENDIAN, .cmp = load_ip },
  { .type = TYPE_IP6ADDR, .typestr = "ip6", .element_len = 16, 
    .byteorder = BYTEORDER_BIG_ENDIAN },
  { .type = TYPE_IFNAME, .typestr = "ifname", .element_len = 16, 
    .byteorder = BYTEORDER_HOST_ENDIAN, .cmp = load_ifname},
  { 0, NULL, 0, 0 }
};


static bool load_lladdr(
    struct nftnl_rule *rul,
    int dir)
{
  struct nftnl_expr *exp[3] = {0};

  exp[0] = nftnl_expr_alloc("meta");
  exp[1] = nftnl_expr_alloc("cmp");
  exp[2] = nftnl_expr_alloc("payload");
  if (!exp[0] || !exp[1] || !exp[2])
    goto err;

  /* Load the meta payload and confirm device is a ethernet device */
  nftnl_expr_set_u32(exp[0], NFTNL_EXPR_META_KEY, 
                          dir ? NFT_META_OIFTYPE : 
                                NFT_META_IIFTYPE);
  nftnl_expr_set_u32(exp[0], NFTNL_EXPR_META_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp[0]);

  /* Compare its Arp type as being ETHERNET */
  nftnl_expr_set_u32(exp[1], NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp[1], NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
  /* the below MUST be set as a 16 bit char size for nft to work! */
  nftnl_expr_set_u16(exp[1], NFTNL_EXPR_CMP_DATA, ARPHRD_ETHER);
  nftnl_rule_add_expr(rul, exp[1]);

  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_LL_HEADER);
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_OFFSET, 
                           dir ? offsetof(struct ethhdr, h_dest) : 
                                 offsetof(struct ethhdr, h_source));
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_LEN, ETH_ALEN);
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp[2]);
  return true;

err:
  if (exp[0]) nftnl_expr_free(exp[0]);
  if (exp[1]) nftnl_expr_free(exp[1]);
  if (exp[2]) nftnl_expr_free(exp[2]);

  return false;
}

static bool load_ifname(
    struct nftnl_rule *rul,
    int dir)
{
  struct nftnl_expr *exp = NULL;
  exp = nftnl_expr_alloc("meta");
  if (!exp)
    goto err;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_META_KEY,
                     dir ? NFT_META_OIFNAME : NFT_META_IIFNAME);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_META_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp);

  return true;

err:
  if (exp) nftnl_expr_free(exp);
  return false;
}

static bool load_ip(
    struct nftnl_rule *rul,
    int dir)
{
  struct nftnl_expr *exp[3] = {0};

  exp[0] = nftnl_expr_alloc("meta");
  exp[1] = nftnl_expr_alloc("cmp");
  exp[2] = nftnl_expr_alloc("payload");
  if (!exp[0] || !exp[1] || !exp[2])
    goto err;

  /* Load the NFProto IP address onto register and check its an ipv4 */
  nftnl_expr_set_u32(exp[0], NFTNL_EXPR_META_KEY, NFT_META_NFPROTO);
  nftnl_expr_set_u32(exp[0], NFTNL_EXPR_META_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp[0]);

  /* Compare its IPv4 */
  nftnl_expr_set_u32(exp[1], NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp[1], NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
  /* the below MUST be set as a 8 bit char size for nft to work! */
  nftnl_expr_set_u8(exp[1], NFTNL_EXPR_CMP_DATA, AF_INET);
  nftnl_rule_add_expr(rul, exp[1]);

  /* Load the IP address onto the register */
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_OFFSET,
                             dir ? offsetof(struct iphdr, saddr) :
                                   offsetof(struct iphdr, daddr));
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
  nftnl_expr_set_u32(exp[2], NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp[2]);

  return true;

err:
  if (exp[0]) nftnl_expr_free(exp[0]);
  if (exp[1]) nftnl_expr_free(exp[1]);
  if (exp[2]) nftnl_expr_free(exp[2]);

  return false;
}

static inline const struct set_type * nf_datatype(
    const char *type)
{
  int i;
  const struct set_type *t;

  for (i=0; i < sizeof(data_types); i++) {
    t = &data_types[i];
    if (strcmp(t->typestr, type) == 0)
      return t;
  }

  return NULL;
}

static inline const struct set_type * nf_datatype_type(
    int type)
{
  int i;
  const struct set_type *t;

  for (i=0; i < sizeof(data_types); i++) {
    t = &data_types[i];
    if (t->type == type)
      return t;
  }

  return NULL;
}

static inline bool nf_badmsg(
    struct nlmsghdr *hdr,
    int msgtype) 
{
  if (NFNL_MSG_TYPE(hdr->nlmsg_type) != msgtype) {
    errno = EBADMSG;
    return true;
  }
  return false;
}

static inline int nf_verdict(
    const char *verdict)
{
  if (strlen(verdict) == 0)
    return NF_ACCEPT;

  if (strcmp(verdict, "drop") == 0)
    return NF_DROP;
  else if (strcmp(verdict, "accept") == 0)
    return NF_ACCEPT;
  else if (strcmp(verdict, "stolen") == 0)
    return NF_STOLEN;
  else if (strcmp(verdict, "queue") == 0)
    return NF_QUEUE;
  else if (strcmp(verdict, "repeat") == 0)
    return NF_REPEAT;
  else if (strcmp(verdict, "stop") == 0)
    return NF_STOP;
  else
    return NF_ACCEPT;
}

static inline int nf_hook(
    const char *hook)
{
  if (strlen(hook) == 0)
    return NF_INET_FORWARD;

  if (strcmp(hook, "pre") == 0)
    return NF_INET_PRE_ROUTING;
  else if (strcmp(hook, "in") == 0)
    return NF_INET_LOCAL_IN;
  else if (strcmp(hook, "forward") == 0)
    return NF_INET_FORWARD;
  else if (strcmp(hook, "out") == 0)
    return NF_INET_LOCAL_OUT;
  else if (strcmp(hook, "post") == 0)
    return NF_INET_POST_ROUTING;
  else
    return -1;
}

static inline int nf_policy(
    const char *policy)
{
  if (strlen(policy) == 0)
    return NF_ACCEPT;

  if (strcmp(policy, "accept") == 0)
    return NF_ACCEPT;
  else if (strcmp(policy, "drop") == 0)
    return NF_DROP;
  else
    return -1;
}

static inline int nf_family(
    const char *famstr)
{
  if (strlen(famstr) == 0)
    return NFPROTO_UNSPEC;

  if (strcmp(famstr, "inet") == 0)
    return NFPROTO_INET;
  else if (strcmp(famstr, "ip") == 0)
    return NFPROTO_IPV4;
  else if (strcmp(famstr, "arp") == 0)
    return NFPROTO_ARP;
  else if (strcmp(famstr, "netdev") == 0)
    return NFPROTO_NETDEV;
  else if (strcmp(famstr, "bridge") == 0)
    return NFPROTO_BRIDGE;
  else if (strcmp(famstr, "ip6") == 0)
    return NFPROTO_IPV6;
  else if (strcmp(famstr, "decnec") == 0)
    return NFPROTO_DECNET;
  else
    return NFPROTO_UNSPEC;
}

static inline const char * nf_nftables_type(
    int type)
{
  switch(type) {
    case NFT_MSG_NEWTABLE:
      return "nftables: new table";
    case NFT_MSG_GETTABLE:
      return "nftables: get table";
    case NFT_MSG_DELTABLE:
      return "nftables: delete table";
    case NFT_MSG_NEWCHAIN:
      return "nftables: new chain";
    case NFT_MSG_GETCHAIN:
      return "nftables: get chain";
    case NFT_MSG_DELCHAIN:
      return "nftables: delete chain";
    case NFT_MSG_NEWRULE:
      return "nftables: new rule";
    case NFT_MSG_GETRULE:
      return "nftables: get rule";
    case NFT_MSG_DELRULE:
      return "nftables: delete rule";
    case NFT_MSG_NEWSET:
      return "nftables: new set";
    case NFT_MSG_GETSET:
      return "nftables: get set";
    case NFT_MSG_DELSET:
      return "nftables: delete set";
    case NFT_MSG_NEWSETELEM:
      return "nftables: new element";
    case NFT_MSG_GETSETELEM:
      return "nftables: get element";
    case NFT_MSG_DELSETELEM:
      return "nftables: delet eelement";
    case NFT_MSG_NEWGEN:
      return "nftables: new genid";
    case NFT_MSG_GETGEN:
      return "nftables: get genid";
    case NFT_MSG_TRACE:
      return "nftables: trace event";
    case NFT_MSG_NEWOBJ:
      return "nftables: new object";
    case NFT_MSG_GETOBJ:
      return "nftables: get object";
    case NFT_MSG_DELOBJ:
      return "nftables: delete object";
    case NFT_MSG_GETOBJ_RESET:
      return "nftables: object reset";
    case NFT_MSG_NEWFLOWTABLE:
      return "nftables: new flow table";
    case NFT_MSG_GETFLOWTABLE:
      return "nftables: get flow table";
    case NFT_MSG_DELFLOWTABLE:
      return "nftables: delete flow table";

    default:
      return "nftables: unknown type";
  }
}



static int get_genid(
    nf_t nf)
{
  int nmsgs;
  struct nlmsghdr *hdr = NULL;
  struct nftnl_gen *obj = NULL;
  uint32_t gen;

  if (!nf) {
    errno = EINVAL;
    goto err;
  }

  obj = nftnl_gen_alloc();
  if (!obj)
    goto err;

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_GETGEN,
                        nf_family("inet"),
                        0,
                        nl_next_seqno(nf->nl));

  if (!nl_next_msg(nf->nl))
    goto err;

  if (nl_send(nf->nl) < 0)
    goto err;

  if (nl_recv(nf->nl, &hdr, &nmsgs) < 0)
    goto err;

  if (nmsgs > 1) {
    errno = EOVERFLOW;
    goto err;
  }

  if (nf_badmsg(hdr, NFT_MSG_NEWGEN))
    goto err;

  if (nftnl_gen_nlmsg_parse(hdr, obj) < 0)
    goto err;

  if (!nftnl_gen_is_set(obj, NFTNL_GEN_ID)) {
    errno = ENODATA;
    goto err;
  }

  gen = nftnl_gen_get_u32(obj, NFTNL_GEN_ID);
  nftnl_gen_free(obj);
  free(hdr);

  return gen;
err:
  if (hdr)
    free(hdr);
  if (obj)
    nftnl_gen_free(obj);
  return -1;
}

/* Helper utility to return message type */
const char * nf_nlmsg_type(
    uint16_t msgtype)
{
  int subsys = NFNL_SUBSYS_ID(msgtype);
  int type = NFNL_MSG_TYPE(msgtype);

  switch (subsys) {
    case NFNL_SUBSYS_NONE:
      return "no";
    case NFNL_SUBSYS_CTNETLINK:
      return "conntracking";
    case NFNL_SUBSYS_CTNETLINK_EXP:
      return "expanded conntracking";
    case NFNL_SUBSYS_QUEUE:
      return "queueing";
    case NFNL_SUBSYS_ULOG:
      return "logging";
    case NFNL_SUBSYS_OSF:
      return "operating system fingerprinting";
    case NFNL_SUBSYS_IPSET:
      return "ipsetting";
    case NFNL_SUBSYS_ACCT:
      return "accounting";
    case NFNL_SUBSYS_CTNETLINK_TIMEOUT:
      return "conntrack timeout";
    case NFNL_SUBSYS_CTHELPER:
      return "conntrack helper";
    case NFNL_SUBSYS_NFTABLES:
      return nf_nftables_type(type);
    case NFNL_SUBSYS_NFT_COMPAT:
      return "nftables (compat)";
    default:
      return "unknown subsystem";
  }
}

/* Destructor */
void nf_close(
  nf_t nf)
{
  if (nf) {
    if (nf->nl)
      nl_close(nf->nl);
    /* transaction close */
    free(nf);
  }
}

/* Constructor */
nf_t nf_open(
    int groups,
    int flags)
{
  nf_t nf = malloc(sizeof(struct nf));
  if (!nf)
    goto err;

  nf->nl = nl_open(NETLINK_NETFILTER, groups, flags);
  if (!nf->nl)
    goto err;

  nf->tx_no = -1;
  nf->nacks = 0;
  nf->gen = get_genid(nf);
  if (nf->gen < 0)
    goto err;

  return nf;
err:
  if (nf)
    nf_close(nf);
  return NULL;
}

/* Utility function to keep track of the generation ID netfilter produces */
bool nf_set_genid(
    nf_t nf,
    uint32_t genid)
{
  if (genid > nf->gen) {
    nf->gen = genid;
    return true;
  }

  nf->gen = genid;
  return false;
}

/* Starts a batch -- there must be room in the entire batch to fit 
 * inside of one datagram, so the buffer is adjusted to accomodate that */

bool nf_txn_begin(
    nf_t nf)
{

  if (!nf) {
    errno = EINVAL;
    goto err;
  }

  if (nf->tx_no > -1 || nf->nacks > 0) {
    errno = EINPROGRESS;
    goto err;
  }

  nftnl_batch_begin(nl_buf_current(nf->nl), nl_next_seqno(nf->nl));
  nf->tx_no++;
  if (!nl_next_msg(nf->nl))
    goto err;

  return true;

err:
  return false;
}

/* Aborts a transaction. We dont send the data until nf_transact() so
 * this just clears the buffer and resets the accounting */
void nf_txn_abort(
    nf_t nf)
{
  if (!nf)
    return;

  nf->nacks = 0;
  nf->tx_no = -1;
  nl_buf_clear(nf->nl);  
}

/* Ends a transaction buffer */
bool nf_txn_commit(
//bool __attribute__((optimize("O0"))) nf_txn_commit(
    nf_t nf)
{
  //__attribute__((unused)) struct nlmsghdr *hdr;

  if (!nf) {
    errno = EINVAL;
    goto err;
  }

  nftnl_batch_end(nl_buf_current(nf->nl), nl_next_seqno(nf->nl));
  if (!nl_next_msg(nf->nl))
    goto err;

  return true;

err:
  return false;
}

/* Creates a new set using the referenced table */
struct nftnl_set * nf_set_init(
    nf_t nf, 
    const struct nftnl_table *tbl,
    const char *name,
    const char *settype)
{
  struct nlmsghdr *hdr;
  const struct set_type *type = NULL;
  struct nftnl_set *obj = NULL;
  struct nftnl_udata_buf *com = NULL;
  const char *tname;
  int family = 0;

  if (!tbl || !settype) {
    errno = EINVAL;
    goto err;
  }

  /* Lookup type struct to refer to rules of the set */
  type = nf_datatype(settype);
  if (!type) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_table_get_u32(tbl, NFTNL_TABLE_FAMILY);
  tname = nftnl_table_get_str(tbl, NFTNL_TABLE_NAME);
  if (!tname) {
    errno = EINVAL;
    goto err;
  }

  if (name && strlen(name) > NFT_SET_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_set_alloc();
  com = nftnl_udata_buf_alloc(32);
  if (!obj || !com)
    goto err;

  /* When the name isn't set, its an anonymous set */
  if (nftnl_set_set_str(obj, NFTNL_SET_NAME, name ? name : "__set%d") < 0)
    goto err;
  if (nftnl_set_set_str(obj, NFTNL_SET_TABLE, tname) < 0)
    goto err;
  nftnl_set_set_u32(obj, NFTNL_SET_FLAGS, name ? NFT_SET_CONSTANT :
                         NFT_SET_ANONYMOUS|NFT_SET_CONSTANT);

  nftnl_set_set_u32(obj, NFTNL_SET_KEY_TYPE, type->type);
  nftnl_set_set_u32(obj, NFTNL_SET_FAMILY, family);
  nftnl_set_set_u32(obj, NFTNL_SET_ID, nf->tx_no);
  nftnl_set_set_u32(obj, NFTNL_SET_KEY_LEN, type->element_len);

  /* byte order hint for nft.. */
  nftnl_udata_put_u32(com, NFTNL_UDATA_SET_KEYBYTEORDER, type->byteorder);
  nftnl_set_set_data(obj, NFTNL_SET_USERDATA,
                     nftnl_udata_buf_data(com),
                     nftnl_udata_buf_len(com));

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWSET,
                        family,
                        NLM_F_CREATE|NLM_F_ACK,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_set_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return obj;

err:
  if (obj)
    nftnl_set_free(obj);
  if (com)
    nftnl_udata_buf_free(com);
  return NULL;
}


/* Add the log expression to a rule */
bool nf_rule_add_log(
    struct nftnl_rule *rul, 
    uint16_t log_group, 
    const char *prefix)
{
  struct nftnl_expr *exp = NULL;

  if (!rul) {
    errno = EINVAL;
    goto err;
  }

  exp = nftnl_expr_alloc("log");
  if (!exp)
    goto err;

  if (strlen(prefix) > NFT_NAME_MAXLEN) {
    errno = E2BIG;
    goto err;
  }

  nftnl_expr_set_u16(exp, NFTNL_EXPR_LOG_GROUP, log_group);
  nftnl_expr_set_str(exp, NFTNL_EXPR_LOG_PREFIX, prefix);
  nftnl_rule_add_expr(rul, exp);

  return true;
err:
  if (exp)
    nftnl_expr_free(exp);
  return false;
}

/* Add the limit expression to a rule */
bool nf_rule_add_limit(
    struct nftnl_rule *rul, 
    int rate, 
    int unit)
{
  struct nftnl_expr *exp = NULL;

  if (!rul || rate < 1 || unit < 1) {
    errno = EINVAL;
    goto err;
  }

  exp = nftnl_expr_alloc("limit");
  if (!exp)
    goto err;

  nftnl_expr_set_u64(exp, NFTA_LIMIT_RATE, rate);
  nftnl_expr_set_u64(exp, NFTA_LIMIT_UNIT, unit);
  nftnl_expr_set_u32(exp, NFTA_LIMIT_TYPE, NFT_LIMIT_PKTS);
  nftnl_rule_add_expr(rul, exp);

  return true;
err:
  if (exp)
    nftnl_expr_free(exp);
  return false;
}


/* Add named quota action to a rule */
bool nf_rule_add_quota(
    struct nftnl_rule *rul, 
    struct nftnl_obj *quo)
{
  struct nftnl_expr *exp = NULL;
  const char *qname = NULL;

  if (!rul || !quo) {
    errno = EINVAL;
    goto err;
  }

  if (!nftnl_obj_is_set(quo, NFTNL_OBJ_NAME)) {
    errno = EINVAL;
    goto err;
  }

  if (!nftnl_obj_is_set(quo, NFTNL_OBJ_TYPE)) {
    errno = EINVAL; 
    goto err;
  }

  if (nftnl_obj_get_u32(quo, NFTNL_OBJ_TYPE) != NFT_OBJECT_QUOTA) {
    errno = EINVAL;
    goto err;
  }

  qname = nftnl_obj_get_str(quo, NFTNL_OBJ_NAME);
  exp = nftnl_expr_alloc("objref");
  if (!exp)
    goto err;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_OBJREF_IMM_TYPE, NFT_OBJECT_QUOTA);
  nftnl_expr_set_str(exp, NFTNL_EXPR_OBJREF_IMM_NAME, qname);
  nftnl_rule_add_expr(rul, exp);
  exp = NULL;

  return true;
err:
  if (exp)
    nftnl_expr_free(exp);
  return false;
}

/* Add set to a rule */
bool nf_rule_add_set(
    struct nftnl_rule *rul, 
    int dir,
    struct nftnl_set *set)
{
  struct nftnl_expr *exp = NULL;
  const char *sname = NULL;
  const struct set_type *type = NULL;
  int sid = -1;

  if (!rul || !set) {
    errno = EINVAL;
    goto err;
  }

  if (!nftnl_set_is_set(set, NFTNL_SET_NAME)) {
    errno = EINVAL;
    goto err;
  }

  if (!nftnl_set_is_set(set, NFTNL_SET_ID)) {
    errno = EINVAL;
    goto err;
  }

  /* Determine data type */
  if (!nftnl_set_is_set(set, NFTNL_SET_KEY_TYPE)) {
    errno = EINVAL;
    goto err;
  }

  type = nf_datatype_type(nftnl_set_get_u32(set, NFTNL_SET_KEY_TYPE));
  if (!type) {
    errno = EINVAL;
    goto err;
  }

  sname = nftnl_set_get_str(set, NFTNL_SET_NAME);
  sid = nftnl_set_get_u32(set, NFTNL_SET_ID);

  /* Load the comparator callback if one exists */
  if (type->cmp) {
    if (!type->cmp(rul, dir)) 
      goto err;
  }

  exp = nftnl_expr_alloc("lookup");
  if (!exp)
    goto err;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_LOOKUP_SREG, NFT_REG_1);
  nftnl_expr_set_str(exp, NFTNL_EXPR_LOOKUP_SET, sname);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_LOOKUP_SET_ID, sid);
  nftnl_rule_add_expr(rul, exp);
  exp = NULL;

  return true;
err:
  if (exp)
    nftnl_expr_free(exp);
  return false;
}


/* Add element to a set */
bool nf_set_add(
    struct nftnl_set *set,
    const void *data,
    int dlen)
{
  unsigned char *buf;
  struct nftnl_set_elem *obj = NULL;
  const struct set_type *type = NULL;

  if (!set || !data || dlen < 1) {
    errno = EINVAL;
    goto err;
  }

  /* Determine data type */
  if (!nftnl_set_is_set(set, NFTNL_SET_KEY_TYPE)) {
    errno = EINVAL;
    goto err;
  }

  type = nf_datatype_type(nftnl_set_get_u32(set, NFTNL_SET_KEY_TYPE));
  if (!type) {
    errno = EINVAL;
    goto err;
  }

  if (dlen > type->element_len) {
    errno = E2BIG;
    goto err;
  }

  /* Doing this ensures we fill the entire buffer -- seems to be a requirement */
  buf = alloca(type->element_len);
  memset(buf, 0, type->element_len);
  memcpy(buf, data, dlen);

  obj = nftnl_set_elem_alloc();
  if (!obj)
    goto err;

  if (nftnl_set_elem_set(obj, NFTNL_SET_ELEM_KEY, buf, type->element_len) < 0)
    goto err;

  nftnl_set_elem_add(set, obj);

  return true;

err:
  if (obj)
    nftnl_set_elem_free(obj);
  return false;
}


/* Create a new rule object */
struct nftnl_rule * nf_rule_init(
    nf_t nf, 
    const struct nftnl_chain *cha,
    const char *comment)
{
  struct nftnl_rule *obj = NULL;
  struct nftnl_udata_buf *com = NULL;
  const char *tname;
  const char *cname;
  int family = 0;

  if (!cha) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_chain_get_u32(cha, NFTNL_CHAIN_FAMILY);
  tname = nftnl_chain_get_str(cha, NFTNL_CHAIN_TABLE);
  cname = nftnl_chain_get_str(cha, NFTNL_CHAIN_NAME);
  if (!tname || !cname) {
    errno = EINVAL;
    goto err;
  }

  if (comment && strlen(comment) > NFT_USERDATA_MAXLEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_rule_alloc();
  if (!obj)
    goto err;

  if (nftnl_rule_set_str(obj, NFTNL_RULE_TABLE, tname) < 0)
    goto err;
  if (nftnl_rule_set_str(obj, NFTNL_RULE_CHAIN, cname) < 0)
    goto err;
  nftnl_rule_set_u32(obj, NFTNL_RULE_FAMILY, family);
  nftnl_rule_set_u32(obj, NFTNL_RULE_ID, nf->tx_no);

  /* Set comment */
  if (comment) {
    com = nftnl_udata_buf_alloc(strlen(comment) + 4);
    if (!com)
      goto err;

    if (!nftnl_udata_put_strz(com, NFTNL_UDATA_RULE_COMMENT, comment))
      goto err;

    if(nftnl_rule_set_data(obj, NFTNL_RULE_USERDATA,
                        nftnl_udata_buf_data(com),
                        nftnl_udata_buf_len(com)) < 0)
      goto err;
  }

  nf->tx_no++;
  return obj;

err:
  if (obj)
    nftnl_rule_free(obj);
  if (com) {
    nftnl_udata_buf_free(com);
  }
  return NULL;
}


/* Put set into nlmsg buffer */
bool nf_set_create(
    nf_t nf,
    struct nftnl_set *set)
{
  struct nlmsghdr *hdr;
  int family = 0;

  if (!set) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_set_get_u32(set, NFTNL_SET_FAMILY);
  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWSET,
                        family,
                        NLM_F_CREATE|NLM_F_ACK,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_set_nlmsg_build_payload(hdr, set);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;

  /* Now add the elements of said set to buffer */
  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWSETELEM,
                        family,
                        NLM_F_CREATE|NLM_F_ACK,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_set_elems_nlmsg_build_payload(hdr, set);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return true;

err:
  return false;
}


/* Erase a rule from the table */
bool nf_rule_delete(
    nf_t nf,
    struct nftnl_rule *rul)
{
  struct nlmsghdr *hdr;
  int family = 0;

  if (!rul) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_rule_get_u32(rul, NFTNL_RULE_FAMILY);
  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_DELRULE,
                        family,
                        NLM_F_ACK,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_rule_nlmsg_build_payload(hdr, rul);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return true;

err:
  return false;
}


/* Replace a rule in the table */
bool nf_rule_replace(
    nf_t nf,
    struct nftnl_rule *rul)
{
  struct nlmsghdr *hdr;
  int family = 0;
  uint64_t handle = 0;

  if (!rul) {
    errno = EINVAL;
    goto err;
  }

  if (!nftnl_rule_is_set(rul, NFTNL_RULE_HANDLE)) {
    errno  = EINVAL;
    goto err;
  }

  handle = nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE);
  if (handle == 0) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_rule_get_u32(rul, NFTNL_RULE_FAMILY);
  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWRULE,
                        family,
                        NLM_F_REPLACE|NLM_F_ACK,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_rule_nlmsg_build_payload(hdr, rul);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->tx_no++;
  nf->nacks++;
  return true;

err:
  return false;
}


/* Add a rule to the bottom table */
bool nf_rule_create(
    nf_t nf, 
    struct nftnl_rule *rul)
{
  struct nlmsghdr *hdr;
  int family = 0;

  if (!rul) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_rule_get_u32(rul, NFTNL_RULE_FAMILY);
  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWRULE,
                        family,
                        NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL|NLM_F_APPEND,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_rule_nlmsg_build_payload(hdr, rul);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return true;

err:
  return false;
}


/* Reset quota object. Returns quota object */
bool nf_quota_reset(
    nf_t nf, 
    struct nftnl_obj *obj)
{
  struct nlmsghdr *hdr;
  struct nftnl_obj *new = NULL;
  int family = 0, nmsgs = 0;

  if (!obj) {
    errno = EINVAL;
    goto err;
  }

  new = nftnl_obj_alloc();
  if (!new)
    goto err;

  family = nftnl_obj_get_u32(obj, NFTNL_OBJ_FAMILY);
  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_GETOBJ_RESET,
                        family,
                        0,
                        nl_next_seqno(nf->nl));

  if (!hdr)
    goto err;
  nftnl_obj_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  if (nl_send(nf->nl) < 0)
    goto err;

  if (nl_recv(nf->nl, &hdr, &nmsgs) < 0)
    goto err;

  if (nmsgs > 1) {
    errno = EOVERFLOW;
    goto err;
  }

  if (nf_badmsg(hdr, NFT_MSG_NEWOBJ))
    goto err;

  if (nftnl_obj_nlmsg_parse(hdr, obj) < 0)
    goto err;

  nftnl_obj_free(new);
  return true;
err:
  if (new)
    nftnl_obj_free(new);
  return false;
}


/* Create new named quota object */
struct nftnl_obj * nf_quota_create(
    nf_t nf,
    const struct nftnl_table *tbl,
    const char *quota,
    uint64_t limit,
    uint64_t used)
{
  struct nlmsghdr *hdr;
  struct nftnl_obj *obj = NULL;
  const char *tname;
  int family = 0;

  if (!tbl || !quota) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_table_get_u32(tbl, NFTNL_TABLE_FAMILY);
  tname = nftnl_table_get_str(tbl, NFTNL_TABLE_NAME);
  if (!tname) {
    errno = EINVAL;
    goto err;
  }

  if (strlen(quota) >= NFT_OBJ_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_obj_alloc();
  if (!obj)
    goto err;

  nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, quota);
  nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, tname);
  nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_QUOTA);
  nftnl_obj_set_u32(obj, NFTNL_OBJ_FAMILY, family);
  nftnl_obj_set_u64(obj, NFTNL_OBJ_QUOTA_BYTES, limit);
  nftnl_obj_set_u64(obj, NFTNL_OBJ_QUOTA_CONSUMED, used);
  /* Make the quota an OVER value */
  nftnl_obj_set_u32(obj, NFTNL_OBJ_QUOTA_FLAGS, NFT_QUOTA_F_INV);

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWOBJ,
                        family,
                        NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_obj_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return obj;

err:
  if (obj)
    nftnl_obj_free(obj);
  return NULL;
}



/* Create a new chain with policy */
struct nftnl_chain * nf_chain_create(
    nf_t nf, 
    const struct nftnl_table *tbl,
    const char *chain,
    const char *hook, 
    const char *type,
    int priority, 
    const char *policy)
{
  struct nlmsghdr *hdr;
  struct nftnl_chain *obj = NULL;
  const char *tname;
  int family = 0;

  if (!tbl || !chain) {
    errno = EINVAL;
    goto err;
  }

  family = nftnl_table_get_u32(tbl, NFTNL_TABLE_FAMILY);
  tname = nftnl_table_get_str(tbl, NFTNL_TABLE_NAME);
  if (!tname) {
    errno = EINVAL;
    goto err;
  }

  if (strlen(chain) >= NFT_CHAIN_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  /* If any of hook, type or policy are set, all must be set */
  if ((hook || type || policy) && (!hook || !type || !policy)) {
    errno = EINVAL;
    goto err;
  }

  obj = nftnl_chain_alloc();
  if (!obj)
    goto err;

  if (nftnl_chain_set_str(obj, NFTNL_CHAIN_NAME, chain) < 0)
    goto err;

  if (nftnl_chain_set_str(obj, NFTNL_CHAIN_TABLE, tname) < 0)
    goto err;

  if (type) {
    if (nftnl_chain_set_str(obj, NFTNL_CHAIN_TYPE, type) < 0)
      goto err;
  }

  nftnl_chain_set_u32(obj, NFTNL_CHAIN_FAMILY, family);
  if (hook || type || policy)
    nftnl_chain_set_u32(obj, NFTNL_CHAIN_PRIO, priority);
  if (hook)
    nftnl_chain_set_u32(obj, NFTNL_CHAIN_HOOKNUM, nf_hook(hook));
  if (policy)
    nftnl_chain_set_u32(obj, NFTNL_CHAIN_POLICY, nf_policy(policy));

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWCHAIN,
                        family,
                        NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_chain_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return obj;

err:
  if (obj)
    nftnl_chain_free(obj);
  return NULL;
}


/* Create a new table */
struct nftnl_table * nf_table_create(
    nf_t nf,
    const char *family,
    const char *name)
{
  struct nlmsghdr *hdr;
  struct nftnl_table *obj = NULL;

  if (strlen(name) >= NFT_TABLE_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_table_alloc();
  if (!obj)
    goto err;

  if (nftnl_table_set_str(obj, NFTNL_TABLE_NAME, name) < 0)
    goto err;

  nftnl_table_set_u32(obj, NFTNL_TABLE_FLAGS, 0);
  nftnl_table_set_u32(obj, NFTNL_TABLE_FAMILY, nf_family(family));

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_NEWTABLE,
                        nf_family(family),
                        NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_table_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  nf->nacks++;
  nf->tx_no++;
  return obj;

err:
  if (obj)
    nftnl_table_free(obj);
  return NULL;
}


int nf_get_fd(
    nf_t nf)
{
  return nl_get_fd(nf->nl);
}


int nf_send(
    nf_t nf)
{
  return nl_send(nf->nl);
}

int nf_recv(nf_t nf, 
    struct nlmsghdr **payload, 
    int *nmsgs)
{
  return nl_recv(nf->nl, payload, nmsgs);
}


/* Send a message if we have transactions in queue */
bool nf_transact(
    nf_t nf)
{

  /* If no items are transactable, silently discard and return OK */
  if (nf->tx_no <= 0) {
    nf_txn_abort(nf);
    return true;
  }

  if (nl_send(nf->nl) < 0)
    return false;

  /* Cosume all the acks. Expect to get all acks here */
  if (nl_recv_ack(nf->nl, nf->nacks) < 0)
    return false;

  nf->nacks = 0;
  nf->tx_no = -1;

  return true;
}


/* Fetch a named quota */
struct nftnl_obj * nf_quota_get(
    nf_t nf, 
    const struct nftnl_table *tbl, 
    const char *quota)
{
  int nmsgs;
  struct nlmsghdr *hdr = NULL;
  struct nftnl_obj *obj = NULL;
  const char *tname;
  int family = 0;

  if (!tbl || !quota) {
    errno = EINVAL;
    goto err;
  }

  if (strlen(quota) >= NFT_OBJ_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_obj_alloc();
  if (!obj)
    goto err;

  family = nftnl_table_get_u32(tbl, NFTNL_TABLE_FAMILY);
  tname = nftnl_table_get_str(tbl, NFTNL_TABLE_NAME);
  if (!tname) {
    errno = EINVAL;
    goto err;
  }

  nftnl_obj_set_str(obj, NFTNL_OBJ_NAME, quota);
  nftnl_obj_set_str(obj, NFTNL_OBJ_TABLE, tname); 
  nftnl_obj_set_u32(obj, NFTNL_OBJ_FAMILY, family);
  nftnl_obj_set_u32(obj, NFTNL_OBJ_TYPE, NFT_OBJECT_QUOTA);

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_GETOBJ,
                        family,
                        0,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_obj_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  if (nl_send(nf->nl) < 0)
    goto err;

  if (nl_recv(nf->nl, &hdr, &nmsgs) < 0)
    goto err;

  if (nmsgs > 1) {
    errno = EOVERFLOW;
    goto err;
  }

  if (nf_badmsg(hdr, NFT_MSG_NEWOBJ))
    goto err;

  if (nftnl_obj_nlmsg_parse(hdr, obj) < 0)
    goto err;

  free(hdr);
  return obj;

err:
  if (hdr)
    free(hdr);
  if (obj)
    nftnl_obj_free(obj);
  return NULL;

}


/* Fetch a named chain */
struct nftnl_chain * nf_chain_get(
    nf_t nf,
    const struct nftnl_table *tbl,
    const char *chain)
{
  int nmsgs;
  struct nlmsghdr *hdr = NULL;
  struct nftnl_chain *obj = NULL;
  const char *tname;
  int family = 0;

  if (!tbl || !chain) {
    errno = EINVAL;
    goto err;
  }

  if (strlen(chain) >= NFT_CHAIN_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_chain_alloc();
  if (!obj)
    goto err;

  family = nftnl_table_get_u32(tbl, NFTNL_TABLE_FAMILY);
  tname = nftnl_table_get_str(tbl, NFTNL_TABLE_NAME);
  if (!tname) {
    errno = EINVAL;
    goto err;
  }

  if (nftnl_chain_set_str(obj, NFTNL_CHAIN_NAME, chain) < 0)
    goto err;

  if (nftnl_chain_set_str(obj, NFTNL_CHAIN_TABLE, tname) < 0)
    goto err;

  nftnl_chain_set_u32(obj, NFTNL_CHAIN_FAMILY, family);

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_GETCHAIN,
                        family,
                        0,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_chain_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  if (nl_send(nf->nl) < 0)
    goto err;

  if (nl_recv(nf->nl, &hdr, &nmsgs) < 0)
    goto err;

  if (nmsgs > 1) {
    errno = EOVERFLOW;
    goto err;
  }

  if (nf_badmsg(hdr, NFT_MSG_NEWCHAIN))
    goto err;

  if (nftnl_chain_nlmsg_parse(hdr, obj) < 0)
    goto err;

  free(hdr);
  return obj;

err:
  if (hdr)
    free(hdr);
  if (obj)
    nftnl_chain_free(obj);
  return NULL;
}


/* Returns a malloced list of rules for said chain */
bool nf_rule_list(
    nf_t nf, 
    const struct nftnl_chain *cha,
    struct nftnl_rule ***res, 
    int *nrules)
{
  int rc, i=0;
  struct nlmsghdr *hdrs = NULL, *hdr = NULL;
  struct nftnl_rule *obj = NULL;
  struct nftnl_rule **objs = NULL;
  const char *tname;
  const char *cname;
  int family = 0;
  int nmsgs = 0;

  if (!nf || !cha) {
    errno = EINVAL;
    goto err;
  }

  tname = nftnl_chain_get_str(cha, NFTNL_CHAIN_TABLE);
  cname = nftnl_chain_get_str(cha, NFTNL_CHAIN_NAME);
  family = nftnl_chain_get_u32(cha, NFTNL_CHAIN_FAMILY);

  obj = nftnl_rule_alloc();
  if (!obj)
    goto err;

  if (nftnl_rule_set_str(obj, NFTNL_RULE_TABLE, tname) < 0)
    goto err;

  if (nftnl_rule_set_str(obj, NFTNL_RULE_CHAIN, cname) < 0)
    goto err;

  nftnl_rule_set_u32(obj, NFTNL_RULE_FAMILY, family);

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_GETRULE,
                        family,
                        NLM_F_DUMP,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_rule_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  if (nl_send(nf->nl) < 0)
    goto err;

  rc = nl_recv(nf->nl, &hdrs, &nmsgs);
  if (rc < 0)
    goto err;

  hdr = hdrs;
  i = 0;
  /* Parse any rules found */
  if (nmsgs) {
    objs = calloc(nmsgs, sizeof(struct nftnl_rule *));
    if (!objs)
      goto err;

    while (mnl_nlmsg_ok(hdr, rc)) {
      objs[i] = nftnl_rule_alloc();
      if (!objs[i])
        goto err;
      if (nftnl_rule_nlmsg_parse(hdr, objs[i]) < 0)
        goto err;
      hdr = mnl_nlmsg_next(hdr, &rc);
      i++;
    }
  }

  free(hdrs);
  free(obj);
  *nrules = nmsgs;
  *res = objs;
  return true;
  
err:
  if (hdrs)
    free(hdrs);
  if (objs) {
    for (i=0; i < nmsgs; i++) {
      if (objs[i]) nftnl_rule_free(objs[i]);
    }
    free(objs);
  }
  if (obj)
    nftnl_rule_free(obj);
  return false;
}


/* Retrieve named table from family */
struct nftnl_table * nf_table_get(
    nf_t nf,
    const char *family,
    const char *name)
{
  int nmsgs;
  struct nlmsghdr *hdr = NULL;
  struct nftnl_table *obj = NULL;

  if (strlen(name) >= NFT_TABLE_MAXNAMELEN) {
    errno = E2BIG;
    goto err;
  }

  obj = nftnl_table_alloc();
  if (!obj)
    goto err;

  if (nftnl_table_set_str(obj, NFTNL_TABLE_NAME, name) < 0)
    goto err;

  nftnl_table_set_u32(obj, NFTNL_TABLE_FAMILY, nf_family(family));

  hdr = nftnl_nlmsg_build_hdr(nl_buf_current(nf->nl),
                        NFT_MSG_GETTABLE,
                        nf_family(family),
                        0,
                        nl_next_seqno(nf->nl));
  if (!hdr)
    goto err;
  nftnl_table_nlmsg_build_payload(hdr, obj);

  if (!nl_next_msg(nf->nl))
    goto err;

  if (nl_send(nf->nl) < 0)
    goto err;

  if (nl_recv(nf->nl, &hdr, &nmsgs) < 0)
    goto err;

  if (nmsgs > 1) {
    errno = EOVERFLOW;
    goto err;
  }

  if (nf_badmsg(hdr, NFT_MSG_NEWTABLE))
    goto err;

  if (nftnl_table_nlmsg_parse(hdr, obj) < 0)
    goto err;

  free(hdr);
  return obj;
err:
  if (hdr)
    free(hdr);
  if (obj)
    nftnl_table_free(obj);
  return NULL;
}


/* Add the verdict object to a rule */
bool nf_rule_verdict(
    struct nftnl_rule *rul, 
    const char *verdict)
{
  struct nftnl_expr *obj = NULL;

  if (!rul || !verdict) {
    errno = EINVAL;
    goto err;
  }

  if (strcmp(verdict, "reject") == 0) {
    obj = nftnl_expr_alloc("reject");
    nftnl_expr_set_u32(obj, NFTNL_EXPR_REJECT_TYPE, NFT_REJECT_ICMPX_UNREACH);
    nftnl_expr_set_u32(obj, NFTNL_EXPR_REJECT_CODE, NFT_REJECT_ICMPX_ADMIN_PROHIBITED);
  }
  else {
    obj = nftnl_expr_alloc("immediate");
    nftnl_expr_set_u32(obj, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(obj, NFTNL_EXPR_IMM_VERDICT, nf_verdict(verdict));
  }

  nftnl_rule_add_expr(rul, obj);

  return true;
err:
  if (obj)
    nftnl_expr_free(obj);
  return false;
}


/* Custom userdata value we set for a timestamp.
 * Lets us track how long a rule has existed in nftables for,
 * nft wont show this on a rule dump */
bool nf_rule_set_timestamp(
    struct nftnl_rule *rul)
{
  struct nftnl_udata_buf *ud = NULL;
  const void *data;
  uint32_t len;
  time_t now = time(NULL);
  
  if (!rul)
    goto err;

  /* copy current buffer */
  if (nftnl_rule_is_set(rul, NFTNL_RULE_USERDATA)) {
    data = nftnl_rule_get_data(rul, NFTNL_RULE_USERDATA, &len);
    ud = nftnl_udata_buf_alloc(len + sizeof(time_t)+16);
    if (!ud)
      goto err;
    nftnl_udata_buf_put(ud, data, len);

    /* Drop the old udata */
    nftnl_rule_unset(rul, NFTNL_RULE_USERDATA);
  }
  else {
    ud = nftnl_udata_buf_alloc(16);
    if (!ud)
      goto err;
  }

  if (!nftnl_udata_put(ud, NF_UDATA_TIMESTAMP, sizeof(now), &now))
    goto err;

  /* Update udata buffer */
  nftnl_rule_set_data(rul, NFTNL_RULE_USERDATA,
                     nftnl_udata_buf_data(ud),
                     nftnl_udata_buf_len(ud));
  
  return true;

err:
  if (ud)
    free(ud);
  return false;
}


/* Retrieve the timestamp value we set */
time_t nf_rule_get_timestamp(
    struct nftnl_rule *rul)
{
  struct nftnl_udata *att = NULL;
  const void *data = NULL;
  const void *d = NULL; 
  time_t then = 0;
  uint32_t len;

  if (!rul)
    goto err;

  if (!nftnl_rule_is_set(rul, NFTNL_RULE_USERDATA))
    goto err;

  data = nftnl_rule_get_data(rul, NFTNL_RULE_USERDATA, &len);
  nftnl_udata_for_each_data(data, len, att) {
    if (nftnl_udata_type(att) == NF_UDATA_TIMESTAMP) {
      d = nftnl_udata_get(att);
      then = *(time_t *)d;
      return then;
    }
  }

err:
  return -1;
}


/* Utility function to extract comment from rule */
const char * nf_rule_get_comment(
    struct nftnl_rule *rul)
{
  struct nftnl_udata *att = NULL;
  const void *data = NULL;
  const char *comment;
  uint32_t len;

  if (!rul)
    goto err;

  if (!nftnl_rule_is_set(rul, NFTNL_RULE_USERDATA))
    goto err;

  data = nftnl_rule_get_data(rul, NFTNL_RULE_USERDATA, &len);
  nftnl_udata_for_each_data(data, len, att) {
    if (nftnl_udata_type(att) == NFTNL_UDATA_RULE_COMMENT) {
      comment = nftnl_udata_get(att);
      return comment;
    }
  }

err:
  return NULL;
}


/* Binds a netfilter socket to nflog code, a bit more 
 * efficient than the dedicated library for it */
bool nf_nflog_bind(
    nf_t nf,
    uint16_t groupno,
    uint32_t qthresh,
    uint32_t tout,
    int mode,
    uint16_t size)
{
  struct nlmsghdr *hdr = NULL;
  struct nfgenmsg *msg = NULL;
  struct nfulnl_msg_config_cmd cmd = {0};
  struct nfulnl_msg_config_mode mod = {0};

  /* Bind to the multicast group for nflogging */
  if (!nl_set_group(nf->nl, NFNLGRP_NFTABLES))
    return false;

  /* Header */
  hdr = mnl_nlmsg_put_header(
          nl_buf_current(nf->nl));
  hdr->nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
  hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  hdr->nlmsg_seq = nl_next_seqno(nf->nl);
  /* Netfilter payload */
  msg = mnl_nlmsg_put_extra_header(hdr, sizeof(struct nfgenmsg));
  msg->nfgen_family = nf_family("inet");
  msg->version = NFNETLINK_V0;
  msg->res_id = bswap_16(groupno);
  /* Additional attributes */
  cmd.command = NFULNL_CFG_CMD_BIND;
  mod.copy_range = bswap_16(size);
  mod.copy_mode = mode;

  if (tout == 0) tout = 100;

  if (qthresh == 0) qthresh = 5;

  if (!hdr) return false;

  /* Build a config message */
  mnl_attr_put(hdr, NFULA_CFG_CMD, sizeof(cmd), &cmd);
  mnl_attr_put_u32(hdr, NFULA_CFG_TIMEOUT, bswap_32(tout));
  mnl_attr_put_u32(hdr, NFULA_CFG_TIMEOUT, bswap_32(qthresh));
  mnl_attr_put(hdr, NFULA_CFG_MODE, sizeof(mod), &mod);

  if (!nl_next_msg(nf->nl)) return false;

  if (nl_send(nf->nl) < 0) return false;

  if (nl_recv_ack(nf->nl, 1) < 0) return false;

  return true;
}


/* Return prefix from the log output, only attribute we
 * support! */
const char * nf_nflog_prefix(
    struct nlmsghdr *hdr)
{
  struct nlattr *att;
  mnl_attr_for_each(att, hdr, sizeof(struct nfgenmsg)) {
    switch (mnl_attr_get_type(att)) {
      case NFULA_PREFIX:
        if (mnl_attr_validate(att, MNL_TYPE_NUL_STRING) < 0) {
          perror("mnl_attr_validate");
          return NULL;
        }
        return mnl_attr_get_str(att);
      break;

      default:
        continue;
      break;
    }
  }

  return NULL;
}


/* Utility function prints the bytecode for the rule out */
void nf_debug_rule(
    const struct nftnl_rule *rul)
{
    struct nftnl_expr *expr;
    struct nftnl_expr_iter *iter = nftnl_expr_iter_create(rul);

    printf("Iterating rule handle: %lu, family: %d\n", nftnl_rule_get_u64(rul, NFTNL_RULE_HANDLE),
                                                        nftnl_rule_get_u32(rul, NFTNL_RULE_FAMILY));
    while ((expr = nftnl_expr_iter_next(iter))) {
      printf("[ %s ", nftnl_expr_get_str(expr, NFTNL_EXPR_NAME));
      nftnl_expr_fprintf(stdout, expr, 0, 0);
      printf(" ]\n");
    }
    printf("\n");
    nftnl_expr_iter_destroy(iter);
}
