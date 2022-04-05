#ifndef _NF_H_
#define _NF_H_

#include <stdbool.h>
#include "nl.h"

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/object.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/udata.h>
#include <libnftnl/expr.h>
#include <libnftnl/gen.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_log.h>

#define NF_SRC 0
#define NF_DST 1

#define NF_UDATA_TIMESTAMP 2
#define NF_NFTABLES (1 << (NFNLGRP_NFTABLES-1))
#define NF_NFQUOTA (1 << (NFNLGRP_ACCT_QUOTA-1))

#define NF_COPY_NONE NFULNL_COPY_NONE
#define NF_COPY_META NFULNL_COPY_META
#define NF_COPY_PACKET NFULNL_COPY_PACKET

struct nf {
  nl_t nl;
  uint32_t gen;
  int nacks;
  int tx_no;
};

typedef struct nf * nf_t;

const char * nf_nlmsg_type(uint16_t msgtype);

nf_t nf_open(int groups, int flags);
void nf_close(nf_t nf);
int nf_send(nf_t nf);
int nf_recv(nf_t nf, struct nlmsghdr **payload, int *nmsgs);
bool nf_transact(nf_t nf);
bool nf_set_genid(nf_t nf, uint32_t genid);

int nf_get_fd(nf_t nf);

bool nf_txn_begin(nf_t nf);
void nf_txn_abort(nf_t nf);
bool nf_txn_commit(nf_t nf);

struct nftnl_table * nf_table_create(nf_t nf, const char *family, const char *table);
struct nftnl_chain * nf_chain_create(nf_t nf, const struct nftnl_table *tbl, 
                              const char *chain, 
                              const char *hook, 
                              const char *type,
                              int priority, 
                              const char *policy);

struct nftnl_obj * nf_quota_create(nf_t nf, const struct nftnl_table *tbl,
                              const char *quota,
                              uint64_t limit,
                              uint64_t used);

bool nf_quota_reset(nf_t nf, struct nftnl_obj *obj);

struct nftnl_set * nf_set_init(nf_t nf, const struct nftnl_table *tbl,
                               const char *name,
                               const char *type);
bool nf_set_create(nf_t nf, struct nftnl_set *set);

struct nftnl_rule * nf_rule_init(nf_t nf, const struct nftnl_chain *cha, 
                              const char *comment);
bool nf_rule_create(nf_t nf, struct nftnl_rule *rul);
bool nf_rule_replace(nf_t nf, struct nftnl_rule *rul);
bool nf_rule_delete(nf_t nf, struct nftnl_rule *rul);

struct nftnl_table * nf_table_get(nf_t nf, const char *family, const char *name);
struct nftnl_chain * nf_chain_get(nf_t nf, const struct nftnl_table *tbl, const char *chain);
struct nftnl_obj * nf_quota_get(nf_t nf, const struct nftnl_table *tbl, const char *quota);

bool nf_rule_list(nf_t nf, const struct nftnl_chain *cha, 
                                        struct nftnl_rule ***res, 
                                        int *nrules);

bool nf_rule_verdict(struct nftnl_rule *rul, const char *verdict);

bool nf_set_add(struct nftnl_set *set, const void *buf, int len);
bool nf_rule_add_set(struct nftnl_rule *rul, int dir, struct nftnl_set *set);
bool nf_rule_add_quota(struct nftnl_rule *rul, struct nftnl_obj *quo);
bool nf_rule_add_limit(struct nftnl_rule *rul, int rate, int unit);
bool nf_rule_add_log(struct nftnl_rule *rul, uint16_t log_group, const char *prefix);
bool nf_rule_set_timestamp(struct nftnl_rule *rul);
time_t nf_rule_get_timestamp(struct nftnl_rule *rul);
const char * nf_rule_get_comment(struct nftnl_rule *rul);

bool nf_nflog_bind(nf_t nf, uint16_t groupno, uint32_t qthresh, uint32_t tout, int mode, uint16_t size);
const char * nf_nflog_prefix(struct nlmsghdr *hdr);

void nf_debug_rule(const struct nftnl_rule *rul);

#endif
