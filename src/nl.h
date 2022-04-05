#ifndef _NL_H_
#define _NL_H_

#include "common.h"
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#define NL_MAX_VECS 256
#define NL_MAX_BUF 32768
#define NL_RCVBUFSZ 16777216

struct ack_entry {
  struct nlmsghdr hdr;
  SLIST_ENTRY(ack_entry) e;
};

struct nl {
  int seqno;
  int bind_groups;
  int type;
  uint32_t pid;
  int fd;

  SLIST_HEAD(ack_list, ack_entry) acks;

  unsigned char *buf;
  struct mnl_nlmsg_batch *batch;
};

typedef struct nl * nl_t;

bool nl_next_msg(nl_t nl);

void * nl_buf_current(nl_t nl);
void nl_buf_clear(nl_t nl);

int nl_get_fd(nl_t nl);
int nl_get_seqno(nl_t nl);
int nl_next_seqno(nl_t nl);

struct nlmsghdr * nl_add_hdr(nl_t nl, int msgtype, int flags);
int nl_add_msg(nl_t nl, void *payload, int plen);
int nl_add_attr_str(nl_t nl, uint16_t type, const char *str);
int nl_add_attr_u32(nl_t nl, uint16_t type, uint32_t fl);


void nl_close(nl_t nl);
nl_t nl_open(int type, int bind_groups, int flags);

bool nl_set_group(nl_t nl, int grp);
bool nl_unset_group(nl_t nl, int grp);

int nl_send(nl_t nl);
int nl_recv(nl_t nl, struct nlmsghdr **payload, int *nmsgs);
int nl_recv_ack(nl_t nl, int acks);
#endif
