#ifndef _QUOTA_H_
#define _QUOTA_H_
#include "nf.h"
#include <ev.h>

#define O_STATE_NONE             0x00
#define O_STATE_QUOTA_CREATED    0x01
#define O_STATE_QUOTA_DELETED    0x02
#define O_STATE_LOG_CREATED      0x04
#define O_STATE_LOG_DELETED      0x08
#define O_STATE_IRULE_CREATED    0x10
#define O_STATE_IRULE_DELETED    0x20 
#define O_STATE_ORULE_CREATED    0x40
#define O_STATE_ORULE_DELETED    0x80

#define OBJ_STATE(x,y) ((x & (y)) == (y))
#define OBJ_NO_STATE(x) ((x | O_STATE_NONE) ? 0 : 1)
#define OBJ_SET_STATE(x,y) (x |= (y))
#define OBJ_UNSET_STATE(x,y) (x &= (~y))

struct quota {
  nf_t nf;
  ev_timer expiry;
  const char *table_name;
  const char *chain_name;
  char *name;
  uint64_t limit;
  uint64_t used;
  uint8_t state;

  int quota_h;
  int in_h;
  int out_h;
  int log_h;
  struct in_addr *hosts;
  uint8_t **macs;
  int macs_len;
  int hosts_len;
};

typedef struct quota * quota_t;

quota_t quota_init(int n);
void quota_destroy(quota_t q);
void quota_inspect_firewall_state(quota_t q, nf_t nf);

/* When an deletion event occurred, state gets marked as deleted
 * call this function to fix the deleted state for whatever the
 * object was */
void quota_resolve_deleted_state(quota_t q, nf_t nf);
void quota_resolve_created_state(quota_t q, nf_t nf);
bool quota_handle_message(quota_t q, struct nlmsghdr *hdr);
bool quota_handle_log_message(quota_t q, struct nlmsghdr *hdr);
bool quota_reset(quota_t q, nf_t nf);
#endif
