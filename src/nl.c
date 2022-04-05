#include "common.h"

#include "nl.h"
#include <byteswap.h>
#include <linux/netlink.h>

static bool set_pending_acks(
    nl_t nl)
{
  assert(nl);
  assert(nl->batch);

  struct ack_entry *ae;
  struct nlmsghdr *hdr = mnl_nlmsg_batch_head(nl->batch);
  int len = mnl_nlmsg_batch_size(nl->batch);

  while (mnl_nlmsg_ok(hdr, len)) {
    if (hdr->nlmsg_flags & NLM_F_ACK) {
      ae = malloc(sizeof(struct ack_entry));
      if (!ae)
        goto err;
      memcpy(&ae->hdr, hdr, NLMSG_HDRLEN);
      SLIST_INSERT_HEAD(&nl->acks, ae, e);
      ae = NULL;
    }

    hdr = mnl_nlmsg_next(hdr, &len);
  }

  return true;
err:
  return false;
}

static bool nl_is_error(
    nl_t nl,
    struct nlmsghdr *hdr)
{
  struct nlmsgerr *err = NULL;
  if (!hdr)
    goto err;

  if (hdr->nlmsg_type != NLMSG_ERROR)
    return false;

  err = mnl_nlmsg_get_payload(hdr);
  if (err->error != 0) {
    errno = abs(err->error);
    goto err;;
  }

  return false;

err:
  return true;
}

static bool find_sequence(
    nl_t nl,
    struct nlmsghdr *hdr)
{
  struct ack_entry *ae;

  if (!nl)
    goto err;

  /* The message isn't a ack */
  if (hdr->nlmsg_type != NLMSG_ERROR)
    return true;

  /* No acks waiting */
  if (SLIST_EMPTY(&nl->acks))
    return true;

  SLIST_FOREACH(ae, &nl->acks, e) {
    if (ae->hdr.nlmsg_seq == hdr->nlmsg_seq) {
      /* If found, remove from list */
      SLIST_REMOVE(&nl->acks, ae, ack_entry, e);
      free(ae);
      return true;
    }
  }

err:
  return false;
}



void nl_close(
    nl_t nl)
{
  struct ack_entry *ae;

  if (!nl)
    return;

  if (nl->fd > -1)
    close(nl->fd);

  if (nl->batch) {
    mnl_nlmsg_batch_stop(nl->batch);
    nl->batch = NULL;
  }

  if (nl->buf) {
    free(nl->buf);
    nl->buf = NULL;
  }

  while ((ae = SLIST_FIRST(&nl->acks))) {
    SLIST_REMOVE_HEAD(&nl->acks, e);
    free(ae);
  }

  free(nl);
}

nl_t nl_open(
    int type,
    int bind_groups,
    int flags)
{
  struct sockaddr_nl nla = {0};
  int fl = flags & (SOCK_CLOEXEC|SOCK_NONBLOCK);
  int buflen = NL_RCVBUFSZ;

  nl_t nl = malloc(sizeof(struct nl));
  if (!nl)
    goto err;

  SLIST_INIT(&nl->acks);
  nl->type = type;
  nl->seqno = 0;
  nl->batch = NULL;
  nl->buf = calloc(1, NL_MAX_BUF);
  if (!nl->buf)
    goto err;

  nl->fd = socket(AF_NETLINK, SOCK_DGRAM|fl, type);
  if (nl->fd < 0)
    goto err;

  /* Make sure we always keep enough buffer for very large rulesets */
  if (setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUFFORCE, &buflen, 
                 sizeof(buflen)) < 0) {
    goto err;
  }

  nla.nl_family = AF_NETLINK;
  nla.nl_pid = 0;
  nla.nl_groups = bind_groups;
  /* Bind */
  if (bind(nl->fd, (struct sockaddr *)&nla, sizeof(struct sockaddr_nl)) < 0)
    goto err;

  return nl;

err:
  if (nl)
    nl_close(nl);
  return NULL;
}



void * nl_buf_current(
    nl_t nl)
{
  if (nl->batch) {
    return mnl_nlmsg_batch_current(nl->batch);
  }

  nl->batch = mnl_nlmsg_batch_start(nl->buf, NL_MAX_BUF);
  if (!nl->batch)
    return NULL;

  return mnl_nlmsg_batch_current(nl->batch);
}

void nl_buf_clear(
    nl_t nl)
{
  if (!nl)
    return;

  if (!nl->batch)
    return;

  mnl_nlmsg_batch_stop(nl->batch);
  memset(nl->buf, 0, NL_MAX_BUF);
  nl->batch = mnl_nlmsg_batch_start(nl->buf, NL_MAX_BUF);
}

int nl_get_fd(
    nl_t nl)
{
  if (!nl)
    return -1;

  return nl->fd;
}



int nl_get_seqno(
    nl_t nl)
{
  if (!nl)
    return -1;

  return nl->seqno;
}



int nl_next_seqno(
    nl_t nl)
{
  if (!nl)
    return -1;

  return nl->seqno++;
}



bool nl_next_msg(
    nl_t nl)
{
  int rc;
  if (!nl->batch)
    return true;

  if (!mnl_nlmsg_batch_next(nl->batch)) {
    rc = nl_send(nl);
    printf("Sent %d bytes as out of buffer!\n", rc);
    if (rc < 0)
      return false;
  }
  return true;
}


int nl_send(
    nl_t nl)
{
  int rc;
  struct sockaddr_nl ad = {0};

  if (!nl) {
    errno = EINVAL;
    return -1;
  }

  if (nl->batch && mnl_nlmsg_batch_is_empty(nl->batch))
    return 0;

  /* Set pending acks */
  set_pending_acks(nl);

  ad.nl_family = AF_NETLINK;

  rc = sendto(nl->fd,
              mnl_nlmsg_batch_head(nl->batch),
              mnl_nlmsg_batch_size(nl->batch),
              MSG_NOSIGNAL,
              (struct sockaddr *)&ad, 
              sizeof(struct sockaddr_nl));

  mnl_nlmsg_batch_reset(nl->batch);

  return rc;
}



int nl_recv(
    nl_t nl,
    struct nlmsghdr **payload,
    int *num)
{
  int rc;
  int nmsgs = 0;
  int len = 0, total = 0;
  bool more = false;
  unsigned char buf[NL_MAX_BUF];
  struct nlmsghdr *hdr = NULL;
  unsigned char *pay = NULL;

  if (!nl || !payload) {
    errno = EINVAL;
    return -1;
  }

  memset(buf, 0, sizeof(buf));

  /* Retrieve the max buffer size you can.. */
  do {
    rc = recv(nl->fd, buf, NL_MAX_BUF, 0);
    if (rc < NLMSG_HDRLEN)
      goto err;

    hdr = (struct nlmsghdr *)buf; 

    /* Test each header received for sanity */
    while (mnl_nlmsg_ok(hdr, rc)) {
      if (!find_sequence(nl, hdr))
        errno = EILSEQ;

      /* Check if this is an error message */
      if (nl_is_error(nl, hdr))
        goto err;

      /* Check if this is the last message */
      if (hdr->nlmsg_flags & NLM_F_MULTI) {
        more = true;
      }

      /* NFLOG subsystem marks DONE messages without multi.. */
      if (hdr->nlmsg_type == NLMSG_DONE) {
        more = false;
        break;
      }

      nmsgs++;
      len += hdr->nlmsg_len;
      hdr = mnl_nlmsg_next(hdr, &rc);
    }

    /* Allocate memory for payload */
    if (!pay) {
      pay = malloc(len);
      if (!pay)
        goto err;
    }
    else {
      pay = realloc(pay, total + len);
      if (!pay)
        goto err;
    }

    memcpy(pay+total, buf, len);
    total += len;
    memset(buf, 0, NL_MAX_BUF);
    len = 0;
  } while (more);

  *payload = (struct nlmsghdr *)pay;
  if (num)
    *num = nmsgs;
  return total;

err:
  if (pay)
    free(pay);
  *payload = NULL;
  if (num)
    *num = 0;
  return -1;
}



int nl_recv_ack(
    nl_t nl,
    int acks)
{
  int rc, nmsgs;
  struct nlmsghdr *hdrs = NULL, *hdr = NULL;
  struct nlmsgerr *err = NULL;

  if (!nl) {
    errno = EINVAL;
    return -1;
  }

  while (acks) {
    rc = nl_recv(nl, &hdrs, &nmsgs);
    if (rc < 0)
      goto err;

    hdr = hdrs;
    while (mnl_nlmsg_ok(hdr, rc)) {
      err = mnl_nlmsg_get_payload(hdr);
      if (err->error != 0) {
        errno = abs(err->error);
        goto err;
      }

      /* Do basic header checks */
      if (hdr->nlmsg_type != NLMSG_ERROR) {
        errno = EBADMSG;
        goto err;
      }

      hdr = mnl_nlmsg_next(hdr, &rc);
    }

    acks -= nmsgs;
  }

  free(hdrs);
  return 0;

err:
  if (hdrs)
    free(hdrs);
  return -1;
}


bool nl_set_group(
    nl_t nl,
    int grp)
{
  if (setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                 &grp, sizeof(grp)) < 0)
    return false;
  return true;
}


bool nl_unset_group(
    nl_t nl,
    int grp)
{
  if (setsockopt(nl->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                 &grp, sizeof(grp)) < 0)
    return false;
  return true;
}
