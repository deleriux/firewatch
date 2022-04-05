#include "common.h"
#include <linux/netfilter.h>
#include <yaml.h>

LOGSET("config")

#define CONFIG_DEFAULT_TABLENAME "firewatch"
#define CONFIG_DEFAULT_PRIORITY 10
#define CONFIG_DEFAULT_FAMILY NFPROTO_INET

struct config_table_device {
  char *name;
  SLIST_ENTRY(config_table_device) e;
};

struct config_quota_mac {
  unsigned char mac[6];
  SLIST_ENTRY(config_quota_mac) e;
};

struct config_quota_host {
  struct in_addr addr;
  SLIST_ENTRY(config_quota_host) e;
};

struct config_quota {
  char *name;
  uint64_t limit;
  SLIST_HEAD(mac_head, config_quota_mac) trigger_macs;
  SLIST_HEAD(host_head, config_quota_host) hosts;
  int nmacs;
  int nhosts;
  SLIST_ENTRY(config_quota) e;
};

struct config {
  struct tm quota_reset_time;
  int log_level;
  char *table_name;
  int32_t priority;
  int family;
  SLIST_HEAD(device_head, config_table_device) devices;
  SLIST_HEAD(quota_head, config_quota) quotas;
  int ndevices;
  int nquotas;
};

typedef struct config * config_t;

static bool device_is_valid(char *name);
static bool quota_is_valid(struct config_quota *q);
static bool table_name_is_valid(char *name);
static char * yaml_symbol_to_string(yaml_event_type_t e);
static config_t config_init(void);
static int host_address_valid(struct in_addr *addr, char *src);
static int mac_address_valid(unsigned char *mac, char *src);
static int parse_config_devices(yaml_parser_t *pa, struct device_head *devs);
static int parse_config_main(yaml_parser_t *pa, config_t c);
static int parse_config_quota_hosts(yaml_parser_t *pa, struct host_head *hosts);
static int parse_config_quota_trigger_macs(yaml_parser_t *pa, struct mac_head *macs);
static int parse_config_quotas(yaml_parser_t *pa, struct quota_head *quotas);
static int parse_config_root(yaml_parser_t *pa);
static struct config_quota * config_quota_init(void);
static uint64_t quota_limit(char *strlim);
static void config_device_free(struct config_table_device *d);
static void config_free(config_t c);
static void config_quota_free(struct config_quota *q);
static void config_quota_host_free(struct config_quota_host *h);
static void config_quota_mac_free(struct config_quota_mac *m);



static config_t active_conf;

static struct config_quota * config_quota_init(
    void)
{
  struct config_quota *cq = malloc(sizeof(struct config_quota));
  if (!cq)
    return NULL;

  cq->name = NULL; 
  cq->limit = 1*(2^30);
  SLIST_INIT(&cq->trigger_macs);
  SLIST_INIT(&cq->hosts);
  cq->nmacs = 0;
  cq->nhosts = 0;

  return cq;
}

static config_t config_init(
    void)
{
  config_t c = malloc(sizeof(struct config));
  if (!c)
    return NULL;

  memset(&c->quota_reset_time, 0, sizeof(struct tm));
  c->log_level = INFO;
  c->table_name = strdup(CONFIG_DEFAULT_TABLENAME);
  c->priority = CONFIG_DEFAULT_PRIORITY;
  SLIST_INIT(&c->devices);
  SLIST_INIT(&c->quotas);
  c->ndevices = 0;
  c->nquotas = 0;

  return c;
}

static int log_level_is_valid(
    const char *level)
{
  int i;
  char lvl[32] = {0};

  if (!level) return -1;

  for (i=0; i < strlen(level); i++) {
    lvl[i] = tolower(level[i]);
  }

  if (strcmp(lvl, "debug") == 0)
    return DEBUG;
  else if (strcmp(lvl, "verbose") == 0)
    return VERBOSE;
  else if (strcmp(lvl, "info") == 0)
    return INFO;
  else if (strcmp(lvl, "warning") == 0)
    return WARNING;
  else if (strcmp(lvl, "error") == 0)
    return ERROR;
  else if (strcmp(lvl, "critical") == 0)
    return CRITICAL;
  else 
    return -1;

}

static bool quota_is_valid(
    struct config_quota *q)
{
  if (!q->name) {
    ELOG(ERROR, "quota->name is required in a quota entry");
    return 0;
  }

  if (q->limit <= 0) {
    ELOG(ERROR, "quota->limit is required in a quota entry (%s)", q->name);
    return 0;
  }

  if (q->nmacs <= 0) {
    ELOG(ERROR, "quota->trigger_macs must contain at least one address (%s)", q->name);
    return 0;
  }

  if (q->nhosts <= 0) {
    ELOG(ERROR, "quota->quota_hosts must contain at least one address");
    return 0;
  }

  return 1;
}

static bool device_is_valid(
    char *name)
{
  int i;
  int l = strlen(name);
  if (l < 1 || l > 24)
    return 0;

  for (i=0; i < l; i++) {
    switch (name[i]) {
      case 'a' ... 'z':
      case 'A' ... 'Z':
      case '0' ... '9':
      case '-':
      case '_':
      case ':':
        continue;
      break;

      default:
        return 0;
      break;
    }
  }

  return 1;
}

static uint64_t quota_limit(
    char *strlim)
{
  uint64_t lim;
  char si[3] = {0};
  int rc = -1;

  rc = sscanf(strlim, "%lu %[kkMmGg]", &lim, si);
  if (rc < 1)
    return 0;

  switch (tolower(si[0])) {
    case 'g':
      lim *= 1024;
    case 'm':
      lim *= 1024;
    case 'k':
      lim *= 1024;
    case 0:
    break;
  }

  return lim;
}

static bool table_name_is_valid(
    char *name)
{
  int i;
  int l = strlen(name);
  if (l < 1 || l > 24)
    return 0;

  for (i=0; i < l; i++) {
    switch (name[i]) {
      case 'a' ... 'z':
      case 'A' ... 'Z':
      case '0' ... '9':
      case '-':
      case '_':
        continue;
      break;

      default:
        return 0;
      break;
    }
  }

  return 1;
}

static int host_address_valid(
    struct in_addr *addr,
    char *src)
{
  if (!inet_pton(AF_INET, src, addr))
    if (!inet_pton(AF_INET6, src, addr))
      return 0;
  return 1;
}

static int mac_address_valid(
    unsigned char *mac,
    char *src)
{
  int rc = -1;
  rc = sscanf(src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
  if (rc != 6)
    return 0;

  return 1;
}


static char * yaml_symbol_to_string(
    yaml_event_type_t e)
{
  switch(e) {
    case YAML_STREAM_START_EVENT:
      return "stream";
    case YAML_STREAM_END_EVENT:
      return "stream end";
    case YAML_DOCUMENT_START_EVENT:
      return "document";
    case YAML_DOCUMENT_END_EVENT:
      return "document end";
    case YAML_ALIAS_EVENT:
      return "alias";
    case YAML_SCALAR_EVENT:
      return "scalar";
    case YAML_SEQUENCE_START_EVENT:
      return "sequence";
    case YAML_SEQUENCE_END_EVENT:
      return "sequence end";
    case YAML_MAPPING_START_EVENT:
      return "mapping";
    case YAML_MAPPING_END_EVENT:
      return "mapping end";
    default:
      return "unknown";
  }
}

static int parse_config_devices(
    yaml_parser_t *pa,
    struct device_head *devs)
{
  yaml_event_t val = {};
  bool go = true;
  int rc = 0;
  struct config_table_device *d = NULL;

  while (go) {
    /* Iterate the sequence */
    yaml_parser_parse(pa, &val);

    if (val.type == YAML_SEQUENCE_END_EVENT) {
      go = false;
      goto again;
    }

    if (val.type != YAML_SCALAR_EVENT) {
      ELOG(ERROR, "Config file error. Expected valid quota_device element [a-zA-Z0-9:]{1,64} but got yaml token %s",
                   yaml_symbol_to_string(val.type));
      go = false;
      rc = -1;
      goto again;
    }

    d = malloc(sizeof(struct config_table_device));
    if (!d) {
      ELOGERR(ERROR, "Config file error. Out of memory acquiring element",
                     val.data.scalar.value);
      go = false;
      rc = -1;
      goto again;
    }

    if (!device_is_valid((char *)val.data.scalar.value)) {
      ELOG(ERROR, "Config file error. Expected valid quota_device element [a-zA-Z0-9:]{1,64} but got %s",
                  val.data.scalar.value);
      go = false;
      rc = -1;
      goto again;
    }

    d->name = strdup((char *)val.data.scalar.value);
    SLIST_INSERT_HEAD(devs, d, e);

    rc++;
  again:
    yaml_event_delete(&val);
  }

  return rc;
}

static int parse_config_quota_hosts(
    yaml_parser_t *pa,
    struct host_head *hosts)
{
  yaml_event_t val = {};
  bool go = true;
  int rc = 0;
  struct config_quota_host *h = NULL;

  while (go) {
    /* Iterate the sequence */
    yaml_parser_parse(pa, &val);

    if (val.type == YAML_SEQUENCE_END_EVENT) {
      go = false;
      goto again;
    }

    if (val.type != YAML_SCALAR_EVENT) {
      ELOG(ERROR, "Config file error. Expected valid mac address element [a-zA-Z0-9:]{1,64} but got yaml token %s",
                   yaml_symbol_to_string(val.type));
      go = false;
      rc = -1;
      goto again;
    }

    h = malloc(sizeof(struct config_quota_host));
    if (!h) {
      ELOGERR(ERROR, "Config file error. Out of memory acquiring element",
                     (char *)val.data.scalar.value);
      go = false;
      rc = -1;
      goto again;
    }

    if (!host_address_valid(&h->addr, (char *)val.data.scalar.value)) {
      ELOG(ERROR, "Config file error. Expected valid ipv4/ipv6 address but got %s",
                  (char *)val.data.scalar.value);
      go = false;
      rc = -1;
      goto again;
    }

    SLIST_INSERT_HEAD(hosts, h, e);

    rc++;
  again:
    yaml_event_delete(&val);
  }

  return rc;
}

static int parse_config_quota_trigger_macs(
    yaml_parser_t *pa,
    struct mac_head *macs)
{
  yaml_event_t val = {};
  bool go = true;
  int rc = 0;
  struct config_quota_mac *m = NULL;

  while (go) {
    /* Iterate the sequence */
    yaml_parser_parse(pa, &val);

    if (val.type == YAML_SEQUENCE_END_EVENT) {
      go = false;
      goto again;
    }

    if (val.type != YAML_SCALAR_EVENT) {
      ELOG(ERROR, "Config file error. Expected valid mac address element [a-zA-Z0-9:]{1,64} but got yaml token %s",
                   yaml_symbol_to_string(val.type));
      go = false;
      rc = -1;
      goto again;
    }

    m = malloc(sizeof(struct config_quota_mac));
    if (!m) {
      ELOGERR(ERROR, "Config file error. Out of memory acquiring element",
                     val.data.scalar.value);
      go = false;
      rc = -1;
      goto again;
    }

    if (!mac_address_valid(m->mac, (char *)val.data.scalar.value)) {
      ELOG(ERROR, "Config file error. Expected valid mac address (aa:bb:cc:dd:ee:ff) but got %s",
                  val.data.scalar.value);
      go = false;
      rc = -1;
      goto again;
    }

    SLIST_INSERT_HEAD(macs, m, e);

    rc++;
  again:
    yaml_event_delete(&val);
  }

  return rc;
}

static int parse_config_quotas(
    yaml_parser_t *pa,
    struct quota_head *quotas)
{
  yaml_event_t key = {};
  yaml_event_t val = {};
  bool go = true;
  int rc = 0;
  struct config_quota *q = NULL;
  bool set_name = false;
  bool set_limit = false;
  bool set_macs = false;
  bool set_hosts = false;

  while (go) {
    /* Iterate the sequence */
    yaml_parser_parse(pa, &key);

    if (key.type == YAML_SEQUENCE_END_EVENT) {
      go = false;
      goto again;
    }

    else if (key.type == YAML_MAPPING_START_EVENT) {
      q = config_quota_init();
    }

    else if (key.type == YAML_MAPPING_END_EVENT) {
      assert(q); 
      if (!quota_is_valid(q)) {
        go = false;
        rc = -1;
        goto again;
      }

      rc++;
      SLIST_INSERT_HEAD(quotas, q, e);
      q = NULL;
      set_name = set_limit = set_macs = set_hosts = false;
    }

    else if (key.type == YAML_SCALAR_EVENT) {

      if (strcmp((const char *)key.data.scalar.value, "name") == 0) {

        if (set_name) {
          ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
          go = false;
          rc = -1;
          goto again;
        }

        /* Parse the next token, must be a scalar */
        yaml_parser_parse(pa, &val);
        if (val.type != YAML_SCALAR_EVENT) {
          ELOG(ERROR, "Config file error. Expected valid quota->name but got yaml token %s",
                      yaml_symbol_to_string(val.type));
          go = false;
          rc = -1;
          goto again;
        }

        /* Should result in a valid name */
        if (!table_name_is_valid((char *)val.data.scalar.value)) {
          ELOG(ERROR, "Config file error. Expected valid table_name [a-zA-Z0-9_]{1,24} but got %s",
                      val.data.scalar.value);
          go = false;
          rc = -1;
          goto again;
        }

        q->name = strdup((char *)val.data.scalar.value);
        set_name = true;
      }

      else if (strcmp((const char *)key.data.scalar.value, "limit") == 0) {

        if (set_limit) {
          ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
          go = false;
          rc = -1;
          goto again;
        }

        /* Parse the next token, must be a scalar */
        yaml_parser_parse(pa, &val);
        if (val.type != YAML_SCALAR_EVENT) {
          ELOG(ERROR, "Config file error. Expected valid quota->limit but got yaml token %s",
                      yaml_symbol_to_string(val.type));
          go = false;
          rc = -1;
          goto again;
        }

        /* Should result in a valid name */
        q->limit = quota_limit((char *)val.data.scalar.value);
        if (q->limit == 0) {
          ELOG(ERROR, "Config file error. Expected valid limit ([0-9]+ k|m|g) but got %s",
                      val.data.scalar.value);
          go = false;
          rc = -1;
          goto again;
        }

        set_limit = true;
      }

      else if (strcmp((const char *)key.data.scalar.value, "trigger_macs") == 0) {

        if (set_macs) {
          ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
          go = false;
          rc = -1;
          goto again;
        }

        /* Parse the next token, must be a sequence */
        yaml_parser_parse(pa, &val);
        if (val.type != YAML_SEQUENCE_START_EVENT) {
          ELOG(ERROR, "Config file error. Expected valid <sequence of quota->trigger_macs> but got yaml token %s",
                      yaml_symbol_to_string(val.type));
          go = false;
          rc = -1;
          goto again;
        }

        /* Should result in a valid mac list */
        q->nmacs = parse_config_quota_trigger_macs(pa, &q->trigger_macs);
        if (q->nmacs <= 0) {
          go = false;
          rc = -1;
          goto again;
        }

        set_macs = true;
      }

      else if (strcmp((const char *)key.data.scalar.value, "quota_hosts") == 0) {

        if (set_hosts) {
          ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
          go = false;
          rc = -1;
          goto again;
        }

        /* Parse the next token, must be a sequence */
        yaml_parser_parse(pa, &val);
        if (val.type != YAML_SEQUENCE_START_EVENT) {
          ELOG(ERROR, "Config file error. Expected valid <sequence of quota->quota_hosts> but got yaml token %s",
                      yaml_symbol_to_string(val.type));
          go = false;
          rc = -1;
          goto again;
        }

        /* Should result in a valid mac list */
        q->nhosts = parse_config_quota_hosts(pa, &q->hosts);
        if (q->nhosts <= 0) {
          go = false;
          rc = -1;
          goto again;
        }

        set_hosts = true;
      }

      else {
        ELOG(ERROR, "Config file error. Unknown configuration entry: %s", key.data.scalar.value);
        go = false;
        rc = -1;
        goto again;
      }
    }

  again:
    yaml_event_delete(&key);
    yaml_event_delete(&val);
  }

  return rc;
}

static int parse_config_main(
    yaml_parser_t *pa,
    config_t c)
{
  int rc = 1;
  bool go = true;
  yaml_event_t key = {}, val = {};

  char *tmp;
  bool set_reset_quota_time = false;
  bool set_table_name = false;
  bool set_table_priority = false;
  bool set_quota_devices = false;
  bool set_quotas = false;
  bool set_log_level = false;

  while (go) {
    yaml_parser_parse(pa, &key);

    if (key.type == YAML_MAPPING_END_EVENT) {
      go = false;
      goto again;
    }

    else if (key.type != YAML_SCALAR_EVENT) {
      ELOG(ERROR, "Config file error. Expected keyword but got %s",
                  yaml_symbol_to_string(key.type));
      go = false; rc = 0;
      goto again;
    }

    if (strcmp((const char *)key.data.scalar.value, "reset_quota_time") == 0) {

      if (set_reset_quota_time) {
        ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
        go = false; rc = 0; 
        goto again;
      }

      /* Parse the next token, must be a scalar */
      yaml_parser_parse(pa, &val);
      if (val.type != YAML_SCALAR_EVENT) {
        ELOG(ERROR, "Config file error. Expected valid wake time (hh:mm:ss) but got yaml token %s",
                    yaml_symbol_to_string(val.type));
        go = false; rc = 0; 
        goto again;
      }

      /* Should result in a valid time */
      if (strptime((char *)val.data.scalar.value, "%H:%M:%S", 
               &c->quota_reset_time) == NULL) {
        ELOG(ERROR, "Config file error. Expected valid wake time (hh:mm:ss) but got %s",
                    val.data.scalar.value);
        go = false; rc = 0; 
        goto again;
      }

      set_reset_quota_time = true;
    }

    else if (strcmp((const char *)key.data.scalar.value, "log_level") == 0) {

      if (set_log_level) {
        ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
        go = false; rc = 0; 
        goto again;
      }

      /* Parse the next token, must be a scalar */
      yaml_parser_parse(pa, &val);
      if (val.type != YAML_SCALAR_EVENT) {
        ELOG(ERROR, "Config file error. Expected valid table_name but got yaml token %s",
                    yaml_symbol_to_string(val.type));
        go = false; rc = 0;
        goto again;
      }

      c->log_level = log_level_is_valid((char *)val.data.scalar.value);
      if (c->log_level < 0) {
        ELOG(ERROR, "Config file error. Expected valid log level "
                    "(debug|verbose|info|warning|error|critical) but got %s",
                    val.data.scalar.value);
        go = false; rc = 0;
        goto again;
      }

      set_log_level = true;
    }

    else if (strcmp((const char *)key.data.scalar.value, "table_name") == 0) {

      if (set_table_name) {
        ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
        go = false; rc = 0; 
        goto again;
      }

      /* Parse the next token, must be a scalar */
      yaml_parser_parse(pa, &val);
      if (val.type != YAML_SCALAR_EVENT) {
        ELOG(ERROR, "Config file error. Expected valid table_name but got yaml token %s",
                    yaml_symbol_to_string(val.type));
        go = false; rc = 0;
        goto again;
      }

      /* Should result in a valid table_name */ 
      if (!table_name_is_valid((char *)val.data.scalar.value)) {
        ELOG(ERROR, "Config file error. Expected valid table_name [a-zA-Z0-9_]{1,24} but got %s",
                    (char *)val.data.scalar.value);
        go = false; rc = 0;
        goto again;
      }

      c->table_name = strdup((const char *)val.data.scalar.value);
      set_table_name = true;
    }

    else if (strcmp((const char *)key.data.scalar.value, "table_priority") == 0) {

      if (set_table_priority) {
        ELOG(ERROR, "Config file error. Duplicate key: %s", (char *)key.data.scalar.value);
        go = false; rc = 0;
        goto again;
      }

      /* Parse the next token, must be a scalar */
      yaml_parser_parse(pa, &val);
      if (val.type != YAML_SCALAR_EVENT) {
        ELOG(ERROR, "Config file error. Expected valid table_priority but got yaml token %s",
                    yaml_symbol_to_string(val.type));
        go = false; rc = 0;
        goto again;
      }

      /* Should result in a valid table_priority */
      c->priority = strtol((const char *)val.data.scalar.value, &tmp, 10);
      if (errno != 0 || 
          val.data.scalar.value[0] == 0 || 
          *tmp != 0 ||
          c->priority < -50 || 
          c->priority > 50) {

        ELOG(ERROR, "Config file error. Expected valid table_priority (-50 to +50) but got %s",
                    (char *)val.data.scalar.value);
        go = false; rc = 0;
        goto again;
      }

      set_table_priority = true;
    }

    else if (strcmp((const char *)key.data.scalar.value, "quota_devices") == 0) {
      if (set_quota_devices) {
        ELOG(ERROR, "Config file error. Duplicate key: %s", (char *)key.data.scalar.value);
        go = false; rc = 0;
        goto again;
      }

      /* Parse the next token, must be a sequence */
      yaml_parser_parse(pa, &val);
      if (val.type != YAML_SEQUENCE_START_EVENT) {
        ELOG(ERROR, "Config file error. Expected valid quota_devices <sequence of devices> but got yaml token %s",
                    yaml_symbol_to_string(val.type));
        go = false; rc = 0;
        goto again;
      }

      c->ndevices = parse_config_devices(pa, &c->devices);
      if (c->ndevices < 0) {
        go = false; rc = 0;
        goto again;
      }

      set_quota_devices = true;
    }

    else if (strcmp((const char *)key.data.scalar.value, "quotas") == 0) {
      if (set_quotas) {
        ELOG(ERROR, "Config file error. Duplicate key: %s", key.data.scalar.value);
        go = false; rc = 0;
        goto again;
      }

      /* Parse the next token, must be a sequence */
      yaml_parser_parse(pa, &val);
      if (val.type != YAML_SEQUENCE_START_EVENT) {
        ELOG(ERROR, "Config file error. Expected valid quota <sequence of quotas> but got yaml token %s",
                    yaml_symbol_to_string(val.type));
        go = false; rc = 0;
        goto again;
      }

      c->nquotas = parse_config_quotas(pa, &c->quotas);
      if (c->nquotas < 0) {
        go = false; rc = 0;
        goto again;
      }

      set_quotas = true;
    }

    else {
      ELOG(ERROR, "Config file error. Unknown configuration entry: %s", key.data.scalar.value);
      go = false; rc = 0;
      goto again;
    }

  again:
    yaml_event_delete(&key);
    yaml_event_delete(&val);
  }

  /* If all items are loaded, check mandatory items are set */
  if (rc) {
    if (c->ndevices <= 0) {
      ELOG(ERROR, "Config file error. quota_devices list must be set");
      rc = 0;
    }
    else if (c->ndevices > 32) {
      ELOG(ERROR, "Config file error. Too many quota_devices may be an error? (%d devices)", c->ndevices);
      rc = 0;
    }

    if (c->nquotas > 64) {
      ELOG(ERROR, "Config file error. Too many quotas may be an error? (%d devices)", c->ndevices);          
      rc = 0;
    }
  }

  return rc;
}



static int parse_config_root(
    yaml_parser_t *pa)
{
  bool go = true;
  int rc = 0;
  config_t c = NULL;
  yaml_event_t ev = {};

  while (go) {
    yaml_parser_parse(pa, &ev);
    switch (ev.type) {
      case YAML_ALIAS_EVENT:
      case YAML_SCALAR_EVENT:
      case YAML_SEQUENCE_START_EVENT:
      case YAML_SEQUENCE_END_EVENT:
      case YAML_STREAM_START_EVENT:
      case YAML_NO_EVENT:
      break;

      case YAML_DOCUMENT_START_EVENT:
      break;

      case YAML_MAPPING_START_EVENT:
        c = config_init();
        if (!c) {
          ELOGERR(ERROR, "Cannot allocate memory for config file");
          go = false;
        }

        if (!parse_config_main(pa, c))
          go = false;
        else 
          rc = 1;
      break;

      case YAML_MAPPING_END_EVENT:
      break;

      case YAML_DOCUMENT_END_EVENT:
      break;

      case YAML_STREAM_END_EVENT:
        active_conf = c;
        go = false;
        
      break;

    }

    yaml_event_delete(&ev);
  }

  return rc;
}

static void config_quota_mac_free(
    struct config_quota_mac *m)
{
  if (m)
    free(m);
}

static void config_quota_host_free(
    struct config_quota_host *h)
{
  if (h)
    free(h);
}

static void config_quota_free(
    struct config_quota *q)
{
  struct config_quota_mac *m;
  struct config_quota_host *h;

  if (q) {
    if (q->name)
      free(q->name);

    while (!SLIST_EMPTY(&q->trigger_macs)) {
      m = SLIST_FIRST(&q->trigger_macs);
      SLIST_REMOVE_HEAD(&q->trigger_macs, e);
      config_quota_mac_free(m);
    }

    while (!SLIST_EMPTY(&q->hosts)) {
      h = SLIST_FIRST(&q->hosts);
      SLIST_REMOVE_HEAD(&q->hosts, e);
      config_quota_host_free(h);
    }

    free(q);
  }
}

static void config_device_free(
    struct config_table_device *d)
{
  if (d) {
    if (d->name)
      free(d->name);
    free(d);
  }
}

static void config_free(
    config_t c)
{
  struct config_table_device *d;
  struct config_quota *q;

  if (c) {
    if (c->table_name)
      free(c->table_name);

    while (!SLIST_EMPTY(&c->devices)) {
      d = SLIST_FIRST(&c->devices);
      SLIST_REMOVE_HEAD(&c->devices, e);
      config_device_free(d);
    }

    while (!SLIST_EMPTY(&c->quotas)) {
      q = SLIST_FIRST(&c->quotas);
      SLIST_REMOVE_HEAD(&c->quotas, e);
      config_quota_free(q);
    }

    free(c);
  }
}

void config_destroy(
    void)
{
  config_free(active_conf);
}

void config_load(
    char *path)
{
  yaml_parser_t parser = {};
  FILE *fd = NULL;

  ELOG(INFO, "Reading config file");
  fd = fopen(path, "r");
  if (!fd) {
    ELOGERR(ERROR, "Cannot open configuration file: %s", path);
    goto fin;
  }

  if (!yaml_parser_initialize(&parser)) {
    ELOG(ERROR, "Cannot initialize YAML parser");
    goto fin;
  }

  yaml_parser_set_input_file(&parser, fd);  

  if (!parse_config_root(&parser))
    goto fin;
  else
    ELOG(VERBOSE, "Successfully loaded config file");

  yaml_parser_delete(&parser);
  if (fd)
    fclose(fd);
  return;

fin:
  yaml_parser_delete(&parser);
  if (fd)
    fclose(fd);  
  exit(EXIT_FAILURE);
}

const char * config_get_table_name(
    void)
{
  return active_conf->table_name;
}

const int32_t config_get_table_priority(
    void)
{
  return active_conf->priority;
}

const int config_get_table_num_devices(
    void)
{
  return active_conf->ndevices;
}

const int config_get_table_num_quotas(
    void)
{
  return active_conf->nquotas;
}

const struct tm * config_get_table_reset_quota_time(
    void)
{
  return &active_conf->quota_reset_time;
}

const char * config_get_table_device_name(
    int i)
{
  int c = 0;
  struct config_table_device *d; 

  SLIST_FOREACH(d, &active_conf->devices, e) {
    if (i == c)
      return d->name;
    c++;
  }

  return NULL;
}

const char * config_get_quota_name(
    int i)
{
  int c = 0;
  struct config_quota *q;

  SLIST_FOREACH(q, &active_conf->quotas, e) {
    if (i == c)
      return q->name;
    c++;
  }

  return NULL;
}

const uint64_t config_get_quota_limit(
    int i)
{
  int c = 0;
  struct config_quota *q;

  SLIST_FOREACH(q, &active_conf->quotas, e) {
    if (i == c)
      return q->limit;
    c++;
  }

  return 0;
}

const int config_get_quota_num_macs(
    int i)
{
  int c = 0;
  struct config_quota *q;

  SLIST_FOREACH(q, &active_conf->quotas, e) {
    if (i == c)
      return q->nmacs;
    c++;
  }

  return -1;
}

const int config_get_quota_num_hosts(
    int i)
{
  int c = 0;
  struct config_quota *q;

  SLIST_FOREACH(q, &active_conf->quotas, e) {
    if (i == c)
      return q->nhosts;
    c++;
  }

  return -1;
}

const int config_get_log_level(
    void)
{
  return active_conf->log_level;
}

const unsigned char * config_get_quota_mac_address(
    int i,
    int j)
{
  int c = 0;
  int d = 0;
  struct config_quota *q;
  struct config_quota_mac *m;

  SLIST_FOREACH(q, &active_conf->quotas, e) {
    if (i == c)
      SLIST_FOREACH(m, &q->trigger_macs, e) {
        if (j == d)
          return m->mac;
        d++;
      }
    c++;
  }

  return NULL;
}

const struct in_addr * config_get_quota_host(
    int i,
    int j)
{
  int c = 0;
  int d = 0;
  struct config_quota *q;
  struct config_quota_host *h;

  SLIST_FOREACH(q, &active_conf->quotas, e) {
    if (i == c)
      SLIST_FOREACH(h, &q->hosts, e) {
        if (j == d)
          return &h->addr;
        d++;
      }
    c++;
  }

  return NULL;
}
