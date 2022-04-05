#ifndef _CONFIG_H_
#define _CONFIG_H_

void config_load(const char *file);
void config_destroy(void);

struct tm * config_get_table_reset_quota_time(void);
const int config_get_log_level(void);
const char * config_get_table_name(void);
const int32_t config_get_table_priority(void);
const int config_get_table_num_devices(void);
const int config_get_table_num_quotas(void);
const char * config_get_table_device_name(int i);
const char * config_get_quota_name(int i);
const uint64_t config_get_quota_limit(int i);
const int config_get_quota_num_macs(int i);
const int config_get_quota_num_hosts(int i);
const unsigned char * config_get_quota_mac_address(int i, int j);
const struct in_addr * config_get_quota_host(int i, int j);

#define CONFIG_TIMEOUT_RULE 3600
#define CHAIN_NAME "firewatch"
#define TABLE_FAMILY "inet"
#define LOG_GROUP 10
#define PERIODIC_INTERVAL 86400

#endif
