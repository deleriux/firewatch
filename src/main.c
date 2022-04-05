#include "common.h"
#include "config.h"
#include "firewall.h"
#include <ev.h>

#include "nf.h"

#define CONFIG_FILE "/etc/firewatch/config.yml"

int main(
    int argc,
    char **argv)
{
  log_setlevel(INFO);

  if (argv[1]) 
    config_load(argv[1]);
  else
    config_load(CONFIG_FILE);
  log_setlevel(config_get_log_level());

  firewall_load();
  ev_run(EV_DEFAULT, 0);

  firewall_destroy();
  config_destroy();

  exit(EXIT_SUCCESS);
}
