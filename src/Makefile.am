bin_PROGRAMS = firewatch
firewatch_SOURCES = logging.h common.h main.c logging.c config.h config.c nl.c nl.h nf.c nf.h quota.h quota.c firewall.h firewall.c config.yml
                 
firewatch_CFLAGS = $(YAML_CFLAGS) $(NFTNL_CFLAGS) $(MNL_CFLAGS) -Wall
firewatch_LDADD = $(MNL_LIBS) $(NFTNL_LIBS) $(YAML_LIBS) 
