AC_INIT([firewatch], [0.3], [matthew@ife.onl])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-extra-portability -Werror subdir-objects])

LT_INIT
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

PKG_CHECK_MODULES([MNL], libmnl)
PKG_CHECK_MODULES([NFTNL], libnftnl)
PKG_CHECK_MODULES([YAML], yaml-0.1)

AC_SEARCH_LIBS([ev_loop_new], [ev])
AC_SUBST([AM_CPPFLAGS], [-D_GNU_SOURCE])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
