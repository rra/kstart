dnl Process this file with autoconf to produce a configure script.
dnl $Id$
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.61])
AC_INIT([kstart], [3.12], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AM_INIT_AUTOMAKE([1.10])
AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_AIX
AC_GNU_SOURCE

dnl aklog is the standard name for the utility to get AFS tokens from Kerberos
dnl tickets.  afslog is the name of the utility that comes with KTH Kerberos
dnl or Heimdal.  By default, we build in support for calling it if we find
dnl either on the user's path or if the user specifies a default path.
AC_ARG_WITH([aklog],
    AC_HELP_STRING([--with-aklog=PATH],
        [Path to aklog or other AFS token program]),
    [AS_IF([test x"$withval" != xno], [PATH_AKLOG=$withval])],
    [AC_PATH_PROGS([PATH_AKLOG], [aklog afslog])])
AC_DEFINE_UNQUOTED([PATH_AKLOG], ["$PATH_AKLOG"],
    [Full path to aklog binary.])

dnl Allow the user to disable Kerberos v4 support.  Useful for building
dnl against just Heimdal, without KTH Kerberos.
K4START=k4start
K4START_MAN='$(srcdir)/k4start.1'
AC_ARG_ENABLE([k4start],
    AC_HELP_STRING([--disable-k4start],
        [Don't build k4start (Kerberos v4 support)]),
    [AS_IF([test x"$enableval" = xno],
        [K4START=
         K4START_MAN=])])
AC_SUBST([K4START])
AC_SUBST([K4START_MAN])

dnl Check for the Kerberos v5 libraries and for portability between MIT and
dnl Heimdal.
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_FUNCS([krb5_free_keytab_entry_contents \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_get_renewed_creds])
AC_CHECK_TYPES([krb5_realm], , , [#include <krb5.h>])
RRA_LIB_KRB5_RESTORE

dnl If we're building k4start, check for the Kerberos v4 libraries and add our
dnl local lifetime implementation if needed.
AS_IF([test x"$K4START" != x],
    [RRA_LIB_KRB4
     RRA_LIB_KRB4_SWITCH
     AC_CHECK_FUNCS([krb_life_to_time], , [AC_LIBOBJ([lifetime])])
     RRA_LIB_KRB4_RESTORE])

dnl See if AFS setpag support is desired.
AC_ARG_ENABLE([setpag],
    [AC_HELP_STRING([--enable-setpag], [Enable AFS setpag support])],
    [AS_IF([test x"$enableval" != xno], [RRA_LIB_KAFS])])

dnl Other portability checks.
AC_HEADER_TIME
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bitypes.h sys/time.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_SIGNAL
AC_CHECK_TYPES([long long])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit setsid])
AC_REPLACE_FUNCS([asprintf daemon mkstemp])

dnl Create the tests/data directory.
AC_CONFIG_COMMANDS([tests/data/.placeholder], [touch tests/data/.placeholder])

dnl Output the results.
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([tests/k4start/afs-t], [chmod +x tests/k4start/afs-t])
AC_CONFIG_FILES([tests/k4start/basic-t], [chmod +x tests/k4start/basic-t])
AC_CONFIG_FILES([tests/k4start/pod-t], [chmod +x tests/k4start/pod-t])
AC_CONFIG_FILES([tests/k5start/afs-t], [chmod +x tests/k5start/afs-t])
AC_CONFIG_FILES([tests/k5start/basic-t], [chmod +x tests/k5start/basic-t])
AC_CONFIG_FILES([tests/k5start/pod-t], [chmod +x tests/k5start/pod-t])
AC_CONFIG_FILES([tests/krenew/afs-t], [chmod +x tests/krenew/afs-t])
AC_CONFIG_FILES([tests/krenew/basic-t], [chmod +x tests/krenew/basic-t])
AC_CONFIG_FILES([tests/krenew/pod-t], [chmod +x tests/krenew/pod-t])
AC_OUTPUT
