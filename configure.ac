dnl Autoconf configuration for kstart.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
dnl     2011 The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

AC_PREREQ([2.64])
AC_INIT([kstart], [3.16], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news foreign silent-rules subdir-objects
    -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl aklog is the standard name for the utility to get AFS tokens from Kerberos
dnl tickets.  afslog is the name of the utility that comes with Heimdal.  By
dnl default, we build in support for calling it if we find either on the
dnl user's path or if the user specifies a default path.
AC_ARG_WITH([aklog],
    AC_HELP_STRING([--with-aklog=PATH],
        [Path to aklog or other AFS token program]),
    [AS_IF([test x"$withval" != xno], [PATH_AKLOG=$withval])],
    [AC_PATH_PROGS([PATH_AKLOG], [aklog afslog])])
AC_DEFINE_UNQUOTED([PATH_AKLOG], ["$PATH_AKLOG"],
    [Full path to aklog binary.])

dnl Check for the Kerberos v5 libraries and for portability between MIT and
dnl Heimdal.
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_FUNCS([krb5_cc_copy_cache \
    krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_principal_get_realm \
    krb5_xfree])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])
AC_CHECK_DECLS([krb5_kt_free_entry], [], [], [RRA_INCLUDES_KRB5])
AC_CHECK_FUNCS([krb5_get_renewed_creds], [],
    [AC_CHECK_FUNCS([krb5_copy_creds_contents])
     AC_LIBOBJ([krb5-renew])])
AC_LIBOBJ([krb5-extra])
RRA_LIB_KRB5_RESTORE

dnl Allow the user to disable Kerberos v4 support.  If the user doesn't
dnl explicitly disable k4start, it's built if Kerberos v4 libraries are found
dnl and isn't built otherwise.
rra_build_k4start=
AC_ARG_ENABLE([k4start],
    AC_HELP_STRING([--disable-k4start],
        [Don't build k4start (Kerberos v4 support)]),
    [AS_IF([test x"$enableval" = xno], [rra_build_k4start=false])])
AS_IF([test x"$rra_build_k4start" != xfalse],
    [RRA_LIB_KRB4_OPTIONAL
     AS_IF([test x"$rra_use_krb4" = xtrue],
        [RRA_LIB_KRB4_SWITCH
         AC_CHECK_FUNCS([krb_life_to_time], , [AC_LIBOBJ([lifetime])])
         RRA_LIB_KRB4_RESTORE
         rra_build_k4start=true],
        [rra_build_k4start=false])])
AM_CONDITIONAL([K4START], [test x"$rra_build_k4start" = xtrue])

dnl See if AFS setpag support is desired.
rra_build_kafs=false
AC_ARG_ENABLE([setpag],
    [AC_HELP_STRING([--enable-setpag], [Enable AFS setpag support])],
    [AS_IF([test x"$enableval" != xno], [RRA_LIB_KAFS])])
AM_CONDITIONAL([NEED_KAFS], [test x"$rra_build_kafs" = xtrue])

dnl Other portability checks.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([strings.h sys/bitypes.h sys/time.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_TYPE_UINT32_T
AC_CHECK_TYPES([sig_atomic_t], [], [],
    [#include <sys/types.h>
     #include <signal.h>])
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit setsid])
AC_REPLACE_FUNCS([asprintf daemon mkstemp setenv strlcat strlcpy strndup])

dnl Create the tests/data directory.
AC_CONFIG_COMMANDS([tests/data/.placeholder], [touch tests/data/.placeholder])

dnl Output the results.
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
