dnl Process this file with autoconf to produce a configure script.
dnl $Id$

AC_REVISION($Revision$)
AC_PREREQ(2.57)
AC_INIT([kstart], [2.8], [rra@stanford.edu])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

dnl aklog is the old name for the utility to get AFS tokens from Kerberos
dnl tickets.  afslog is the name of the utility that comes with KTH Kerberos
dnl or Heimdal.  By default, we build in support for calling it if we find
dnl either on the user's path or if the user specifies a default path.
AC_ARG_WITH([aklog],
    AC_HELP_STRING([--with-aklog=PATH],
        [Path to aklog or other AFS token program]),
    [if test x"$withval" != xno ; then
        PATH_AKLOG=$withval
    fi],
    [AC_PATH_PROGS([PATH_AKLOG], [aklog afslog])])
if test -n "$PATH_AKLOG" ; then
    AC_DEFINE_UNQUOTED([PATH_AKLOG], ["$PATH_AKLOG"],
        [Full path to aklog binary.])
fi

dnl Find the networking libraries before looking for Kerberos.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket], ,
    [AC_CHECK_LIB([nsl], [socket], [LIBS="$LIBS -lsocket -lnsl"], ,
        [-lsocket])])
AC_SEARCH_LIBS([res_search], [resolv])
AC_SEARCH_LIBS([crypt], [crypt])

dnl Where to find the Kerberos libraries.
AC_ARG_WITH([kerberos],
    AC_HELP_STRING([--with-kerberos=DIR],
        [Path to Kerberos headers and libraries]),
    [if test x"$withval" != xno ; then
         CPPFLAGS="-I$kerberos/include $CPPFLAGS"
         LDFLAGS="-L$kerberos/lib $LDFLAGS"
     fi])

dnl Find the Kerberos libraries.  Supports both MIT and Heimdal.
AC_CHECK_LIB([krb4], [main],
    [KRBLIBS="-lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err"],
    [KRBLIBS="-lcrypto -lkrb"],
    [-ldes425 -lkrb5 -lk5crypto -lcom_err])
AC_CHECK_LIB([k5crypto], [main],
    [KRB5LIBS="-lkrb5 -lk5crypto -lcom_err"],
    [KRB5LIBS="-lkrb5 -lcrypto -lasn1 -lroken -lcom_err"],
    [-lk5crypto -lcom_err])
AC_SUBST([KRBLIBS])
AC_SUBST([KRB5LIBS])

dnl Allow the user to build statically against the Kerberos libraries.
AC_ARG_ENABLE([static],
    AC_HELP_STRING([--enable-static],
        [Link against the static Kerberos libraries]),
    [if test x"$enableval" = xyes ; then
        KRBLIBS="-Wl,-Bstatic $KRBLIBS -Wl,-Bdynamic"
        KRB5LIBS="-Wl,-Bstatic $KRB5LIBS -Wl,-Bdynamic"
     fi])

dnl See if AFS setpag support is desired.
AC_ARG_WITH([afs-setpag],
    AC_HELP_STRING([--with-afs-setpag=DIR],
        [Enable AFS setpag support, libraries at DIR]),
    [if test x"$withval" != xno ; then
        if test x"$withval" != xyes ; then
            LDFLAGS="-L$withval/lib $LDFLAGS"
        fi
        AC_CHECK_LIB([afsauthent], [setpag],
            [LIBS="-lafsauthent -lafsrpc -lpthread $LIBS"
             AC_DEFINE([HAVE_SETPAG], 1,
                [Define to 1 if you have the AFS setpag function.])],
            [AC_MSG_ERROR([setpag function not found])],
            [-lafsrpc -lpthread])
     fi])

dnl Allow the user to disable Kerberos v4 support.  Useful for building
dnl against just Heimdal, without KTH Kerberos.
K4START=k4start
K4START_MAN=k4start.1
AC_ARG_ENABLE([k4start],
    AC_HELP_STRING([--disable-k4start],
        [Don't build k4start (Kerberos v4 support)]),
    [if test x"$enableval" = xno ; then
        K4START=
        K4START_MAN=
     fi])
AC_SUBST([K4START])
AC_SUBST([K4START_MAN])

dnl Check to see if we need to use our local lifetime function.  All of this
dnl machinery is annoying, but required because AC_REPLACE_FUNCS doesn't take
dnl an argument for extra libraries to check.
save_LIBS=$LIBS
LIBS="$KRBLIBS $LIBS"
if test x"$K4START" != x ; then
    AC_CHECK_FUNCS([krb_life_to_time], , [AC_LIBOBJ([lifetime])])
fi
LIBS=$save_LIBS

dnl Checks for header files.
AC_CHECK_HEADERS([kerberosIV/krb.h])

dnl Checks for types.
AC_CHECK_TYPES([long long])
AC_CHECK_TYPES([krb5_realm], , , [#include <krb5.h>])

dnl Checks for functions.
AC_CHECK_FUNCS([setsid])
AC_REPLACE_FUNCS([daemon mkstemp])

dnl Check for Heimdal functions and different generations of Kerberos v5
dnl libraries.
save_LIBS=$LIBS
LIBS="$KRB5LIBS $LIBS"
AC_CHECK_FUNCS([initialize_krb5_error_table])
AC_CHECK_FUNCS([krb5_free_keytab_entry_contents])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_set_default_flags])
LIBS=$save_LIBS

dnl Output the results.
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
