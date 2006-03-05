dnl Process this file with autoconf to produce a configure script.
dnl $Id$

AC_REVISION($Revision$)
AC_PREREQ(2.57)
AC_INIT([kstart], [3.2], [rra@stanford.edu])

m4_include([m4/krb5.m4])

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

dnl Allow the user to disable Kerberos v4 support.  Useful for building
dnl against just Heimdal, without KTH Kerberos.
K4START=k4start
K4START_MAN='$(srcdir)/k4start.1'
AC_ARG_ENABLE([k4start],
    AC_HELP_STRING([--disable-k4start],
        [Don't build k4start (Kerberos v4 support)]),
    [if test x"$enableval" = xno ; then
        K4START=
        K4START_MAN=
     fi])
AC_SUBST([K4START])
AC_SUBST([K4START_MAN])

dnl Check for the Kerberos v5 libraries and for portability between krb5 and
dnl Heimdal when getting initial tickets.
save_LIBS=$LIBS
RRA_LIB_KRB5([krb5], [true])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_set_default_flags krb5_err \
                krb5_get_renewed_creds])
KRB5LIBS=$LIBS
LIBS=$save_LIBS
AC_SUBST([KRB5LIBS])

dnl If we're building k4start, check for the Kerberos v4 libraries and add our
dnl local lifetime implementation if needed.
KRBLIBS=
if test x"$K4START" != x ; then
    save_LIBS=$LIBS
    RRA_LIB_KRB5([krb4], [true])
    AC_CHECK_FUNCS([krb_life_to_time], , [AC_LIBOBJ([lifetime])])
    KRBLIBS=$LIBS
    LIBS=$save_LIBS
fi
AC_SUBST([KRBLIBS])

dnl See if AFS setpag support is desired.
AC_ARG_WITH([afs-setpag],
    AC_HELP_STRING([--with-afs-setpag=DIR],
        [Enable AFS setpag support, libraries at DIR]),
    [if test x"$withval" != xno ; then
        if test x"$withval" != xyes ; then
            LDFLAGS="-L$withval/lib $LDFLAGS"
        fi
        AC_CHECK_LIB([afsauthent], [lsetpag],
            [AFSLIBS="-lafsauthent -lafsrpc"
             AC_DEFINE([HAVE_LSETPAG], 1,
                [Define to 1 if you have the AFS lsetpag function.])],
            [AC_CHECK_LIB([kafs], [k_setpag],
                [AFSLIBS="-lkafs"
                 AC_CHECK_HEADERS([kafs.h])
                 AC_DEFINE([HAVE_K_SETPAG], 1,
                     [Define to 1 if you have the k_setpag function.])],
                [AC_MSG_ERROR([setpag function not found])])],
            [-lafsrpc])
        AC_SUBST([AFSLIBS])
     fi])

dnl Checks for header files.
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/time.h])

dnl Checks for types.
AC_CHECK_TYPES([long long])

dnl Checks for functions.
AC_CHECK_FUNCS([setsid])
AC_REPLACE_FUNCS([daemon mkstemp])

dnl Output the results.
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
