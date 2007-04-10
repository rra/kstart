dnl krb5.m4 -- Find the compiler and linker flags for Kerberos v5.
dnl $Id$
dnl
dnl Finds the compiler and linker flags and adds them to CPPFLAGS and LIBS.
dnl Provides --with-kerberos, --enable-reduced-depends, and --enable-static
dnl configure options to control how linking with Kerberos is done.  Uses
dnl krb5-config where available unless reduced dependencies is requested.
dnl
dnl Provides the macro RRA_LIB_KRB5, which takes two arguments.  The first
dnl argument is the type of Kerberos libraries desired (one of the arguments
dnl to krb5-config).  The second argument is whether to probe for networking
dnl libraries in the non-krb5-config, non-reduced-dependencies case and should
dnl be either "true" (if the program doesn't otherwise use the networking
dnl libraries) or "false" (if it is already probing for the networking
dnl libraries separately).
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2005, 2006, 2007
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See README for licensing terms.

dnl Does the appropriate library checks for reduced-dependency krb5 linkage.
AC_DEFUN([_RRA_LIB_KRB5_KRB5_REDUCED],
[AC_CHECK_LIB([krb5], [krb5_init_context], [KRBLIBS="-lkrb5"],
    [AC_MSG_ERROR([cannot find usable Kerberos v5 library])])])

dnl Does the appropriate library checks for reduced-dependency krb4 linkage.
AC_DEFUN([_RRA_LIB_KRB5_KRB4_REDUCED],
[AC_CHECK_LIB([krb4], [krb_get_svc_in_tkt], [KRBLIBS="-lkrb4"],
    [AC_CHECK_LIB([krb], [krb_get_svc_in_tkt], [KRBLIBS="-lkrb"],
        [AC_MSG_ERROR([cannot find usable Kerberos v4 library])])])])

dnl Does the appropriate library checks for krb5 linkage.  Note that we have
dnl to check for a different function the second time since the Heimdal and
dnl MIT libraries have the same name.
AC_DEFUN([_RRA_LIB_KRB5_KRB5],
[AC_CHECK_LIB([krb5], [krb5_init_context],
    [KRBLIBS="-lkrb5 -lasn1 -lroken -lcrypto -lcom_err"],
    [KRB5EXTRA="-lk5crypto -lcom_err"
     AC_CHECK_LIB([krb5support], [krb5int_getspecific],
        [KRB5EXTRA="$KRB5EXTRA -lkrb5support"],
        [AC_SEARCH_LIBS([pthread_setspecific], [pthreads pthread])
         AC_CHECK_LIB([krb5support], [krb5int_setspecific],
            [KRB5EXTRA="$KRB5EXTRA -lkrb5support"])])
     AC_CHECK_LIB([krb5], [krb5_cc_default],
        [KRBLIBS="-lkrb5 $KRB5EXTRA"],
        [AC_MSG_ERROR([cannot find usable Kerberos v5 library])],
        [$KRB5EXTRA])],
    [-lasn1 -lroken -lcrypto -lcom_err])])

dnl Does the appropriate library checks for krb4 linkage.
AC_DEFUN([_RRA_LIB_KRB5_KRB4],
[KRB4EXTRA=
AC_CHECK_LIB([crypto], [des_set_key], [KRB4EXTRA="-lcrypto"],
    [KRB4EXTRA="-ldes"])
AC_CHECK_LIB([krb], [krb_get_svc_in_tkt],
    [KRBLIBS="-lkrb $KRB4EXTRA"],
    [KRB5EXTRA="-ldes425 -lkrb5 -lk5crypto -lcom_err"
     AC_CHECK_LIB([krb5support], [krb5int_getspecific],
        [KRB5EXTRA="$KRB5EXTRA -lkrb5support"],
        [AC_SEARCH_LIBS([pthread_setspecific], [pthreads pthread])
         AC_CHECK_LIB([krb5support], [krb5int_setspecific],
            [KRB5EXTRA="$KRB5EXTRA -lkrb5support"])])
     AC_CHECK_LIB([krb4], [krb_get_svc_in_tkt],
        [KRBLIBS="-lkrb4 $KRB5EXTRA"],
        [AC_MSG_ERROR([cannot find usable Kerberos v4 library])],
        [$KRB5EXTRA])],
    [$KRB4EXTRA])])

dnl Additional checks for portability between MIT and Heimdal if krb5
dnl libraries were requested.
AC_DEFUN([_RRA_LIB_KRB5_KRB5_EXTRA],
[AC_CHECK_FUNCS([krb5_free_keytab_entry_contents \
                 krb5_get_init_creds_opt_set_default_flags \
                 krb5_get_renewed_creds])
AC_CHECK_TYPES([krb5_realm], , , [#include <krb5.h>])
rra_krb5_uses_com_err=true
AS_IF([test x"$reduce_depends" = xtrue],
    [rra_krb5_uses_com_err=false
     AC_CHECK_FUNCS([krb5_err], ,
        [AC_LIBOBJ([krb5_err])
         AC_CHECK_FUNCS([krb5_get_error_message], ,
            [rra_krb5_uses_com_err=true
             AC_CHECK_HEADERS([et/com_err.h])
             AC_CHECK_LIB([com_err], [com_err], [LIBS="$LIBS -lcom_err"],
                [AC_MSG_ERROR([cannot find usable com_err library])])])])],
    [AC_CHECK_FUNCS([krb5_err], ,
        [AC_LIBOBJ([krb5_err])
         AC_CHECK_FUNCS([krb5_get_error_message])])])
AM_CONDITIONAL([USES_COM_ERR], [test x"$rra_krb5_uses_com_err" = xtrue])])

dnl Additional checks for portability if krb4 libraries were requested.
AC_DEFUN([_RRA_LIB_KRB5_KRB4_EXTRA],
[AC_CHECK_HEADERS([kerberosIV/krb.h])
AC_CHECK_FUNCS([krb_life_to_time], , [AC_LIBOBJ([lifetime])])])

dnl The main macro.
AC_DEFUN([RRA_LIB_KRB5],
[KRBROOT=
AC_ARG_WITH([kerberos],
    AC_HELP_STRING([--with-kerberos=DIR],
        [Location of Kerberos headers and libraries]),
    [AS_IF([test x"$withval" != xno], [KRBROOT="$withval"])])

reduce_depends=false
AC_ARG_ENABLE([reduced-depends],
    AC_HELP_STRING([--enable-reduced-depends],
        [Try to minimize shared library dependencies]),
    [AS_IF([test x"$enableval" = xyes],
         [AS_IF([test x"$KRBROOT" != x],
             [AS_IF([test x"$KRBROOT" != x/usr],
                 [CPPFLAGS="-I$KRBROOT/include"])
              LDFLAGS="$LDFLAGS -L$KRBROOT/lib"])
          case "$1" in
          krb5)   _RRA_LIB_KRB5_KRB5_REDUCED   ;;
          krb4)   _RRA_LIB_KRB5_KRB4_REDUCED   ;;
          *)      AC_MSG_ERROR([BUG: unknown library type $1]) ;;
          esac
          reduce_depends=true])])

dnl Support static linkage as best we can.  Set a variable and do the
dnl wrapping later on.
static=false
AC_ARG_ENABLE([static],
    AC_HELP_STRING([--enable-static],
        [Link against the static Kerberos libraries]),
    [AS_IF([test x"$enableval" = xyes],
         [AS_IF([test x"$reduce_depends" = xtrue],
[AC_MSG_ERROR([--enable-static conflicts with --enable-reduced-depends])])
          static=true])])

dnl Checking for the neworking libraries shouldn't be necessary for the
dnl krb5-config case, but apparently it is at least for MIT Kerberos 1.2.
dnl This will unfortunately mean multiple -lsocket -lnsl references when
dnl building with current versions of Kerberos, but this shouldn't cause
dnl any practical problems.
AS_IF([test x"$reduce_depends" != xtrue],
    [AS_IF([test x"$2" = xtrue],
        [AC_SEARCH_LIBS([gethostbyname], [nsl])
         AC_SEARCH_LIBS([socket], [socket], ,
            [AC_CHECK_LIB([nsl], [socket],
                [LIBS="-lnsl -lsocket $LIBS"], , [-lsocket])])])
    AC_ARG_VAR([KRB5_CONFIG], [Path to krb5-config])
    AS_IF([test x"$KRBROOT" != x],
        [AS_IF([test -x "$KRBROOT/bin/krb5-config"],
            [KRB5_CONFIG="$KRBROOT/bin/krb5-config"])],
        [AC_PATH_PROG([KRB5_CONFIG], [krb5-config])])

    # We can't use krb5-config if building static since we can't tell what
    # of the libraries it gives us should be static and which should be
    # dynamic.
    AS_IF([test x"$KRB5_CONFIG" != x && test x"$static" != xtrue],
        [AC_MSG_CHECKING([for $1 support in krb5-config])
         AS_IF(["$KRB5_CONFIG" | grep '$1' > /dev/null 2>&1],
            [AC_MSG_RESULT([yes])
             KRBCPPFLAGS=`"$KRB5_CONFIG" --cflags '$1'`
             KRBLIBS=`"$KRB5_CONFIG" --libs '$1'`],
            [AC_MSG_RESULT([no])
             KRBCPPFLAGS=`"$KRB5_CONFIG" --cflags`
             KRBLIBS=`"$KRB5_CONFIG" --libs`])
         KRBCPPFLAGS=`echo "$KRBCPPFLAGS" | sed 's%-I/usr/include ?%%'`],
        [AS_IF([test x"$KRBROOT" != x],
            [AS_IF([test x"$KRBROOT" != x/usr],
                [KRBCPPFLAGS="-I$KRBROOT/include"])
             LDFLAGS="$LDFLAGS -L$KRBROOT/lib"])
         AC_SEARCH_LIBS([res_search], [resolv], ,
             [AC_SEARCH_LIBS([__res_search], [resolv])])
         AC_SEARCH_LIBS([crypt], [crypt])
         case "$1" in
         krb5)   _RRA_LIB_KRB5_KRB5   ;;
         krb4)   _RRA_LIB_KRB5_KRB4   ;;
         *)      AC_MSG_ERROR([BUG: unknown library type $1]) ;;
         esac])
    AS_IF([test x"$KRBCPPFLAGS" != x], [CPPFLAGS="$CPPFLAGS $KRBCPPFLAGS"])])

dnl Generate the final library list and put it into the standard variables.
AS_IF([test x"$static" = xtrue],
    [LIBS="-Wl,-Bstatic $KRBLIBS -Wl,-Bdynamic $LIBS"],
    [LIBS="$KRBLIBS $LIBS"])
CPPFLAGS=`echo "$CPPFLAGS" | sed 's/^  *//'`
LDFLAGS=`echo "$LDFLAGS" | sed 's/^  *//'`

dnl Run any extra checks for the desired libraries.
case "$1" in
krb5)   _RRA_LIB_KRB5_KRB5_EXTRA   ;;
krb4)   _RRA_LIB_KRB5_KRB4_EXTRA   ;;
esac])
