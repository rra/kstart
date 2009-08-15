dnl Find the compiler and linker flags for Kerberos v4.
dnl
dnl Finds the compiler and linker flags for linking with Kerberos v4
dnl libraries.  Provides the --with-krb4, --with-krb4-include, and
dnl --with-krb4-lib configure options to specify non-standard paths to the
dnl Kerberos libraries.  Uses krb5-config where available unless reduced
dnl dependencies is requested.
dnl
dnl Provides the macro RRA_LIB_KRB4 and sets the substitution variables
dnl KRB4_CPPFLAGS, KRB4_LDFLAGS, and KRB4_LIBS.  Also provides
dnl RRA_LIB_KRB4_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl Kerberos libraries, saving the current values first, and
dnl RRA_LIB_KRB4_RESTORE to restore those settings to before the last
dnl RRA_LIB_KRB4_SWITCH.
dnl
dnl Provides the RRA_LIB_KRB4_OPTIONAL macro, which should be used if Kerberos
dnl support is optional.  This macro will still always set the substitution
dnl variables, but they'll be empty unless --with-krb4 is given.  Also,
dnl HAVE_KRB4 will be defined if --with-krb4 is given and $rra_use_krb4 will
dnl be set to "true".
dnl
dnl Depends on RRA_ENABLE_REDUCED_DEPENDS and RRA_SET_LDFLAGS.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2005, 2006, 2007, 2008, 2009
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Kerberos v4 flags.  Used as a wrapper, with
dnl RRA_LIB_KRB4_RESTORE, around tests.
AC_DEFUN([RRA_LIB_KRB4_SWITCH],
[rra_krb4_save_CPPFLAGS="$CPPFLAGS"
 rra_krb4_save_LDFLAGS="$LDFLAGS"
 rra_krb4_save_LIBS="$LIBS"
 CPPFLAGS="$KRB4_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$KRB4_LDFLAGS $LDFLAGS"
 LIBS="$KRB4_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_KRB4_SWITCH was called).
AC_DEFUN([RRA_LIB_KRB4_RESTORE],
[CPPFLAGS="$rra_krb4_save_CPPFLAGS"
 LDFLAGS="$rra_krb4_save_LDFLAGS"
 LIBS="$rra_krb4_save_LIBS"])

dnl Set KRB4_CPPFLAGS and KRB4_LDFLAGS based on rra_krb4_root,
dnl rra_krb4_libdir, and rra_krb4_includedir.
AC_DEFUN([_RRA_LIB_KRB4_PATHS],
[AS_IF([test x"$rra_krb4_libdir" != x],
    [KRB4_LDFLAGS="-L$rra_krb4_libdir"],
    [AS_IF([test x"$rra_krb4_root" != x],
        [RRA_SET_LDFLAGS([KRB4_LDFLAGS], [$rra_krb4_root])])])
 AS_IF([test x"$rra_krb4_includedir" != x],
    [KRB4_CPPFLAGS="-I$rra_krb4_includedir"],
    [AS_IF([test x"$rra_krb4_root" != x],
        [AS_IF([test x"$rra_krb4_root" != x/usr],
            [KRB4_CPPFLAGS="-I${rra_krb4_root}/include"])])])])

dnl Does the appropriate library checks for reduced-dependency Kerberos v4
dnl linkage.  The single argument, if true, says to fail if Kerberos v4 could
dnl not be found.
AC_DEFUN([_RRA_LIB_KRB4_REDUCED],
[RRA_LIB_KRB4_SWITCH
 AC_CHECK_LIB([krb4], [krb_get_svc_in_tkt], [KRB4_LIBS="-lkrb4"],
    [AC_CHECK_LIB([krb], [krb_get_svc_in_tkt], [KRB4_LIBS="-lkrb"],
        [AS_IF([test x"$1" = xtrue],
            [AC_MSG_ERROR([cannot find usable Kerberos v4 library])])])])
 AC_CHECK_HEADERS([kerberosIV/krb.h])
 RRA_LIB_KRB4_RESTORE])

dnl Does the appropriate library checks for Kerberos v4 linkage when we don't
dnl have krb5-config or reduced dependencies.  The single argument, if true,
dnl says to fail if Kerberos v4 could not be found.
AC_DEFUN([_RRA_LIB_KRB4_MANUAL],
[RRA_LIB_KRB4_SWITCH
 rra_krb4_extra=
 LIBS=
 AC_SEARCH_LIBS([res_search], [resolv], ,
    [AC_SEARCH_LIBS([__res_search], [resolv])])
 AC_SEARCH_LIBS([gethostbyname], [nsl])
 AC_SEARCH_LIBS([socket], [socket], ,
    [AC_CHECK_LIB([nsl], [socket], [LIBS="-lnsl -lsocket $LIBS"], ,
        [-lsocket])])
 AC_SEARCH_LIBS([crypt], [crypt])
 rra_krb4_extra="$LIBS"
 LIBS="$rra_krb4_save_LIBS"
 AC_CHECK_LIB([crypto], [des_set_key],
    [rra_krb4_extra="-lcrypto $rra_krb4_extra"],
    [AC_CHECK_LIB([des], [des_set_key],
        [rra_krb4_extra="-ldes $rra_krb4_extra"])])
 AC_CHECK_LIB([krb], [krb_get_svc_in_tkt],
    [KRB4_LIBS="-lkrb $rra_krb4_extra"],
    [rra_krb4_extra="-ldes425 -lkrb5 -lk5crypto -lcom_err $rra_krb4_extra"
     AC_CHECK_LIB([krb5support], [krb5int_getspecific],
        [rra_krb4_extra="$rra_krb4_extra -lkrb5support"],
        [AC_CHECK_LIB([pthreads], [pthread_setspecific],
            [rra_krb4_pthread="-lpthreads"],
            [AC_CHECK_LIB([pthread], [pthread_setspecific],
                [rra_krb4_pthread="-lpthread"])])
         AC_CHECK_LIB([krb5support], [krb5int_setspecific],
            [rra_krb4_extra="-lkrb5support $rra_krb4_extra $rra_krb4_pthread"],
            , [$rra_krb4_pthread])])
     AC_CHECK_LIB([krb4], [krb_get_svc_in_tkt],
        [KRB4_LIBS="-lkrb4 $rra_krb4_extra"],
        [AS_IF([test x"$1" = xtrue],
            [AC_MSG_ERROR([cannot find usable Kerberos v4 library])])],
        [$rra_krb4_extra])],
    [$rra_krb4_extra])
 AS_IF([test x"$KRB4_LIBS" != x], [AC_CHECK_HEADERS([kerberosIV/krb.h])])
 RRA_LIB_KRB4_RESTORE])

dnl Sanity-check the results of krb5-config and be sure we can really link a
dnl Kerberos program.  If that fails, clear KRB4_CPPFLAGS and KRB4_LIBS so
dnl that we know we don't have usable flags and fall back on the manual
dnl check.
AC_DEFUN([_RRA_LIB_KRB4_CHECK],
[RRA_LIB_KRB4_SWITCH
 AC_CHECK_FUNC([krb_get_svc_in_tkt],
    [RRA_LIB_KRB4_RESTORE],
    [RRA_LIB_KRB4_RESTORE
     KRB4_CPPFLAGS=
     KRB4_LIBS=
     _RRA_LIB_KRB4_PATHS
     _RRA_LIB_KRB4_MANUAL([$1])])])

dnl The core of the library checking, shared between RRA_LIB_KRB4 and
dnl RRA_LIB_KRB4_OPTIONAL.  The single argument, if "true", says to fail if
dnl Kerberos could not be found.
AC_DEFUN([_RRA_LIB_KRB4_INTERNAL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 AS_IF([test x"$rra_reduced_depends" = xtrue],
    [_RRA_LIB_KRB4_PATHS
     _RRA_LIB_KRB4_REDUCED([$1])],
    [AC_ARG_VAR([KRB5_CONFIG], [Path to krb5-config])
     AS_IF([test x"$rra_krb4_root" != x && test -z "$KRB5_CONFIG"],
         [AS_IF([test -x "${rra_krb4_root}/bin/krb5-config"],
             [KRB5_CONFIG="${rra_krb4_root}/bin/krb5-config"])],
         [AC_PATH_PROG([KRB5_CONFIG], [krb5-config])])
     AS_IF([test x"$KRB5_CONFIG" != x && test -x "$KRB5_CONFIG"],
         [AC_CACHE_CHECK([for krb4 support in krb5-config],
             [rra_cv_lib_krb4_config],
             [AS_IF(["$KRB5_CONFIG" 2>&1 | grep krb4 >/dev/null 2>&1],
                 [rra_cv_lib_krb4_config=yes],
                 [rra_cv_lib_krb4_config=no])])
          AS_IF([test x"$rra_cv_lib_krb4_config" = xyes],
              [KRB4_CPPFLAGS=`"$KRB5_CONFIG" --cflags krb4 2>/dev/null`
               KRB4_LIBS=`"$KRB5_CONFIG" --libs krb4 2>/dev/null`
               KRB4_CPPFLAGS=`echo "$KRB4_CPPFLAGS"|sed 's%-I/usr/include ?%%'`
               _RRA_LIB_KRB4_CHECK([$1])
               RRA_LIB_KRB4_SWITCH
               AC_CHECK_HEADERS([kerberosIV/krb.h])
               RRA_LIB_KRB4_RESTORE],
              [_RRA_LIB_KRB4_PATHS
               _RRA_LIB_KRB4_MANUAL([$1])])],
         [_RRA_LIB_KRB4_PATHS
          _RRA_LIB_KRB4_MANUAL([$1])])])])

dnl The main macro for packages with mandatory Kerberos support.
AC_DEFUN([RRA_LIB_KRB4],
[rra_krb4_root=
 rra_krb4_libdir=
 rra_krb4_includedir=
 KRB4_CPPFLAGS=
 KRB4_LDFLAGS=
 KRB4_LIBS=
 AC_SUBST([KRB4_CPPFLAGS])
 AC_SUBST([KRB4_LDFLAGS])
 AC_SUBST([KRB4_LIBS])

 AC_ARG_WITH([krb4],
    [AS_HELP_STRING([--with-krb4=DIR],
        [Location of Kerberos v4 headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_krb4_root="$withval"])])
 AC_ARG_WITH([krb4-include],
    [AS_HELP_STRING([--with-krb4-include=DIR],
        [Location of Kerberos v4 headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_krb4_includedir="$withval"])])
 AC_ARG_WITH([krb4-lib],
    [AS_HELP_STRING([--with-krb4-lib=DIR],
        [Location of Kerberos v4 libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_krb4_libdir="$withval"])])
 _RRA_LIB_KRB4_INTERNAL([true])])

dnl The main macro for packages with mandatory Kerberos support.
AC_DEFUN([RRA_LIB_KRB4_OPTIONAL],
[rra_krb4_root=
 rra_krb4_libdir=
 rra_krb4_includedir=
 rra_use_krb4=
 KRB4_CPPFLAGS=
 KRB4_LDFLAGS=
 KRB4_LIBS=
 AC_SUBST([KRB4_CPPFLAGS])
 AC_SUBST([KRB4_LDFLAGS])
 AC_SUBST([KRB4_LIBS])

 AC_ARG_WITH([krb4],
    [AS_HELP_STRING([--with-krb4@<:@=DIR@:>@],
        [Location of Kerberos v4 headers and libraries])],
    [AS_IF([test x"$withval" = xno],
        [rra_use_krb4=false],
        [AS_IF([test x"$withval" != xyes], [rra_krb4_root="$withval"])
         rra_use_krb4=true])])
 AC_ARG_WITH([krb4-include],
    [AS_HELP_STRING([--with-krb4-include=DIR],
        [Location of Kerberos v4 headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_krb4_includedir="$withval"])])
 AC_ARG_WITH([krb4-lib],
    [AS_HELP_STRING([--with-krb4-lib=DIR],
        [Location of Kerberos v4 libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_krb4_libdir="$withval"])])

 AS_IF([test x"$rra_use_krb4" != xfalse],
     [AS_IF([test x"$rra_use_krb4" = xtrue],
         [_RRA_LIB_KRB4_INTERNAL([true])],
         [_RRA_LIB_KRB4_INTERNAL([false])])])
 AS_IF([test x"$KRB4_LIBS" != x],
    [AC_DEFINE([HAVE_KRB4], 1, [Define to enable Kerberos v4 features.])])])
