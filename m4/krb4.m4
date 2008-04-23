dnl krb4.m4 -- Find the compiler and linker flags for Kerberos v4.
dnl $Id$
dnl
dnl Finds the compiler and linker flags for linking with Kerberos v4 libraries
dnl and sets the substitution variables KRB4_CPPFLAGS, KRB4_LDFLAGS, and
dnl KRB4_LIBS.  Provides the --with-krb4 configure option to specify a
dnl non-standard path to the Kerberos libraries.  Uses krb5-config where
dnl available unless reduced dependencies is requested.
dnl
dnl Provides the macro RRA_LIB_KRB4 and sets the substitution variables
dnl KRB4_CPPFLAGS, KRB4_LDFLAGS, and KRB4_LIBS.  Also provides
dnl RRA_LIB_KRB4_SET to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl Kerberos libraries; RRA_LIB_KRB4_SWITCH to do the same but save the
dnl current values first; and RRA_LIB_KRB4_RESTORE to restore those settings
dnl to before the last RRA_LIB_KRB4_SWITCH.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2005, 2006, 2007, 2008
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

dnl Set CPPFLAGS, LDFLAGS, and LIBS to values including the Kerberos v4
dnl settings.
AC_DEFUN([RRA_LIB_KRB4_SET],
[CPPFLAGS="$KRB4_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$KRB4_LDFLAGS $LDFLAGS"
 LIBS="$KRB4_LIBS $LIBS"])

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Kerberos v4 flags.  Used as a wrapper, with
dnl RRA_LIB_KRB4_RESTORE, around tests.
AC_DEFUN([RRA_LIB_KRB4_SWITCH],
[rra_krb4_save_CPPFLAGS="$CPPFLAGS"
 rra_krb4_save_LDFLAGS="$LDFLAGS"
 rra_krb4_save_LIBS="$LIBS"
 RRA_LIB_KRB4_SET])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_KRB4_SWITCH was called).
AC_DEFUN([RRA_LIB_KRB4_RESTORE],
[CPPFLAGS="$rra_krb4_save_CPPFLAGS"
 LDFLAGS="$rra_krb4_save_LDFLAGS"
 LIBS="$rra_krb4_save_LIBS"])

dnl Set KRB4_CPPFLAGS and KRB4_LDFLAGS based on rra_krb4_root.
AC_DEFUN([_RRA_LIB_KRB4_PATHS],
[AS_IF([test x"$rra_krb4_root" != x],
    [AS_IF([test x"$rra_krb4_root" != x/usr],
        [KRB4_CPPFLAGS="-I${rra_krb4_root}/include"])
     KRB4_LDFLAGS="-L${rra_krb4_root}/lib"])])

dnl Does the appropriate library checks for reduced-dependency Kerberos v4
dnl linkage.
AC_DEFUN([_RRA_LIB_KRB4_REDUCED],
[RRA_LIB_KRB4_SWITCH
 AC_CHECK_LIB([krb4], [krb_get_svc_in_tkt], [KRB4_LIBS="-lkrb4"],
    [AC_CHECK_LIB([krb], [krb_get_svc_in_tkt], [KRB4_LIBS="-lkrb"],
        [AC_MSG_ERROR([cannot find usable Kerberos v4 library])])])
 RRA_LIB_KRB4_RESTORE])

dnl Does the appropriate library checks for Kerberos v4 linkage when we don't
dnl have krb5-config or reduced dependencies.
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
            [rra_krb4_extra="-lkrb5support $rra_krb4_pthread"], ,
            [$rra_krb4_pthread])])
     AC_CHECK_LIB([krb4], [krb_get_svc_in_tkt],
        [KRB4_LIBS="-lkrb4 $rra_krb4_extra"],
        [AC_MSG_ERROR([cannot find usable Kerberos v4 library])],
        [$rra_krb4_extra])],
    [$rra_krb4_extra])
 RRA_LIB_KRB4_RESTORE])

dnl Additional checks for portability that apply to either way that we find
dnl the right libraries.
AC_DEFUN([_RRA_LIB_KRB4_EXTRA],
[RRA_LIB_KRB4_SWITCH
 AC_CHECK_HEADERS([kerberosIV/krb.h])
 RRA_LIB_KRB4_RESTORE])

dnl Sanity-check the results of krb5-config and be sure we can really link a
dnl Kerberos program.
AC_DEFUN([_RRA_LIB_KRB4_CHECK],
[RRA_LIB_KRB4_SWITCH
 AC_CHECK_FUNC([krb_get_svc_in_tkt], ,
    [AC_MSG_FAILURE([krb5-config results fail for Kerberos v4])])
 RRA_LIB_KRB4_RESTORE])

dnl The main macro.
AC_DEFUN([RRA_LIB_KRB4],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
rra_krb4_root=
KRB4_CPPFLAGS=
KRB4_LDFLAGS=
KRB4_LIBS=
AC_SUBST([KRB4_CPPFLAGS])
AC_SUBST([KRB4_LDFLAGS])
AC_SUBST([KRB4_LIBS])
AC_ARG_WITH([krb4],
    [AC_HELP_STRING([--with-krb4=DIR],
        [Location of Kerberos v4 headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_krb4_root="$withval"])])
AS_IF([test x"$rra_reduced_depends" = xtrue],
    [_RRA_LIB_KRB4_PATHS
     _RRA_LIB_KRB4_REDUCED],
    [AC_ARG_VAR([KRB5_CONFIG], [Path to krb5-config])
     AS_IF([test x"$rra_krb4_root" != x && test -z "$KRB5_CONFIG"],
         [AS_IF([test -x "${rra_krb4_root}/bin/krb5-config"],
             [KRB5_CONFIG="${rra_krb4_root}/bin/krb5-config"])],
         [AC_PATH_PROG([KRB5_CONFIG], [krb5-config])])
     AS_IF([test x"$KRB5_CONFIG" != x && test -x "$KRB5_CONFIG"],
         [AC_CACHE_CHECK([for krb4 support in krb5-config],
             [rra_cv_lib_krb4_config],
             [AS_IF(["$KRB5_CONFIG" | grep krb4 > /dev/null 2>&1],
                 [rra_cv_lib_krb4_config=yes],
                 [rra_cv_lib_krb4_config=no])])
          AS_IF([test "$rra_cv_lib_krb4_config" = yes],
              [KRB4_CPPFLAGS=`"$KRB5_CONFIG" --cflags krb4`
               KRB4_LIBS=`"$KRB5_CONFIG" --libs krb4`],
              [_RRA_LIB_KRB4_PATHS
               _RRA_LIB_KRB4_MANUAL])
          KRB4_CPPFLAGS=`echo "$KRB5_CPPFLAGS" | sed 's%-I/usr/include ?%%'`
          _RRA_LIB_KRB4_CHECK],
         [_RRA_LIB_KRB4_PATHS
          _RRA_LIB_KRB4_MANUAL])])
 _RRA_LIB_KRB4_EXTRA])
