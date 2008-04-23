dnl kafs.m4 -- Test for a libkafs library or replacement.
dnl $Id$
dnl
dnl Check for a working libkafs library, and if not present, check how we can
dnl simulate what one would do ourselves, adding the appropriate things to
dnl LIBOBJS.  Depends on kafs-api.c, kafs-openafs.c, kafs-linux.c, and
dnl kafs-syscall.c for the implementation in the absence of a libkafs library.
dnl
dnl Provides RRA_LIB_KAFS.  If Kerberos libraries may be needed, LIBS and
dnl LDFLAGS must already be set appropriately before calling this.  If we need
dnl special CPPFLAGS, LIBS, or LDFLAGS to find AFS include files or libraries,
dnl those too must already be set.
dnl
dnl Also provides RRA_LIB_KAFS_SET to set CPPFLAGS, LDFLAGS, and LIBS to
dnl include libkafs; RRA_LIB_KAFS_SWITCH to do the same but save the current
dnl values first; and RRA_LIB_KAFS_RESTORE to restore those settings to before
dnl the last RRA_LIB_KFS_SWITCH.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2008 Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

dnl Set CPPFLAGS, LDFLAGS, and LIBS to values including the libkafs settings.
AC_DEFUN([RRA_LIB_KAFS_SET],
[CPPFLAGS="$KAFS_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$KAFS_LDFLAGS $LDFLAGS"
 LIBS="$KAFS_LIBS $LIBS"])

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the libkafs flags.  Used as a wrapper, with
dnl RRA_LIB_KAFS_RESTORE, around tests.
AC_DEFUN([RRA_LIB_KAFS_SWITCH],
[rra_kafs_save_CPPFLAGS="$CPPFLAGS"
 rra_kafs_save_LDFLAGS="$LDFLAGS"
 rra_kafs_save_LIBS="$LIBS"
 RRA_LIB_KAFS_SET])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_KAFS_SWITCH was called).
AC_DEFUN([RRA_LIB_KAFS_RESTORE],
[CPPFLAGS="$rra_kafs_save_CPPFLAGS"
 LDFLAGS="$rra_kafs_save_LDFLAGS"
 LIBS="$rra_kafs_save_LIBS"])

dnl Support --with-afs to specify the location of the AFS libraries and header
dnl files.
AC_DEFUN([_RRA_LIB_KAFS_WITH],
[AC_ARG_WITH([afs],
    [AC_HELP_STRING([--with-afs=DIR],
        [Location of AFS headers and libraries])],
    [AS_IF([test x"$withval" != xno && test x"$withval" != xyes],
        [KAFS_CPPFLAGS="-I${withval}/include"
         KAFS_LDFLAGS="-L${withval}/lib -L${withval}/lib/afs"])])])

dnl Probe for lsetpag in the AFS libraries.  This is required on AIX and IRIX
dnl since we can't use the regular syscall interface there.
AC_DEFUN([_RRA_LIB_KAFS_LSETPAG],
[_RRA_LIB_KAFS_WITH
 RRA_LIB_KAFS_SWITCH
 LIBS=
 AC_SEARCH_LIBS([pthread_getspecific], [pthread])
 AC_SEARCH_LIBS([res_search], [resolv], ,
    [AC_SEARCH_LIBS([__res_search], [resolv])])
 AC_SEARCH_LIBS([gethostbyname], [nsl])
 AC_SEARCH_LIBS([socket], [socket], ,
    [AC_CHECK_LIB([nsl], [socket], [LIBS="-lnsl -lsocket $LIBS"], ,
        [-lsocket])])
 AC_CHECK_LIB([afsauthent], [lsetpag],
    [LIBS="-lafsauthent -lafsrpc $LIBS"
     AC_DEFINE([HAVE_LSETPAG], [1],
        [Define to 1 if you have the OpenAFS lsetpag function.])],
    [AC_CHECK_LIB([sys], [lsetpag],
        [LIBS="-lsys $LIBS"
         AC_DEFINE([HAVE_LSETPAG], [1],
            [Define to 1 if you have the OpenAFS lsetpag function.])])],
    [-lafsrpc])
 KAFS_LIBS="$LIBS"
 RRA_LIB_KAFS_RESTORE
 AC_CHECK_HEADERS([afs/afssyscalls.h])])
        
dnl The public entry point.  Sets up the --with options.
AC_DEFUN([RRA_LIB_KAFS],
[AC_REQUIRE([AC_CANONICAL_HOST])
 AC_REQUIRE([AC_TYPE_SIGNAL])
 libkafs=true
 KAFS_CPPFLAGS=
 KAFS_LDFLAGS=
 KAFS_LIBS=
 AC_SUBST([KAFS_CPPFLAGS])
 AC_SUBST([KAFS_LDFLAGS])
 AC_SUBST([KAFS_LIBS])
 AC_ARG_WITH([libkafs],
    AC_HELP_STRING([--without-libkafs],
        [Always use internal AFS syscall code]),
    [AS_IF([test x"$withval" = xno], [libkafs=false])])
 AS_IF([test x"$libkafs" != xfalse],
    [RRA_LIB_KAFS_SWITCH
     AC_CHECK_LIB([kafs], [k_hasafs],
        [KAFS_LIBS="-lkafs"
         AC_CHECK_HEADERS([kafs.h])],
        [AC_CHECK_LIB([kopenafs], [k_hasafs],
            [KAFS_LIBS="-lkopenafs"
             AC_CHECK_HEADERS([kopenafs.h])],
            [libkafs=false])])
     RRA_LIB_KAFS_RESTORE])
 AS_IF([test x"$libkafs" = xtrue],
    [AC_DEFINE([HAVE_K_HASAFS], 1,
        [Define to 1 if you have the k_hasafs function.])],
    [case "$host" in
     *-linux*)
        AC_LIBOBJ([kafs-api])
        AC_LIBOBJ([kafs-linux])
        AC_CHECK_HEADERS([sys/ioccom.h])
        AC_DEFINE([HAVE_LINUX_AFS], [1],
            [Define to 1 to use the Linux AFS /proc interface.])
        ;;
     *-aix*|*-irix*)
        _RRA_LIB_KAFS_LSETPAG
        ;;
     *)
        _RRA_LIB_KAFS_WITH
        RRA_LIB_KAFS_SWITCH
        AC_CHECK_HEADERS([afs/param.h sys/ioccom.h],
            [AC_LIBOBJ([kafs-api])
             AC_LIBOBJ([kafs-syscall])])
        RRA_LIB_KAFS_RESTORE
        AC_DEFINE([_REENTRANT], [1],
            [Define to 1 on Solaris for correct errno handling with threads.])
        ;;
     esac])])
