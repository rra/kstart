dnl Find the compiler and linker flags for libkeyutils.
dnl
dnl Finds the compiler and linker flags for linking with the libkeyutils
dnl library.  Provides the --with-libkeyutils, --with-libkeyutils-lib, and
dnl --with-libkeyutils-include configure options to specify non-standard paths
dnl to the libkeyutils libraries or header files.
dnl
dnl Provides the macros RRA_LIB_KEYUTILS and RRA_LIB_KEYUTILS_OPTIONAL and
dnl sets the substitution variables LIBKEYUTILS_CPPFLAGS, LIBKEYUTILS_LDFLAGS,
dnl and LIBKEYUTILS_LIBS.  Also provides RRA_LIB_KEYUTILS_SWITCH to set
dnl CPPFLAGS, LDFLAGS, and LIBS to include the libkeyutils libraries, saving
dnl the current values first, and RRA_LIB_KEYUTILS_RESTORE to restore those
dnl settings to before the last RRA_LIB_KEYUTILS_SWITCH.  Defines
dnl HAVE_LIBKEYUTILS if libkeyutils is found.  If it isn't found, the
dnl substitution variables will be empty.
dnl
dnl Depends on the lib-helper.m4 framework.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <https://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Copyright 2021 Russ Allbery <eagle@eyrie.org>
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.
dnl
dnl SPDX-License-Identifier: FSFULLR

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the libevent flags.  Used as a wrapper, with
dnl RRA_LIB_LIBEVENT_RESTORE, around tests.
AC_DEFUN([RRA_LIB_KEYUTILS_SWITCH], [RRA_LIB_HELPER_SWITCH([LIBKEYUTILS])])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values before
dnl RRA_LIB_LIBEVENT_SWITCH was called.
AC_DEFUN([RRA_LIB_KEYUTILS_RESTORE], [RRA_LIB_HELPER_RESTORE([LIBKEYUTILS])])

dnl Checks if libkeyutils is present.  The single argument, if "true", says to
dnl fail if the libkeyutils library could not be found.  Prefer probing with
dnl pkg-config if available and the --with flags were not given.
AC_DEFUN([_RRA_LIB_KEYUTILS_INTERNAL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 RRA_LIB_HELPER_PATHS([LIBKEYUTILS])
 AS_IF([test x"$LIBKEYUTILS_CPPFLAGS" = x && test x"$LIBKEYUTILS_LDFLAGS" = x],
    [PKG_CHECK_EXISTS([libkeyutils],
        [PKG_CHECK_MODULES([LIBKEYUTILS], [libkeyutils])
         LIBKEYUTILS_CPPFLAGS="$LIBKEYUTILS_CFLAGS"])])
 AS_IF([test x"$LIBKEYUTILS_LIBS" = x],
    [RRA_LIB_KEYUTILS_SWITCH
     LIBS=
     AC_SEARCH_LIBS([keyctl_join_session_keyring], [keyutils],
        [LIBKEYUTILS_LIBS="$LIBS"],
        [AS_IF([test x"$1" = xtrue],
            [AC_MSG_ERROR([cannot find usable libkeyutils library])])])
     RRA_LIB_KEYUTILS_RESTORE])])

dnl The main macro for packages with mandatory libkeyutils support.
AC_DEFUN([RRA_LIB_KEYUTILS],
[RRA_LIB_HELPER_VAR_INIT([LIBKEYUTILS])
 RRA_LIB_HELPER_WITH([libkeyutils], [libkeyutils], [LIBKEYUTILS])
 _RRA_LIB_KEYUTILS_INTERNAL([true])
 rra_use_LIBKEYUTILS=true
 AC_DEFINE([HAVE_LIBKEYUTILS], 1, [Define if libkeyutils is available.])])

dnl The main macro for packages with optional libkeyutils support.
AC_DEFUN([RRA_LIB_KEYUTILS_OPTIONAL],
[RRA_LIB_HELPER_VAR_INIT([LIBKEYUTILS])
 RRA_LIB_HELPER_WITH_OPTIONAL([libkeyutils], [libkeyutils], [LIBKEYUTILS])
 AS_IF([test x"$rra_use_LIBKEYUTILS" != xfalse],
    [AS_IF([test x"$rra_use_LIBKEYUTILS" = xtrue],
        [_RRA_LIB_KEYUTILS_INTERNAL([true])],
        [_RRA_LIB_KEYUTILS_INTERNAL([false])])])
 AS_IF([test x"$LIBKEYUTILS_LIBS" != x],
    [rra_use_LIBKEYUTILS=true
     AC_DEFINE([HAVE_LIBKEYUTILS], 1, [Define if libkeyutils is available.])])])
