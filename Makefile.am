# Makefile.am -- Automake makefile for kstart.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
#    Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen examples/krenew-agent k4start.1	\
	k4start.pod k5start.pod krenew.pod kstart.spec tests/TESTS	\
	tests/data/README tests/data/command tests/data/fake-aklog	\
	tests/docs/pod-spelling-t tests/docs/pod-t tests/k4start/afs-t	\
	tests/k4start/basic-t tests/k5start/afs-t tests/k5start/basic-t	\
	tests/k5start/daemon-t tests/k5start/flags-t tests/kafs/basic-t	\
	tests/krenew/afs-t tests/krenew/basic-t tests/krenew/daemon-t	\
	tests/libtest.pl tests/tap/libtap.sh tests/util/xmalloc-t

# The following library order matters for annoying reasons.  libafsauthent
# contains its own com_err implementation, which we do not want to pick up.
#
# With krb4, we have to link with the AFS libraries first, since otherwise
# in the --enable-reduced-depends case the linker may try to resolve the
# com_err symbols in libkrb4 from the AFS libraries.
#
# With krb5, if k5start calls com_err functions directly, configure adds
# -lcom_err to the link line explicitly.  In that case, we want to link with
# the AFS libraries last, after -lcom_err, so that we don't use its com_err
# implementation.  If k5start doesn't call com_err functions, we want to do
# the same thing we do with krb4 for the --enable-reduced-depends case.
K4START_LIBS = $(KAFS_LIBS) $(KRB4_LIBS)
if KRB5_USES_COM_ERR
    K5START_LIBS = $(KRB5_LIBS) $(KAFS_LIBS)
else
    K5START_LIBS = $(KAFS_LIBS) $(KRB5_LIBS)
endif

# We potentially need these for everything due to the libkafs library.
AM_CPPFLAGS = $(KRB4_CPPFLAGS) $(KRB5_CPPFLAGS) $(KAFS_CPPFLAGS)

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/krb5.h	\
	portable/krb5-extra.c portable/macros.h portable/stdbool.h	\
	portable/system.h
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/command.c util/command.h util/concat.c	    \
	util/concat.h util/macros.h util/messages.c util/messages.h	    \
	util/messages-krb5.c util/messages-krb5.h util/perms.c util/perms.h \
	util/xmalloc.c util/xmalloc.h

# Conditionally build the replacement kafs library and add it to the
# libraries used by the other programs.
if NEED_KAFS
    noinst_LIBRARIES += kafs/libkafs.a
    EXTRA_kafs_libkafs_a_SOURCES = kafs/sys-linux.c kafs/sys-syscall.c
    kafs_libkafs_a_SOURCES = kafs/kafs.c kafs/kafs.h
    kafs_libkafs_a_CPPFLAGS = $(KAFS_CPPFLAGS)
    LIBKAFS = kafs/libkafs.a
endif

bin_PROGRAMS = k5start krenew
k5start_LDFLAGS = $(KRB5_LDFLAGS) $(KAFS_LDFLAGS)
k5start_LDADD = $(LIBKAFS) util/libutil.a portable/libportable.a \
	$(K5START_LIBS)
krenew_LDFLAGS = $(KRB5_LDFLAGS) $(KAFS_LDFLAGS)
krenew_LDADD = $(LIBKAFS) util/libutil.a portable/libportable.a \
	$(K5START_LIBS)
dist_man_MANS = k5start.1 krenew.1

# Conditionally add k4start to the build.
if K4START
    bin_PROGRAMS += k4start
    k4start_SOURCES = k4start.c portable/krb4.h
    k4start_LDFLAGS = $(KRB4_LDFLAGS) $(KAFS_LDFLAGS)
    k4start_LDADD = $(LIBKAFS) util/libutil.a portable/libportable.a \
	$(K4START_LIBS)
    dist_man_MANS += k4start.1
endif

DISTCLEANFILES = tests/data/.placeholder
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile \
	build-aux/config.guess build-aux/config.sub build-aux/depcomp \
	build-aux/install-sh build-aux/missing config.h.in config.h.in~ \
	configure k4start.1 k5start.1 krenew.1

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/kafs/basic tests/portable/asprintf-t \
	tests/portable/daemon-t tests/portable/mkstemp-t		   \
	tests/portable/setenv-t tests/portable/snprintf-t		   \
	tests/portable/strlcat-t tests/portable/strlcpy-t		   \
	tests/util/concat-t tests/util/messages-t tests/util/xmalloc
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h

# kafs tests are buit differently depending on whether we use our local
# libkafs replacement.
if NEED_KAFS
    tests_kafs_basic_CPPFLAGS = $(KAFS_CPPFLAGS)
    tests_kafs_basic_LDFLAGS = $(KAFS_LDFLAGS)
    tests_kafs_basic_LDADD = kafs/libkafs.a util/libutil.a \
	portable/libportable.a $(KAFS_LIBS)
else
    tests_kafs_basic_LDADD = util/libutil.a portable/libportable.a \
	$(KAFS_LIBS)
endif

# All of the other test programs.
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_portable_daemon_t_SOURCES = tests/portable/daemon-t.c \
	tests/portable/daemon.c
tests_portable_daemon_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_portable_setenv_t_SOURCES = tests/portable/setenv-t.c \
	tests/portable/setenv.c
tests_portable_setenv_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
	tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
	tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_util_concat_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.a

check-local: $(check_PROGRAMS)
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
