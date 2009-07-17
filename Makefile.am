# Makefile.am -- Automake makefile for kstart.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008
#    Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

# Test suite files that are not generated or touched by configure that need to
# be copied over for builddir != srcdir builds.
TEST_FILES = tests/TESTS tests/data/README tests/data/command \
	tests/data/fake-aklog tests/libtest.pl tests/util/xmalloc-t

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE autogen k4start.1 k4start.pod k5start.1 k5start.pod \
	krenew.1 krenew.pod kstart.spec $(TEST_FILES)

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

# We potentially need these for everything and there's no other way to
# set AM_CPPFLAGS for use with LIBOBJS.
AM_CPPFLAGS = $(KRB4_CPPFLAGS) $(KRB5_CPPFLAGS) $(KAFS_CPPFLAGS)

EXTRA_PROGRAMS = k4start
bin_PROGRAMS = @K4START@ k5start krenew
k4start_SOURCES = k4start.c portable/krb4.h
k4start_LDFLAGS = $(KRB4_LDFLAGS) $(KAFS_LDFLAGS)
k4start_LDADD = util/libutil.a portable/libportable.a $(K4START_LIBS)
k5start_LDFLAGS = $(KRB5_LDFLAGS) $(KAFS_LDFLAGS)
k5start_LDADD = util/libutil.a portable/libportable.a $(K5START_LIBS)
krenew_LDFLAGS = $(KRB5_LDFLAGS) $(KAFS_LDFLAGS)
krenew_LDADD = util/libutil.a portable/libportable.a $(K5START_LIBS)

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/kafs.h \
	portable/macros.h portable/stdbool.h portable/system.h portable/time.h
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/command.c util/concat.c util/messages.c \
	util/messages-krb5.c util/perms.c util/util.h util/xmalloc.c

man_MANS = @K4START_MAN@ k5start.1 krenew.1

$(srcdir)/k4start.1: $(srcdir)/k4start.pod
	pod2man --release=$(VERSION) --center="User commands" \
	    $(srcdir)/k4start.pod > $@

$(srcdir)/k5start.1: $(srcdir)/k5start.pod
	pod2man --release=$(VERSION) --center="User commands" \
	    $(srcdir)/k5start.pod > $@

$(srcdir)/krenew.1: $(srcdir)/krenew.pod
	pod2man --release=$(VERSION) --center="User commands" \
	    $(srcdir)/krenew.pod > $@

DISTCLEANFILES = tests/data/.placeholder
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile \
	build-aux/config.guess build-aux/config.sub build-aux/depcomp \
	build-aux/install-sh build-aux/missing config.h.in config.h.in~ \
	configure k4start.1 k5start.1 krenew.1

# Remove the files that we copy over if and only if builddir != srcdir.
distclean-local:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    rm -f $(TEST_FILES) ; \
	fi

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/portable/asprintf-t		\
	tests/portable/daemon-t tests/portable/mkstemp-t		\
	tests/portable/setenv-t tests/portable/snprintf-t		\
	tests/portable/strlcat-t tests/portable/strlcpy-t		\
	tests/util/concat-t tests/util/messages-t tests/util/xmalloc
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h

# All of the test programs.
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
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    for f in $(TEST_FILES) ; do \
		cp "$(srcdir)/$$f" "$(builddir)/$$f" ; \
	    done \
	fi
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
