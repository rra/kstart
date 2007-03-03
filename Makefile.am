# Makefile.am -- Automake makefile for kstart.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
#    Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = autogen k4start.1 k4start.pod k5start.1 k5start.pod krenew.1 \
	krenew.pod kstart.spec

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
AFSLIBS      = @AFSLIBS@
KRB4LIBS     = @KRB4LIBS@
KRB5LIBS     = @KRB5LIBS@
K4START_LIBS = $(AFSLIBS) $(KRB4LIBS)
if USES_COM_ERR
    K5START_LIBS = $(KRB5LIBS) $(AFSLIBS)
else
    K5START_LIBS = $(AFSLIBS) $(KRB5LIBS)
endif

EXTRA_PROGRAMS = k4start
bin_PROGRAMS = @K4START@ k5start krenew
k4start_SOURCES = k4start.c command.c portable/krb4.h
k4start_LDADD = portable/libportable.a $(K4START_LIBS)
k5start_SOURCES = k5start.c command.c
k5start_LDADD = portable/libportable.a $(K5START_LIBS)
krenew_SOURCES = krenew.c command.c
krenew_LDADD = portable/libportable.a $(K5START_LIBS)

noinst_LIBRARIES = portable/libportable.a
portable_libportable_a_SOURCES = portable/kafs.h portable/krb5.h \
	portable/time.h system.h
portable_libportable_a_LIBADD = $(LIBOBJS)

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

# We shouldn't have to explicitly list $(LIBOBJS) and $(LTLIBOBJS) here.
# This is a bug in the non-recursive support.
MOSTLYCLEANFILES = $(LIBOBJS) $(LTLIBOBJS)
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure k4start.1 k5start.1 krenew.1

# More bugs in the non-recursive support.
distclean-local:
	-rm -rf .deps

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
