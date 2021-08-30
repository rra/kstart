# kstart

[![Build
status](https://github.com/rra/kstart/workflows/build/badge.svg)](https://github.com/rra/kstart/actions)
[![Debian
package](https://img.shields.io/debian/v/kstart/unstable)](https://tracker.debian.org/pkg/kstart)

Copyright 2015, 2021 Russ Allbery <eagle@eyrie.org>.  Copyright 1995-1997,
1999-2002, 2004-2012, 2014 The Board of Trustees of the Leland Stanford
Junior University.  This software is distributed under a BSD-style
license.  Please see the section [License](#license) below for more
information.

## Blurb

k5start and krenew are modified versions of kinit which add support for
running as a daemon to maintain a ticket cache, running a command with
credentials from a keytab and maintaining a ticket cache until that
command completes, obtaining AFS tokens (via an external aklog) after
obtaining tickets, and creating an AFS PAG for a command.  They are
primarily useful in conjunction with long-running jobs; for moving ticket
handling code out of servers, cron jobs, or daemons; and to obtain tickets
and AFS tokens with a single command.

## Description

k5start is a modified version of kinit.  It can be used as a substitute
for kinit (with some additional helpful options), but it can also obtain
credentials automatically from a keytab.  It can run as a daemon, waking
up periodically to refresh credentials using that keytab, and can also
check for the validity of tickets and only refresh if they're no longer
valid.

Some of these capabilities have been included in Kerberos's kinit, but the
ability to maintain tickets while running as a daemon has not and is
useful for servers that need to use Kerberos.  Using kstart allows the
ticket handling to be moved out of the server into a separate process
dedicated just to that purpose.

k5start can optionally run an external program whenever the ticket is
refreshed to obtain an AFS token, and therefore can be used in conjunction
with a program like aklog or afslog to maintain an AFS token.  When built
with support for AFS PAGs, it can also put the program in its own PAG so
that its authentication doesn't affect any other programs.

krenew is identical to k5start except that rather than obtaining new
tickets from a password or keytab, it renews an existing renewable ticket
cache.  It can be used to periodically renew tickets and optionally AFS
tokens for long-running processes in cases where using a keytab is
inappropriate (such as users running their own jobs with their own
credentials).

## Requirements

As Kerberos programs, k5start and krenew require Kerberos libraries to
link against.  They have only been thoroughly tested with the MIT Kerberos
and Heimdal libraries on Debian, but should work with the included
Kerberos libraries on many other platforms.

Other than that, all you should need is a suitable C compiler.  Neither
program has been tested on non-Unix systems.

If you want the `-t` option to work, you need a program to obtain AFS
tokens from Kerberos tickets.  You can specify the program to use on your
system with the `--with-aklog` option to configure; if that option is not
given, the first of aklog or afslog that is found on your path at
configure time will be used.

For AFS PAG support, one of Linux, Mac OS X, Solaris 11, the kafs library
that comes with either Heimdal or KTH Kerberos, the kopenafs library that
comes with newer OpenAFS, AFS header files (on any other platform besides
AIX or IRIX), or AFS libraries (on AIX and IRIX) is required.  AIX
binaries with AFS PAG support may not run on AIX systems that do not have
an AFS client installed due to how AIX handles system calls.

To bootstrap from a Git checkout, or if you change the Automake files and
need to regenerate Makefile.in, you will need Automake 1.11 or later.  For
bootstrap or if you change configure.ac or any of the m4 files it includes
and need to regenerate configure or config.h.in, you will need Autoconf
2.64 or later.  Perl is also required to generate manual pages from a
fresh Git checkout.

## Building and Installation

You can build and install kstart with the standard commands:

```
    ./configure
    make
    make install
```

If you are building from a Git clone, first run `./bootstrap` in the
source directory to generate the build files.  `make install` will
probably have to be done as root.  Building outside of the source
directory is also supported, if you wish, by creating an empty directory
and then running configure with the correct relative path.

If you are using aklog, afslog, or some other program to obtain AFS
tokens, give its path to configure with the `--with-aklog` option, as in:

```
    ./configure --with-aklog=/usr/local/bin/aklog
```

This program will be run when the `-t` option is given to k5start or
krenew.

To enable support for AFS PAGs, pass the `--enable-setpag` flag to
configure.  It is not enabled by default.  On platforms other than Linux
and without the kafs library, you will need to add the `--with-afs` flag
specifying the location of your AFS includes and libraries unless they're
on your standard search path.  For example:

```
    ./configure --enable-setpag --with-afs=/usr/afsws
```

When enabled, k5start and krenew will always create a new PAG before
authentication when running a specific command and when aklog is being
run.

When using the Linux kafs module, the correct way to isolate kafs
credentials is to create a new session keyring rather than a new PAG.
This requires the libkeyutils library.  `configure` will attempt to
discover that library automatically and link with it by default.  Pass the
`--with-libkeyutils`, `--with-libkeyutils-include`, or
`--with-libkeyutils-lib` options to `configure` to specify a different
path to that library, or set the `LIBKEYUTILS_*` environment variables.

Normally, configure will use `krb5-config` to determine the flags to use
to compile with your Kerberos libraries.  To specify a particular
`krb5-config` script to use, either set the `PATH_KRB5_CONFIG` environment
variable or pass it to configure like:

```
    ./configure PATH_KRB5_CONFIG=/path/to/krb5-config
```

If `krb5-config` isn't found, configure will look for the standard
Kerberos libraries in locations already searched by your compiler.  If the
the `krb5-config` script first in your path is not the one corresponding
to the Kerberos libraries you want to use, or if your Kerberos libraries
and includes aren't in a location searched by default by your compiler,
you need to specify a different Kerberos installation root via
`--with-krb5=PATH`.  For example:

```
    ./configure --with-krb5=/usr/pubsw
```

You can also individually set the paths to the include directory and the
library directory with `--with-krb5-include` and `--with-krb5-lib`.  You
may need to do this if Autoconf can't figure out whether to use `lib`,
`lib32`, or `lib64` on your platform.

To not use `krb5-config` and force library probing even if there is a
`krb5-config` script on your path, set `PATH_KRB5_CONFIG` to a nonexistent
path:

```
    ./configure PATH_KRB5_CONFIG=/nonexistent
```

`krb5-config` is not used and library probing is always done if either
`--with-krb5-include` or `--with-krb5-lib` are given.

Pass `--enable-silent-rules` to configure for a quieter build (similar to
the Linux kernel).  Use `make warnings` instead of `make` to build with
full GCC compiler warnings (requires either GCC or Clang and may require a
relatively current version of the compiler).

You can pass the `--enable-reduced-depends` flag to configure to try to
minimize the shared library dependencies encoded in the binaries.  This
omits from the link line all the libraries included solely because other
libraries depend on them and instead links the programs only against
libraries whose APIs are called directly.  This will only work with shared
libraries and will only work on platforms where shared libraries properly
encode their own dependencies (this includes most modern platforms such as
all Linux).  It is intended primarily for building packages for Linux
distributions to avoid encoding unnecessary shared library dependencies
that make shared library migrations more difficult.  If none of the above
made any sense to you, don't bother with this flag.

## Testing

In order to test the client in a meaningful way, you will need to do some
preparatory work before running the test suite.  Follow the instructions
in `tests/data/README` first.  Then, you can run the test suite with:

```
    make check
```

If a test fails, you can run a single test with verbose output via:

```
    tests/runtests -o <name-of-test>
```

Do this instead of running the test program directly since it will ensure
that necessary environment variables are set up.

Perl 5.008 or later and the kinit and klist programs from MIT Kerberos,
not Heimdal, are required to run the test suite.  The following additional
Perl modules will be used by the test suite if present:

* Test::Pod
* Test::Spelling

To enable tests that don't detect functionality problems but are used to
sanity-check the release, set the environment variable `RELEASE_TESTING`
to a true value.  To enable tests that may be sensitive to the local
environment or that produce a lot of false positives without uncovering
many problems, set the environment variable `AUTHOR_TESTING` to a true
value.

## Thanks

To Navid Golpayegani, for contributing the initial implementation of the
`-b` option to background after the initial authentication and the `-p`
option to save the PID in a file.

To Buck Huppmann, for contributing an RPM spec file and suggesting krenew.

To Adam Megacz, for pointing out that checking the executability of the
aklog program isn't necessary and for contributing the code to propagate
signals to a child process.

To Quanah Gibson-Mount, for pointing out various build system issues and
missing documentation.

To Sidney Cammeresi, for catching a missing include in krenew and for
providing information and suggestions about Mac OS X's default ticket
cache and its effects on the `-b` option of k5start and krenew.

To Thomas Kula, for pointing out that `k_hasafs` has to be called before
`k_setpag` when using the kafs functions.

To Thomas Weiss, for noticing that code restructuring caused the argument
to `-H` to be ignored in k5start and that `-H` and `-K` should be
diagnosed as mutually exclusive.

To Howard Wilkinson, for the initial version of the `-o`, `-g`, and `-m`
support and further debugging of it.

To Sascha Tandel, for the initial version of `-c` support and reports of
build problems when the AFS libauthent and libafsrpc libraries didn't
work.

To Gautam Iyer, for the initial version of `-H` support in krenew.

To Mike Horansky, for the idea of copying the current ticket cache when
running krenew with a command, thereby saving the ticket cache from
destruction when the user logs out.

## Support

The [kstart web page](https://www.eyrie.org/~eagle/software/kstart/) will
always have the current version of this package, the current
documentation, and pointers to any additional resources.

For bug tracking, use the [issue tracker on
GitHub](https://github.com/rra/kstart/issues).  However, please be aware
that I tend to be extremely busy and work projects often take priority.
I'll save your report and get to it as soon as I can, but it may take me a
couple of months.

## Source Repository

kstart is maintained using Git.  You can access the current source on
[GitHub](https://github.com/rra/kstart) or by cloning the repository at:

https://git.eyrie.org/git/kerberos/kstart.git

or [view the repository on the
web](https://git.eyrie.org/?p=kerberos/kstart.git).

The eyrie.org repository is the canonical one, maintained by the author,
but using GitHub is probably more convenient for most purposes.  Pull
requests are gratefully reviewed and normally accepted.

## License

The kstart package as a whole is covered by the following copyright
statement and license:

> Copyright 2015, 2021
>     Russ Allbery <eagle@eyrie.org>
>
> Copyright 1995-1997, 1999-2002, 2004-2012, 2014
>     The Board of Trustees of the Leland Stanford Junior University
>
> Permission is hereby granted, free of charge, to any person obtaining a
> copy of this software and associated documentation files (the "Software"),
> to deal in the Software without restriction, including without limitation
> the rights to use, copy, modify, merge, publish, distribute, sublicense,
> and/or sell copies of the Software, and to permit persons to whom the
> Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
> THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
> FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
> DEALINGS IN THE SOFTWARE.

Some files in this distribution are individually released under different
licenses, all of which are compatible with the above general package
license but which may require preservation of additional notices.  All
required notices, and detailed information about the licensing of each
file, are recorded in the LICENSE file.

Files covered by a license with an assigned SPDX License Identifier
include SPDX-License-Identifier tags to enable automated processing of
license information.  See https://spdx.org/licenses/ for more information.

For any copyright range specified by files in this package as YYYY-ZZZZ,
the range specifies every single year in that closed interval.
