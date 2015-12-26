/*
 * Portability wrapper around the kafs API.
 *
 * This header includes kafs.h if it's available, prototypes k_hasafs,
 * k_setpag, and k_unlog replacements (generally provided by the kafs
 * replacement library) imlemented in terms of our system call layer or
 * lsetpag if it is available and libkafs isn't, and as a last resort provides
 * a k_hasafs function that always fails and k_setpag and k_unlog functions
 * that always succeed.
 *
 * It also defines the HAVE_KAFS macro to 1 if some AFS support was available,
 * in case programs that use it want to handle the case of no AFS support
 * differently (such as in help output).
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef PORTABLE_KAFS_H
#define PORTABLE_KAFS_H 1

#include <config.h>
#ifdef HAVE_KRB5
# include <portable/krb5.h>
#endif
#include <portable/macros.h>

#include <errno.h>
#ifdef HAVE_SYS_IOCCOM_H
# include <sys/ioccom.h>
#endif
#include <sys/ioctl.h>

BEGIN_DECLS

/* Assume we have some AFS support available and #undef below if not. */
#define HAVE_KAFS 1

/* We have a libkafs or libkopenafs library. */
#if HAVE_K_HASAFS
# if HAVE_KAFS_H
#  include <kafs.h>
# elif HAVE_KOPENAFS_H
#  include <kopenafs.h>
# else
struct ViceIoctl {
    void *in, *out;
    short in_size;
    short out_size;
};
int k_hasafs(void);
int k_pioctl(char *, struct ViceIoctl *, void *, int);
int k_setpag(void);
int k_unlog(void);
# endif
# ifdef HAVE_K_HASPAG
#  if !defined(HAVE_KAFS_H) && !defined(HAVE_KOPENAFS_H)
int k_haspag(void);
#  endif
# else
int k_haspag(void) __attribute__((__visibility__("hidden")));
# endif

/* We're linking directly to the OpenAFS libraries. */
#elif HAVE_LSETPAG
# if HAVE_AFS_AFSSYSCALLS_H
#  include <afs/afssyscalls.h>
# else
int lsetpag(void);
int lpioctl(char *, int, void *, int);
# endif
# define k_hasafs()           (1)
# define k_pioctl(p, c, a, f) lpioctl((p), (c), (a), (f))
# define k_setpag()           lsetpag()
# define k_unlog()            (errno = ENOSYS, -1)

int k_haspag(void) __attribute__((__visibility__("hidden")));

/* We're using our local kafs replacement. */
#elif HAVE_KAFS_REPLACEMENT
# define HAVE_K_PIOCTL 1

struct ViceIoctl {
    void *in, *out;
    short in_size;
    short out_size;
};

/* Default to a hidden visibility for all portability functions. */
#pragma GCC visibility push(hidden)

int k_hasafs(void);
int k_haspag(void);
int k_pioctl(char *, int, struct ViceIoctl *, int);
int k_setpag(void);
int k_unlog(void);

/* Undo default visibility change. */
#pragma GCC visibility pop

/* We have no kafs implementation available. */
#else
# undef HAVE_KAFS
# define k_hasafs()           (0)
# define k_haspag()           (0)
# define k_pioctl(p, c, a, f) (errno = ENOSYS, -1)
# define k_setpag()           (errno = ENOSYS, -1)
# define k_unlog()            (errno = ENOSYS, -1)
#endif

END_DECLS

#endif /* PORTABLE_KAFS_H */
