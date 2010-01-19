/*
 * Portability wrapper around the kafs API.
 *
 * This header includes kafs.h if it's available, provides k_hasafs, k_setpag,
 * and k_unlog replacements imlemented in terms of our system call layer or
 * lsetpag if it is available and libkafs isn't, and as a last resort provides
 * a k_hasafs function that always fails and k_setpag and k_unlog functions
 * that always succeed.
 *
 * It also defines the HAVE_KAFS macro to 1 if some AFS support was available,
 * in case programs that use it want to handle the case of no AFS support
 * differently (such as in help output).
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifndef PORTABLE_KAFS_H
#define PORTABLE_KAFS_H 1

#include <config.h>
#include <portable/macros.h>

#include <errno.h>

BEGIN_DECLS

/* Assume we have some AFS support available and #undef below if not. */
#define HAVE_KAFS 1

#if HAVE_K_HASAFS
# if HAVE_KAFS_H
#  include <kafs.h>
# elif HAVE_KOPENAFS_H
#  include <kopenafs.h>
# endif
#elif HAVE_LSETPAG
# if HAVE_AFS_AFSSYSCALLS_H
#  include <afs/afssyscalls.h>
# else
int lsetpag(void);
# endif
# define k_hasafs() (1)
# define k_setpag() lsetpag()
# define k_unlog()  (errno = ENOSYS, -1)
#elif defined(HAVE_AFS_PARAM_H) || defined(HAVE_KAFS_LINUX)
int k_hasafs(void);
int k_setpag(void);
int k_unlog(void);
#else
# undef HAVE_KAFS
# define k_hasafs() (0)
# define k_setpag() (errno = ENOSYS, -1)
# define k_unlog()  (errno = ENOSYS, -1)
#endif

END_DECLS

#endif /* PORTABLE_KAFS_H */
