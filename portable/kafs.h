/*
 * Portability wrapper around the kafs API.
 *
 * This header includes kafs.h if it's available, provides k_hasafs, k_setpag,
 * and k_unlog replacements imlemented in terms of our system call layer or
 * lsetpag if it is available and libkafs isn't, and as a last resort provides
 * a k_hasafs function that always fails and k_setpag and k_unlog functions
 * that always succeed.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008
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
#elif defined(HAVE_AFS_PARAM_H) || defined(HAVE_LINUX_AFS)
int k_hasafs(void);
int k_setpag(void);
int k_unlog(void);
#else
# define k_hasafs() (0)
# define k_setpag() (errno = ENOSYS, -1)
# define k_unlog()  (errno = ENOSYS, -1)
#endif

END_DECLS

#endif /* PORTABLE_KAFS_H */
