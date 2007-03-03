/*  $Id$
**
**  Portability wrapper around the kafs API.
**
**  This header includes kafs.h if it's available, provides k_hasafs and
**  k_setpag replacements imlemented in terms of lsetpag if it is available
**  and libkafs isn't, and as a last resort provides a k_hasafs function that
**  always fails and a k_setpag function that always succeeds.
*/

#ifndef PORTABLE_KAFS_H
#define PORTABLE_KAFS_H 1

#if HAVE_K_SETPAG
# if HAVE_KAFS_H
#  include <kafs.h>
# endif
#elif HAVE_LSETPAG
int lsetpag(void);
# define k_hasafs() (1)
# define k_setpag() lsetpag()
#else
# define k_hasafs() (1)
# define k_setpag() (0)
#endif

#endif /* PORTABLE_KAFS_H */
