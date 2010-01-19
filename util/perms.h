/*
 * Prototypes to set owner and mode of ticket files.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2008, 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifndef UTIL_PERMS_H
#define UTIL_PERMS_H 1

#include <config.h>
#include <portable/macros.h>

BEGIN_DECLS

/* Default to a hidden visibility for all util functions. */
#pragma GCC visibility push(hidden)

/*
 * Set permissions on a file.  owner and group may be NULL, names, or numeric
 * IDs as strings.  Mode should be NULL or the octal mode as a string.  If the
 * owner is a username and the group is NULL, sets the group to the primary
 * group of that user.  Dies on failure.
 */
void file_permissions(const char *file, const char *owner, const char *group,
                      const char *mode)
    __attribute__((__nonnull__(1)));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* UTIL_PERMS_H */
