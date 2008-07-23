/*
 * Set owner and mode of ticket files.
 *
 * Holds common code to set the owner and mode of ticket cache files, used by
 * both k4start and k5start.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2008 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include <util/util.h>


/*
 * Convert from a string to a number, checking errors, and return -1 on any
 * error or for any negative number.
 */
static long
convert_number(const char *string, int base)
{
    long number;
    char *end;

    errno = 0;
    number = strtol(string, &end, base);
    if (errno != 0 || *end != '\0')
        return -1;
    return number;
}


/*
 * Given the path to a ticket cache, an owner, a group, and a mode, set the
 * owner, group, and mode of that file accordingly.  Owner and group may be
 * either the name of a user or group or a numeric UID or GID (as a string).
 * Mode should be the octal mode (as a string).  If the owner is specified as
 * a username (but not if it is specified as a UID), set the GID, if
 * unspecified, to the primary group of that user.
 *
 * Dies on failure.
 */
void
file_permissions(const char *file, const char *owner, const char *group,
                 const char *mode_string)
{
    struct passwd *pw;
    struct group *gr;
    uid_t uid = -1;
    gid_t gid = -1;
    mode_t mode;

    /* Support Kerberos ticket cache names as file names. */
    if (strncmp(file, "FILE:", strlen("FILE:")) == 0)
        file += strlen("FILE:");
    if (strncmp(file, "WRFILE:", strlen("WRFILE:")) == 0)
        file += strlen("WRFILE:");

    /* Change ownership. */
    if (group != NULL) {
        gid = convert_number(group, 10);
        if (gid == (gid_t) -1) {
            gr = getgrnam(group);
            if (gr == NULL)
                die("unknown group %s", group);
            gid = gr->gr_gid;
        }
    }
    if (owner != NULL) {
        uid = convert_number(owner, 10);
        if (uid == (uid_t) -1) {
            pw = getpwnam(owner);
            if (pw == NULL)
                die("unknown user %s", owner);
            uid = pw->pw_uid;
            if (gid == (gid_t) -1)
                gid = pw->pw_gid;
        }
    }
    if (uid != (uid_t) -1 || gid != (gid_t) -1)
        if (chown(file, uid, gid) < 0)
            sysdie("cannot chown %s to %ld:%ld", file, (long) uid, (long) gid);

    /* Change permissions. */
    if (mode_string != NULL) {
        mode = convert_number(mode_string, 8);
        if (mode == (mode_t) -1)
            die("invalid mode %s", mode_string);
        if (chmod(file, mode) < 0)
            sysdie("cannot chmod %s to %s", file, mode_string);
    }
}
