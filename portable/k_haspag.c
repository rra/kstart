/*
 * Replacement for missing k_haspag kafs function.
 *
 * k_haspag is a relatively new addition to the kafs interface (implemented by
 * Heimdal's libkafs and OpenAFS's libkopenafs).  It returns true if the
 * current process is in a PAG and false otherwise.  This is a replacement
 * function for libraries that don't have it or for use with a replacement
 * kafs layer.  It falls back on looking at the current process's supplemental
 * groups if the system call isn't supported or if k_pioctl isn't available.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <https://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2020-2021 Russ Allbery <eagle@eyrie.org>
 * Copyright 2010-2011, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Copying and distribution of this file, with or without modification, are
 * permitted in any medium without royalty provided the copyright notice and
 * this notice are preserved.  This file is offered as-is, without any
 * warranty.
 *
 * SPDX-License-Identifier: FSFAP
 */

#include <config.h>
#include <portable/kafs.h>
#include <portable/system.h>

#ifdef HAVE_SYS_IOCCOM_H
#    include <sys/ioccom.h>
#endif
#include <sys/ioctl.h>


/*
 * The haspag function.  Returns true if the current process is in a PAG,
 * false otherwise.  This attempts a system call, and if that fails, falls
 * back on looking for supplemental groups that match the AFS groups.
 */
int
k_haspag(void)
{
    int ngroups, i;
    gid_t *groups;
    uint32_t pag, g0, g1, hi, lo;

    /* First, try the system call if k_pioctl is available. */
#ifdef HAVE_K_PIOCTL
    int result;
    struct ViceIoctl iob;

    pag = (uint32_t) -1;
    iob.in = NULL;
    iob.in_size = 0;
    iob.out = (void *) &pag;
    iob.out_size = sizeof(pag);
    result = k_pioctl(NULL, _IOW('C', 13, struct ViceIoctl), &iob, 0);
    if (result == 0)
        return pag != (uint32_t) -1;
#endif

    /*
     * If that failed, the cache manager may not support the VIOC_GETPAG
     * system call.  Fall back on analyzing the groups.
     */
    ngroups = getgroups(0, NULL);
    if (ngroups < 1)
        return 0;
    groups = calloc(ngroups, sizeof(*groups));
    if (groups == NULL)
        return 0;
    ngroups = getgroups(ngroups, groups);
    if (ngroups < 1) {
        free(groups);
        return 0;
    }

    /*
     * Strictly speaking, the single group PAG is only used on Linux, but
     * check it everywhere anyway to simplify life.
     */
    for (i = 0; i < ngroups; i++)
        if (((groups[i] >> 24) & 0xff) == 'A') {
            free(groups);
            return 1;
        }

    /*
     * Check for the PAG group pair.  The first two groups, when combined with
     * a rather strange formula, must result in a number matching the single
     * group number we already checked for.
     */
    if (ngroups < 2) {
        free(groups);
        return 0;
    }
    g0 = (groups[0] & 0xffff) - 0x3f00;
    g1 = (groups[1] & 0xffff) - 0x3f00;
    free(groups);
    if (g0 < 0xc0000 && g1 < 0xc0000) {
        lo = ((g0 & 0x3fff) << 14) | (g1 & 0x3fff);
        hi = (g1 >> 14) + (g0 >> 14) * 3;
        pag = ((hi << 28) | lo);
        return ((pag >> 24) & 0xff) == 'A';
    }
    return 0;
}
