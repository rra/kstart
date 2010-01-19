/*
 * Test suite for kafs library.
 *
 * This is the backend program run by the kafs-t driver script.  It first
 * checks whether k_hasafs returns true.  If it doesn't, it exits with status
 * 2, indicating that all tests should be skipped.  Otherwise, it runs
 * k_setpag, then tokens, then aklog, then tokens, and then k_unlog, sending
 * the output to standard output and errors to standard error.  If either
 * k_setpag or k_unlog return failure, it reports an error to standard error
 * and exits with status 1.  If aklog fails, it exits with status 3.  If the
 * commands all finish, it exits 0.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2009 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <kafs/kafs.h>
#include <util/messages.h>

int
main(void)
{
    if (!k_hasafs())
        exit(2);
    if (k_setpag() != 0)
        sysdie("k_setpag failed");
    printf("=== tokens (setpag) ===\n");
    fflush(stdout);
    system("tokens");
    if (system("aklog") != 0)
        exit(3);
    printf("=== tokens (aklog) ===\n");
    fflush(stdout);
    system("tokens");
    if (k_unlog() != 0)
        sysdie("k_unlog failed");
    printf("=== tokens (unlog) ===\n");
    fflush(stdout);
    system("tokens");

    return 0;
}
