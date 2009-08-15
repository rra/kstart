/*
 * AFS system call via syscall.
 *
 * This is an AFS system call implementation for systems that use syscall,
 * such as Solaris.  It is for use on systems that don't have libkafs or
 * libkopenafs, or where a dependency on those libraries is not desirable for
 * some reason.
 *
 * This file is included by kafs/kafs.c on platforms that use syscall and
 * therefore doesn't need its own copy of standard includes, only whatever
 * additional data is needed for the Linux interface.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifdef HAVE_AFS_PARAM_H
# include <afs/param.h>
#endif
#include <sys/syscall.h>

int
k_syscall(long call, long param1, long param2, long param3, long param4,
          int *rval)
{
    *rval = syscall(AFS_SYSCALL, call, param1, param2, param3, param4);
    return 0;
}
