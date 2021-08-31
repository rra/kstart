/*
 * AFS system call via syscall.
 *
 * This is an AFS system call implementation for systems that use syscall,
 * such as Solaris prior to Solaris 11.  It is for use on systems that don't
 * have libkafs or libkopenafs, or where a dependency on those libraries is
 * not desirable for some reason.
 *
 * This file is included by kafs/kafs.c on platforms that use syscall and
 * therefore doesn't need its own copy of standard includes, only whatever
 * additional data is needed for the Linux interface.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <https://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2009, 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Copying and distribution of this file, with or without modification, are
 * permitted in any medium without royalty provided the copyright notice and
 * this notice are preserved.  This file is offered as-is, without any
 * warranty.
 *
 * SPDX-License-Identifier: FSFAP
 */

#include <afs/param.h>
#include <sys/syscall.h>

int
k_syscall(long call, long param1, long param2, long param3, long param4,
          int *rval)
{
    *rval = syscall(AFS_SYSCALL, call, param1, param2, param3, param4);
    return 0;
}
