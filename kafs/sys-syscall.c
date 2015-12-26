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
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
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
