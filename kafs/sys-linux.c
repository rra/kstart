/*
 * AFS system call for Linux systems.
 *
 * This is an AFS system call implementation for Linux systems only (and new
 * enough implementations of OpenAFS on Linux that /proc/fs/openafs/afs_ioctl
 * exists).  It is for use on systems that don't have libkafs or libkopenafs,
 * or where a dependency on those libraries is not desirable for some reason.
 *
 * This file is included by kafs/kafs.c on Linux platforms and therefore
 * doesn't need its own copy of standard includes, only whatever additional
 * data is needed for the Linux interface.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

/* 
 * The struct passed to ioctl to do an AFS system call.  Definition taken from
 * the afs/afs_args.h OpenAFS header.
 */
struct afsprocdata {
    long param4;
    long param3;
    long param2;
    long param1;
    long syscall;
};


/*
 * The workhorse function that does the actual system call.  All the values
 * are passed as longs to match the internal OpenAFS interface, which means
 * that there's all sorts of ugly type conversion happening here.
 *
 * The first path we attempt is the OpenAFS path; the second is the one used
 * by Arla (at least some versions).
 *
 * Returns -1 and sets errno to ENOSYS if attempting a system call fails and 0
 * otherwise.  If the system call was made, its return status will be stored
 * in rval.
 */
static int
k_syscall(long call, long param1, long param2, long param3, long param4,
          int *rval)
{
    struct afsprocdata syscall_data;
    int fd, oerrno;

    fd = open("/proc/fs/openafs/afs_ioctl", O_RDWR);
    if (fd < 0)
        fd = open("/proc/fs/nnpfs/afs_ioctl", O_RDWR);
    if (fd < 0) {
        errno = ENOSYS;
        return -1;
    }

    syscall_data.syscall = call;
    syscall_data.param1 = param1;
    syscall_data.param2 = param2;
    syscall_data.param3 = param3;
    syscall_data.param4 = param4;
    *rval = ioctl(fd, _IOW('C', 1, void *), &syscall_data);

    oerrno = errno;
    close(fd);
    errno = oerrno;
    return 0;
}
