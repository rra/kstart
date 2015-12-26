/*
 * AFS system call for Solaris 11 and later.
 *
 * This is an AFS system call implementation for Solaris 11 and later
 * (versions of Solaris where OpenAFS has switched from a system call to an
 * ioctl).  It is for use on systems that don't have libkafs or libkopenafs,
 * or where a dependency on those libraries is not desirable for some reason.
 *
 * This file is included by kafs/kafs.c on Solaris 11 platforms and therefore
 * doesn't need its own copy of standard includes, only whatever additional
 * data is needed for the Linux interface.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2009, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * The struct passed to ioctl to do an AFS system call.  Definition taken from
 * the afs/afs_args.h OpenAFS header.  We choose one of two structs depending
 * on whether we have a 32-bit or 64-bit interface.
 */
struct afssysargs {
    uint32_t param6;
    uint32_t param5;
    uint32_t param4;
    uint32_t param3;
    uint32_t param2;
    uint32_t param1;
    uint32_t syscall;
};
struct afssysargs64 {
    uint64_t param6;
    uint64_t param5;
    uint64_t param4;
    uint64_t param3;
    uint64_t param2;
    uint64_t param1;
    uint32_t syscall;
};


/*
 * The workhorse function that does the actual system call.  All the values
 * are passed as longs to match the internal OpenAFS interface, which means
 * that there's all sorts of ugly type conversion happening here.
 *
 * Returns -1 and sets errno to ENOSYS if attempting a system call fails and 0
 * otherwise.  If the system call was made, its return status will be stored
 * in rval.
 */
static int
k_syscall(long call, long param1, long param2, long param3, long param4,
          int *rval)
{
    int fd, code, oerrno, callnum;

#ifdef _ILP32
    struct afssysargs syscall_data;

    syscall_data.syscall = call;
    syscall_data.param1 = param1;
    syscall_data.param2 = param2;
    syscall_data.param3 = param3;
    syscall_data.param4 = param4;
    syscall_data.param5 = 0;
    syscall_data.param6 = 0;
    callnum = _IOW('C', 2, struct afssysargs);
#else
    struct afssysargs64 syscall_data;

    syscall_data.syscall = call;
    syscall_data.param1 = param1;
    syscall_data.param2 = param2;
    syscall_data.param3 = param3;
    syscall_data.param4 = param4;
    syscall_data.param5 = 0;
    syscall_data.param6 = 0;
    callnum = _IOW('C', 1, struct afssysargs64);
#endif

    fd = open("/dev/afs", O_RDWR);
    if (fd < 0) {
        errno = ENOSYS;
        return -1;
    }
    *rval = ioctl(fd, callnum, &syscall_data);

    oerrno = errno;
    close(fd);
    errno = oerrno;
    return 0;
}
