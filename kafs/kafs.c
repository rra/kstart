/*
 * kafs replacement, main API.
 *
 * This is a simple implementation of the k_hasafs, k_setpag, and k_unlog
 * functions.  It is for use on systems that don't have libkafs or
 * libkopenafs, or where a dependency on those libraries is not desirable for
 * some reason.
 *
 * A more robust implementation of the full kafs interface would have a
 * separate header file with the various system call constants and would
 * support more operations and the k_pioctl interface.  Since this is a
 * stripped-down implementation with only the few functions to do PAG
 * management, various interface constants and system call numbers are
 * hard-coded here.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2009
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#ifdef HAVE_SYS_IOCCOM_H
# include <sys/ioccom.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <kafs/kafs.h>

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED __attribute__((__unused__))

/* Provided by the relevant sys-*.c file. */
static int k_syscall(long, long, long, long, long, int *);

/*
 * Include the syscall implementation for this host, based on the configure
 * results.  An include of the C source is easier to handle in the build
 * machinery than lots of Automake conditionals.
 *
 * The included file must provide a k_syscall implementation.
 */
#if defined(HAVE_KAFS_LINUX)
# include <kafs/sys-linux.c>
#elif defined(HAVE_KAFS_SYSCALL)
# include <kafs/sys-syscall.c>
#else
# error "Unknown AFS system call implementation"
#endif

/*
 * The struct passed to unlog as an argument.  All the values are NULL or 0,
 * but we need the struct to be the right size.
 */
struct ViceIoctl {
    void *in, *out;
    short in_size;
    short out_size;
};

/*
 * On some platforms, k_hasafs needs to try a system call.  This attempt may
 * fail with SIGSYS.  We therefore set a signal handler that changes a static
 * variable if SIGSYS is received.
 *
 * It's really ugly to do this in library or PAM module in so many ways.
 * Static variables are evil, changing signal handlers out from under an
 * application is evil, and the interaction of signals and threads is probably
 * nasty.  The only things that make this better is that this case will never
 * be triggered in the normal case of AFS being loaded and the only time that
 * we change this static variable is to say that the call failed, so there
 * shouldn't be a collision of updates from multiple calls.
 *
 * It's probably safe to just ignore SIGSYS instead, but this feels more
 * thorough.
 */
static volatile sig_atomic_t syscall_okay = 1;


/*
 * Signal handler to catch failed system calls and change the okay flag.
 */
#ifdef SIGSYS
static void
sigsys_handler(int s UNUSED)
{
    syscall_okay = 0;
    signal(SIGSYS, sigsys_handler);
}
#endif /* SIGSYS */


/*
 * The other system calls are implemented in terms of k_pioctl.  This is a
 * standard part of the kafs interface, but we don't export it here since our
 * code never needs to call it directly and therefore doesn't need to know the
 * constants that it uses.
 *
 * This interface assumes that all pointers can be represented in a long, but
 * then so does the whole AFS system call interface.
 */
static int
k_pioctl(const char *path, int cmd, const void *cmarg, int follow)
{
    int err, rval;

    rval = k_syscall(20, (long) path, cmd, (long) cmarg, follow, &err);
    if (rval != 0)
        err = rval;
    return err;
}


/*
 * Probe to see if AFS is available and we can make system calls successfully.
 * This just attempts the set token system call with an empty token structure,
 * which will be a no-op in the kernel.
 */
int
k_hasafs(void)
{
    struct ViceIoctl iob;
    int id, result, err, saved_errno, okay;
    void (*saved_func)(int);

    saved_errno = errno;

#ifdef SIGSYS
    saved_func = signal(SIGSYS, sigsys_handler);
#endif

    iob.in = NULL;
    iob.in_size = 0;
    iob.out = NULL;
    iob.out_size = 0;
    id = _IOW('V', 3, struct ViceIoctl);
    result = k_syscall(20, 0, id, (long) &iob, 0, &err);

#ifdef SIGSYS
    signal(SIGSYS, saved_func);
#endif

    okay = (result == 0 && syscall_okay && err == -1 && errno == EINVAL);
    errno = saved_errno;
    return okay;
}


/*
 * The setpag system call.  This is special in that it's not a pioctl;
 * instead, it's a separate system call done directly through the afs_syscall
 * function.
 */
int
k_setpag(void)
{
    int err, rval;

    rval = k_syscall(21, 0, 0, 0, 0, &err);
    if (rval != 0)
        err = rval;
    return err;
}


/*
 * The unlog system call.  This destroys any tokens in the current PAG.
 */
int
k_unlog(void)
{
    struct ViceIoctl iob;

    iob.in = NULL;
    iob.in_size = 0;
    iob.out = NULL;
    iob.out_size = 0;
    return k_pioctl(NULL, _IOW('V', 9, struct ViceIoctl), &iob, 0);
}
