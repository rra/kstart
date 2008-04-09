/*  $Id$
**
**  Shared command handling for k4start and k5start.
**
**  Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004, 2005, 2007
**      Board of Trustees, Leland Stanford Jr. University
**
**  For copying and distribution information, please see README.
**
**  Contains the code for running aklog and an external command, used by both
**  k4start and k5start.
*/

#include <config.h>
#include <system.h>

#include <signal.h>
#include <sys/wait.h>

#include <util/util.h>

/* Global so that it can be used in signal handlers. */
static pid_t global_child_pid;


/*
**  Run the given aklog command, returning its exit status.  The command must
**  be a fully-qualified path.
*/
void
command_run(const char *aklog, int verbose)
{
    int status;

    /* IRIX 6.5's WEXITSTATUS() macro is  broken and can't cope with being
       called directly on the return value of system(). */
    status = system(aklog);
    status = WEXITSTATUS(status);
    if (verbose)
        printf("%s exited with status %d\n", aklog, status);
}


/*
**  We need a signal handler for SIGCHLD to be received, but it doesn't do
**  anything.  We just want the signal to be caught so that select will be
**  interrupted.
*/
static RETSIGTYPE
child_handler(int signal UNUSED)
{
    /* Do nothing. */
}


/*
**  This handler is installed for signals that should be propagated to the
**  child (and ignored by kstart).
*/
static RETSIGTYPE
propagate_handler(int signal)
{
    kill(global_child_pid, signal);
}


/*
**  Start a command, returning its PID.  Takes the command to run, which will
**  be searched for on the path if not fully-qualified, and then the arguments
**  to pass to it.  If execution fails for some reason, returns -1.
**
**  This function should only be called once before a call to finish_command;
**  otherwise, the signal handler code won't work properly.
*/
pid_t
command_start(const char *command, char **argv)
{
    pid_t child;

    /* Ignored. */
    signal(SIGCHLD, child_handler);

    /* Propagated to child process. */
    signal(SIGHUP, propagate_handler);
    signal(SIGTERM, propagate_handler);
    signal(SIGQUIT, propagate_handler);

    child = fork();
    if (child < 0)
        return -1;
    else if (child == 0) {
        execvp(command, argv);
        return -1;
    } else {
        global_child_pid = child;
        return child;
    }
}


/*
**  Check to see if the given pid is finished.  If it is, put its exit status
**  into the second argument, if not NULL, and return 1.  Otherwise, return
**  0, or -1 if waitpid failed.
*/
int
command_finish(pid_t child, int *status)
{
    int result;

    result = waitpid(child, status, WNOHANG);
    if (result < 0)
        return -1;
    if (result == 0)
        return 0;
    *status = WEXITSTATUS(*status);
    return 1;
}
