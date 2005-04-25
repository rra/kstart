/*  $Id$
**
**  Shared command handling for k4start and k5start.
**
**  Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004, 2005
**      Board of Trustees, Leland Stanford Jr. University
**
**  For copying and distribution information, please see README.
**
**  Contains the code for running aklog and an external command, used by both
**  k4start and k5start.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
**  Run the given aklog command, returning its exit status or 7 if it could
**  not be executed.  The command must be a fully-qualified path.
*/
int
run_aklog(const char *aklog, int verbose)
{
    int status;

    if (access(aklog, X_OK) == 0) {
        status = system(aklog);

        /* IRIX 6.5's WEXITSTATUS() macro is broken and can't cope with being
           called directly on the return value of system().  If we can't
           execute the aklog program, set the exit status to an arbitrary but
           distinct value. */
        status = WEXITSTATUS(status);
        if (verbose)
            printf("%s exited with status %d\n", aklog, status);
    } else {
        if (verbose)
            printf("no execute access to %s\n", aklog);
        status = 7;
    }
    return status;
}


/*
**  Start a command, returning its PID.  Takes the command to run, which will
**  be searched for on the path if not fully-qualified, and then the arguments
**  to pass to it.  If execution fails for some reason, returns -1.
*/
pid_t
start_command(const char *command, char **argv)
{
    pid_t child;

    child = fork();
    if (child < 0)
        return -1;
    else if (child == 0) {
        execvp(command, argv);
        return -1;
    } else
        return child;
}


/*
**  Check to see if the given pid is finished.  If it is, put its exit status
**  into the second argument, if not NULL, and return 1.  Otherwise, return
**  0, or -1 if waitpid failed.
*/
int
finish_command(pid_t child, int *status)
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
