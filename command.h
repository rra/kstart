/* command.h -- Shared command execution for k4start and k5start. */
/* $Id$ */

#ifndef COMMAND_H
#define COMMAND_H 1

#include <sys/types.h>          /* pid_t */

/* Run the given aklog command.  If verbose is true, print some more output to
   standard output about the exit status. */
int run_aklog(const char *aklog, int verbose);

/* Start a command, executing the given command with the given argument vector
   (which includes argv[0]).  Returns the PID or -1 on error. */
pid_t start_command(const char *command, char **argv);

/* Check to see if the given command has finished.  If so, return 1 and set
   status to its exit status.  If it hasn't, return 0.  Return -1 on an
   error. */
int finish_command(pid_t child, int *status);

#endif /* COMMAND_H */

