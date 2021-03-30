/*
 * Prototypes for shared command handling.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2021 Russ Allbery <eagle@eyrie.org>
 * Copyright 1995-1997, 1999-2002, 2004-2005, 2007-2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef UTIL_COMMAND_H
#define UTIL_COMMAND_H 1

#include <config.h>
#include <portable/macros.h>
#include <portable/stdbool.h>

#include <sys/types.h>

BEGIN_DECLS

/* Default to a hidden visibility for all util functions. */
#pragma GCC visibility push(hidden)

/*
 * Run the given aklog command.  If verbose is true, print some more output to
 * standard output about the exit status.
 */
void command_run(const char *aklog, bool verbose);

/*
 * Start a command, executing the given command with the given argument vector
 * (which includes argv[0]).  Returns the PID or -1 on error.  This function
 * should not be called again without an intervening finish_command or the
 * signal handling won't work properly.
 */
pid_t command_start(const char *command, char **argv);

/*
 * Check to see if the given command has finished.  If so, return 1 and set
 * status to its exit status.  If it hasn't, return 0.  Return -1 on an
 * error.
 */
int command_finish(pid_t child, int *status);

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* UTIL_COMMAND_H */
