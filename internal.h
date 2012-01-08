/*
 * Internal functions shared between k5start and krenew.
 *
 * The interfaces to the code that can be shared between k5start and krenew,
 * most notably run_framework, which provides the main execution path of both
 * binaries.  Also defines the config struct that's used as a configuration
 * interface to run_framework.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include <config.h>
#include <portable/krb5.h>
#include <portable/macros.h>
#include <portable/stdbool.h>

/* Private structs used by krenew and k5start for internal configuration. */
struct k5start_private;
struct krenew_private;

/* The struct used to pass configuration details to run_framework. */
struct config {
    bool background;            /* Whether to run in the background. */
    bool clean_cache;           /* Whether to destroy ticket cache at exit. */
    bool do_aklog;              /* Whether to run aklog. */
    bool exit_errors;           /* Whether to exit on error as a daemon. */
    bool ignore_errors;         /* Ignore errors on initial authentication. */
    bool verbose;               /* Whether to do verbose logging. */

    char **command;             /* NULL-terminated command to run, if any. */
    int happy_ticket;           /* Remaining life of ticket required. */
    int keep_ticket;            /* How often to wake up to check ticket. */

    const char *aklog;          /* Path to aklog. */

    const char *childfile;      /* Path to child PID file to write out. */
    const char *pidfile;        /* Path to PID file to write out. */

    const char *cache;          /* Ticket cache to maintain. */

    /*
     * Desired principal.  If set, checks ticket cache for that principal in
     * particular and considers the ticket expired if it's not for that
     * principal.
     */
    krb5_principal client;

    /* Private data for the two programs. */
    union {
        struct k5start_private *k5start;
        struct krenew_private *krenew;
    } private;

    /* Callbacks. */
    krb5_error_code (*auth)(krb5_context, struct config *, krb5_error_code);
};

BEGIN_DECLS

/*
 * The primary entry point of the framework.  Both k5start and krenew call
 * this function after setting up the options and configuration to do the real
 * work.
 */
void run_framework(krb5_context, struct config *)
    __attribute__((__nonnull__, __noreturn__));

/*
 * Called to exit a program.  This handles the cleanup required, such as
 * removing the ticket cache or removing PID files.  Exits with the given
 * status.
 */
void exit_cleanup(krb5_context, struct config *, int status)
    __attribute__((__nonnull__, __noreturn__));

/* A small helper routine for parsing command-line options. */
long convert_number(const char *string, int base)
    __attribute__((__nonnull__));

END_DECLS

#endif /* !INTERNAL_H */
