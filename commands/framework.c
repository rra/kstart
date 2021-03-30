/*
 * Shared framework between k5start and krenew.
 *
 * Both k5start and krenew have a similar structure and sequence of actions:
 *
 * 1. Parse command-line options and initialize parameters.
 * 2. Do an initial authentication or ticket renewal, reporting errors.
 * 3. Run the aklog command, if any.
 * 4. Background and write out PID files if necessary.
 * 5. Spawn the external command, if any.
 * 6. If running a command or as a daemon, loop and reauthenticate as needed.
 *
 * They also support a variety of common options, such as how frequently to
 * wake up when running as a daemon, the aklog command, the happy ticket
 * handling, and so forth.
 *
 * This framework tries to handle all the shared code between the two
 * programs.  It is configured via the options struct, which stores the shared
 * information between k5start and krenew.  The code specific to one or the
 * other is handled via callbacks.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2015, 2021 Russ Allbery <eagle@eyrie.org>
 * Copyright 2006-2012, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kafs.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#include <signal.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <time.h>

#include <commands/internal.h>
#include <util/command.h>
#include <util/macros.h>
#include <util/messages-krb5.h>
#include <util/messages.h>
#include <util/xmalloc.h>

/*
 * The number of seconds of fudge to add to the check for whether we need to
 * obtain a new ticket.  This is here to make sure that we don't wake up just
 * as the ticket is expiring.
 */
#define EXPIRE_FUDGE (2 * 60)

/*
 * Set when the program receives SIGALRM, which indicates that it should wake
 * up immediately and reauthenticate.
 */
static volatile sig_atomic_t alarm_signaled = 0;

/*
 * Set when the program receives SIGHUP or SIGTERM to do cleanup and exit.
 * These signal handlers are only used when we're not running a command, since
 * running a command provides its own signal handlers.
 */
static volatile sig_atomic_t exit_signaled = 0;


/*
 * Convert from a string to a number, checking errors, and return -1 on any
 * error or for any negative number.  This doesn't really belong here, but
 * it's a tiny function used by both k5start and krenew.
 */
long
convert_number(const char *string, int base)
{
    long number;
    char *end;

    errno = 0;
    number = strtol(string, &end, base);
    if (errno != 0 || *end != '\0')
        return -1;
    return number;
}


/*
 * Signal handler for SIGALRM.  Just sets the global sentinel variable.
 */
static void
alarm_handler(int s UNUSED)
{
    alarm_signaled = 1;
}


/*
 * Signal handler for SIGHUP and SIGTERM.  Just sets the global sentinel
 * variable.
 */
static void
exit_handler(int s UNUSED)
{
    exit_signaled = 1;
}


/*
 * Get the principal name for the krbtgt ticket for the local realm.  The
 * caller is responsible for freeing the principal.  Takes an existing
 * principal to get the realm from and returns a Kerberos error on failure.
 */
static krb5_error_code
get_krbtgt_princ(krb5_context ctx, krb5_principal user, krb5_principal *princ)
{
    const char *realm;

    realm = krb5_principal_get_realm(ctx, user);
    if (realm == NULL)
        return KRB5_CONFIG_NODEFREALM;
    return krb5_build_principal(ctx, princ, (unsigned int) strlen(realm),
                                realm, "krbtgt", realm, (const char *) NULL);
}


/*
 * Check whether a ticket will expire within the given number of minutes.
 * Takes the cache and the number of minutes.  Returns a Kerberos status code
 * which will be 0 if the ticket won't expire, KRB5KRB_AP_ERR_TKT_EXPIRED if
 * it will expire and can be renewed, or another error code for any other
 * situation.
 *
 * Don't report any errors here, since k5start doesn't want to warn about any
 * of these problems.  Just return the status code.  krenew will separately
 * report an error if appropriate.
 */
static krb5_error_code
ticket_expired(krb5_context ctx, struct config *config)
{
    krb5_ccache ccache = NULL;
    krb5_creds increds, *outcreds = NULL;
    bool increds_valid = false;
    time_t now, then, offset;
    krb5_error_code code;

    /* Obtain the ticket. */
    memset(&increds, 0, sizeof(increds));
    code = krb5_cc_resolve(ctx, config->cache, &ccache);
    if (code != 0)
        goto done;
    if (config->client != NULL)
        increds.client = config->client;
    else {
        code = krb5_cc_get_principal(ctx, ccache, &increds.client);
        if (code != 0)
            goto done;
    }
    code = get_krbtgt_princ(ctx, increds.client, &increds.server);
    if (code != 0)
        goto done;
    code = krb5_get_credentials(ctx, 0, ccache, &increds, &outcreds);
    if (code != 0)
        goto done;
    increds_valid = true;

    /* Check the expiration time and renewal limit. */
    if (code == 0) {
        now = time(NULL);
        then = outcreds->times.endtime;
        if (config->happy_ticket > 0)
            offset = 60 * (config->keep_ticket + config->happy_ticket);
        else
            offset = 60 * config->keep_ticket + EXPIRE_FUDGE;
        if (then < now + offset)
            code = KRB5KRB_AP_ERR_TKT_EXPIRED;

        /*
         * The error code for an inability to renew the ticket for long enough
         * is arbitrary.  It just needs to be different than the error code
         * that indicates we can renew the ticket and coordinated with the
         * check in krenew's authentication callback.
         *
         * If the ticket is not going to expire, we skip this check.
         * Otherwise, krenew -H 1 would fail even if the ticket had plenty of
         * remaining lifespan if it was not renewable.
         */
        if (code == KRB5KRB_AP_ERR_TKT_EXPIRED) {
            then = outcreds->times.renew_till;
            if (then < now + offset)
                code = KRB5KDC_ERR_KEY_EXP;
        }
    }

done:
    if (increds.client == config->client)
        increds.client = NULL;
    if (ccache != NULL)
        krb5_cc_close(ctx, ccache);
    if (increds_valid)
        krb5_free_cred_contents(ctx, &increds);
    else {
        if (increds.client != NULL)
            krb5_free_principal(ctx, increds.client);
        if (increds.server != NULL)
            krb5_free_principal(ctx, increds.server);
    }
    if (outcreds != NULL)
        krb5_free_creds(ctx, outcreds);
    return code;
}


/*
 * Retry the initial authentication when the program is first starting.  Retry
 * the authentication immediately, then after one second, and keep trying with
 * exponential backoff, maxing out at one minute and continuing until
 * authentication succeeds or we exit due to signal.
 */
static krb5_error_code
retry_auth(krb5_context ctx, struct config *config)
{
    krb5_error_code code;
    struct timeval timeout;
    unsigned int delay = 1;

    code = config->auth(ctx, config, 0);
    while (code != 0) {
        timeout.tv_sec = delay;
        timeout.tv_usec = 0;
        delay = (delay < 30) ? delay * 2 : delay;
        select(0, NULL, NULL, NULL, &timeout);
        if (exit_signaled)
            exit_cleanup(ctx, config, 1);
        code = config->auth(ctx, config, 0);
    }
    return code;
}


/*
 * Write out a PID file given the path to the file and the PID to write.
 * Errors are reported but otherwise ignored.
 */
static void
write_pidfile(const char *path, pid_t pid)
{
    FILE *file;

    file = fopen(path, "w");
    if (file == NULL) {
        syswarn("cannot create PID file %s", path);
        return;
    }
    if (fprintf(file, "%lu\n", (unsigned long) pid) < 0)
        syswarn("cannot write to PID file %s", path);
    if (fclose(file) == EOF)
        syswarn("cannot flush PID file %s", path);
}


/*
 * Add a signal handler, exiting if there was a failure.
 */
static void
add_handler(krb5_context ctx, struct config *config, void (*handler)(int),
            int sig, const char *name)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    if (sigaction(sig, &sa, NULL) < 0) {
        syswarn("cannot set %s handler", name);
        exit_cleanup(ctx, config, 1);
    }
}


/*
 * The primary entry point of the framework.  Both k5start and krenew call
 * this function after setting up the options and configuration to do the real
 * work.  This function never returns.
 */
void
run_framework(krb5_context ctx, struct config *config)
{
    const char *aklog;
    krb5_error_code code = 0;
    pid_t child = 0;
    int result;
    int status = 0;

    /* Set aklog from AKLOG, KINIT_PROG, or the compiled-in default. */
    aklog = getenv("AKLOG");
    if (aklog == NULL)
        aklog = getenv("KINIT_PROG");
    if (aklog == NULL)
        aklog = PATH_AKLOG;
    if (aklog[0] == '\0' && config->do_aklog) {
        warn("set AKLOG to specify the path to aklog");
        exit_cleanup(ctx, config, 1);
    }

    /*
     * If built with setpag support and we're running a command, create the
     * new PAG now before the first authentication.
     */
    if (config->command != NULL && config->do_aklog) {
        if (k_hasafs()) {
            if (k_setpag() < 0) {
                syswarn("unable to create PAG");
                exit_cleanup(ctx, config, 1);
            }
        } else {
            warn("cannot create PAG: AFS support is not available");
            exit_cleanup(ctx, config, 1);
        }
    }

    /* 
     * Do the authentication once even if not necessary so that we can check
     * for any problems while we still have standard error.  If -H wasn't set,
     * always authenticate.  If -H was set, authenticate only if the ticket
     * isn't expired.
     */
    if (config->happy_ticket == 0)
        code = config->auth(ctx, config, 0);
    else {
        code = ticket_expired(ctx, config);
        if (code != 0)
            code = config->auth(ctx, config, code);
    }
    if (code != 0)
        status = 1;
    if (code != 0 && !config->ignore_errors)
        exit_cleanup(ctx, config, status);

    /* If requested, run the aklog program. */
    if (code == 0 && config->do_aklog)
        command_run(aklog, config->verbose);

    /*
     * If told to background, background ourselves.  We do this late so that
     * we can report initial errors.  We have to do this before spawning the
     * command, though, since we want to background the command as well and
     * since otherwise we wouldn't be able to wait for the child process.
     */
    if (config->background)
        if (daemon(0, 0) < 0) {
            syswarn("cannot background");
            exit_cleanup(ctx, config, 1);
        }

    /* Write out the PID file. */
    if (config->pidfile != NULL)
        write_pidfile(config->pidfile, getpid());

    /*
     * Now, if the initial authentication failed and we're ignoring initial
     * failures, retry authentication until it succeeds so that we never start
     * the command without authentication.  We don't set up signal handlers
     * here, which means SIGHUP may terminate the program during this period
     * but not after the command is started.  Any approach here is potentially
     * inconsistent; that seems the simplest.
     *
     * Set up some signal handlers so that we remove the PID file if we exit
     * via signal.  These will be overwritten by the command signal handlers
     * if we start a command later.
     */
    if (code != 0 && config->ignore_errors) {
        add_handler(ctx, config, exit_handler, SIGHUP, "SIGHUP");
        add_handler(ctx, config, exit_handler, SIGTERM, "SIGTERM");
        code = retry_auth(ctx, config);
        if (code == 0 && config->do_aklog)
            command_run(aklog, config->verbose);
    }

    /* Spawn the external command, if we were told to run one. */
    if (config->command != NULL) {
        child = command_start(config->command[0], config->command);
        if (child < 0) {
            syswarn("unable to run command %s", config->command[0]);
            exit_cleanup(ctx, config, 1);
        }
        if (config->keep_ticket == 0)
            config->keep_ticket = 60;
        if (config->childfile != NULL)
            write_pidfile(config->childfile, child);
        config->child = child;
    }

    /* Loop if we're running as a daemon. */
    if (config->keep_ticket > 0) {
        struct timeval timeout;

        add_handler(ctx, config, alarm_handler, SIGALRM, "SIGALRM");
        if (config->command == NULL) {
            add_handler(ctx, config, exit_handler, SIGHUP, "SIGHUP");
            add_handler(ctx, config, exit_handler, SIGTERM, "SIGTERM");
        }
        while (1) {
            if (config->command != NULL) {
                result = command_finish(child, &status);
                if (result < 0) {
                    syswarn("waitpid for %lu failed", (unsigned long) child);
                    exit_cleanup(ctx, config, 1);
                }
                if (result > 0) {
                    config->child = 0;
                    break;
                }
            }
            timeout.tv_sec = (code == 0) ? config->keep_ticket * 60 : 60;
            timeout.tv_usec = 0;
            select(0, NULL, NULL, NULL, &timeout);
            if (exit_signaled)
                exit_cleanup(ctx, config, 0);
            code = ticket_expired(ctx, config);
            if (alarm_signaled || config->always_renew || code != 0) {
                code = config->auth(ctx, config, code);
                if (code != 0 && config->exit_errors)
                    exit_cleanup(ctx, config, 1);
                if (code == 0 && config->do_aklog)
                    command_run(aklog, config->verbose);
            }
            alarm_signaled = 0;
        }
    }

    /* All done. */
    exit_cleanup(ctx, config, status);
}


/*
 * Handles cleanup when exiting a program.  This takes care of removing PID
 * files, destroying the ticket cache if desired, and so forth, and then calls
 * exit with the given status.
 */
void
exit_cleanup(krb5_context ctx, struct config *config, int status)
{
    krb5_error_code code;
    krb5_ccache ccache;

    if (config->cleanup != NULL)
        config->cleanup(ctx, config, status);
    if (config->clean_cache) {
        code = krb5_cc_resolve(ctx, config->cache, &ccache);
        if (code == 0)
            code = krb5_cc_destroy(ctx, ccache);
        if (code != 0)
            warn_krb5(ctx, code, "cannot destroy ticket cache");
    }
    if (config->pidfile != NULL)
        unlink(config->pidfile);
    if (config->childfile != NULL)
        unlink(config->childfile);
    krb5_free_context(ctx);
    exit(status);
}
