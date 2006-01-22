/*  $Id$
**
**  Automatically renew a Kerberos v5 ticket.
**
**  Copyright 2006 Board of Trustees, Leland Stanford Jr. University
**
**  For copying and distribution information, please see README.
**
**  Similar to k5start, krenew can run as a daemon or run a specified program
**  and wait until it completes.  Rather than obtaining fresh Kerberos
**  credentials, however, it uses an existing Kerberos ticket cache and
**  tries to renew the tickets until it exits or until the ticket cannot be
**  renewed any longer.
*/

#include "config.h"
#include "command.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <krb5.h>

#if HAVE_K_SETPAG
# if HAVE_KAFS_H
#  include <kafs.h>
# endif
# define lsetpag() k_setpag()
#elif HAVE_LSETPAG
int lsetpag(void);
#else
# define lsetpag() (0)
#endif

/* __attribute__ is available in gcc 2.5 and later, but only with gcc 2.7
   could you use the __format__ form of the attributes, which is what we use
   (to avoid confusion with other macros). */
#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(spec)   /* empty */
# endif
#endif

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#ifndef HAVE_KRB5_ERR
extern krb5_error_code krb5_err(krb5_context, int, krb5_error_code,
                                const char *, ...)
    __attribute__((__format__(printf, 4, 5)));
extern krb5_error_code krb5_warn(krb5_context, krb5_error_code,
                                 const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
#endif

/* The number of seconds of fudge to add to the check for whether we need to
   obtain a new ticket.  This is here to make sure that we don't wake up just
   as the ticket is expiring. */
#define EXPIRE_FUDGE (2 * 60)

/* Make sure everything compiles even if no aklog program was found by
   configure. */
#ifndef PATH_AKLOG
# define PATH_AKLOG ""
#endif

/* The usage message. */
const char usage_message[] = "\
Usage: krenew [options] [command]\n\
   -b                   Fork and run in the background\n\
   -h                   Display this usage message and exit\n\
   -K <interval>        Run as daemon, renew ticket every <interval> minutes\n\
                        (implies -q unless -v is given)\n\
   -k <file>            Use <file> as the ticket cache\n\
   -p <file>            Write process ID (PID) to <file>\n\
   -t                   Get AFS token via aklog or KINIT_PROG\n\
   -v                   Verbose\n\
\n\
If the environment variable KINIT_PROG is set to a program (such as aklog)\n\
then this program will be executed when requested by the -t flag.\n\
Otherwise, %s.\n";


/*
**  Report an error message to standard error and then exit.
*/
static void
die(const char *format, ...)
{
    va_list args;

    fprintf(stderr, "k5start: ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    exit(1);
}


/*
**  Print out the usage message and then exit with the status given as the
**  only argument.  If status is zero, the message is printed to standard
**  output; otherwise, it is sent to standard error.
*/
static void
usage(int status)
{
    fprintf((status == 0) ? stdout : stderr, usage_message,
            ((PATH_AKLOG[0] == '\0')
             ? "using -t is an error"
             : "the default program to run is " PATH_AKLOG));
    exit(status);
}


/*
**  Given a context and a principal, get the realm.  This works differently in
**  MIT Kerberos and Heimdal, unfortunately.
*/
static char *
get_realm(krb5_context ctx, krb5_principal princ)
{
#ifdef HAVE_KRB5_REALM
    krb5_realm *realm;

    realm = krb5_princ_realm(ctx, princ);
    if (realm == NULL)
        die("cannot get local Kerberos realm");
    return krb5_realm_data(*realm);
#else
    krb5_data *data;

    data = krb5_princ_realm(ctx, princ);
    if (data == NULL)
        die("cannot get local Kerberos realm");
    return data->data;
#endif
}


/*
**  Get the principal name for the krbtgt ticket for the local realm.  The
**  caller is responsible for freeing the principal.  Takes an existing
**  principal to get the realm from and returns a Kerberos v5 error on
**  failure.
*/
static int
get_krbtgt_princ(krb5_context ctx, krb5_principal user, krb5_principal *princ)
{
    char *realm;

    realm = get_realm(ctx, user);
    return krb5_build_principal(ctx, princ, strlen(realm), realm, "krbtgt",
                                realm, (const char *) NULL);
}


/*
**  Check whether a ticket will expire within the given number of minutes.
**  Takes the cache and the number of minutes.  Returns a Kerberos status
**  code.
*/
static krb5_error_code
ticket_expired(krb5_context ctx, krb5_ccache cache, int keep_ticket)
{
    krb5_creds increds, *outcreds = NULL;
    time_t now, then;
    int status;

    /* Obtain the ticket. */
    memset(&increds, 0, sizeof(increds));
    status = krb5_cc_get_principal(ctx, cache, &increds.client);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error reading cache");
    status = get_krbtgt_princ(ctx, increds.client, &increds.server);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error building ticket name");
    status = krb5_get_credentials(ctx, 0, cache, &increds, &outcreds);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: cannot get current credentials");

    /* Check the expiration time. */
    if (status == 0) {
        now = time(NULL);
        then = outcreds->times.endtime;
        if (then < now + 60 * keep_ticket + EXPIRE_FUDGE)
            status = KRB5KRB_AP_ERR_TKT_EXPIRED;
    }

    /* Free memory. */
    krb5_free_cred_contents(ctx, &increds);
    if (outcreds != NULL)
        krb5_free_creds(ctx, outcreds);

    return status;
}


/*
**  Renew the user's tickets, exiting with an error if this isn't possible.
**  Normally dies on failure, but if authentication succeeds and aklog just
**  failed, return the exit status of aklog instead.
*/
static int
renew(krb5_context ctx, krb5_ccache cache, const char *aklog, int verbose)
{
    int status;
    krb5_principal user;
    krb5_creds creds, *out;
#ifndef HAVE_KRB5_GET_RENEWED_CREDS
    krb5_kdc_flags flags;
    krb5_creds in, *old = NULL;
#endif

    memset(&creds, 0, sizeof(creds));
    status = krb5_cc_get_principal(ctx, cache, &user);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error reading cache");
    if (verbose) {
        char *name;

        status = krb5_unparse_name(ctx, user, &name);
        if (status != 0)
            krb5_warn(ctx, status, "krenew: error unparsing name");
        else {
            printf("kstart: renewing credentials for %s\n", name);
            free(name);
        }
    }
#ifdef HAVE_KRB5_GET_RENEWED_CREDS
    status = krb5_get_renewed_creds(ctx, &creds, user, cache, NULL);
    out = &creds;
#else
    flags.i = 0;
    flags.b.renewable = 1;
    flags.b.renew = 1;
    memset(&in, 0, sizeof(in));
    status = krb5_copy_principal(ctx, user, &in.client);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error copying principal");
    status = get_krbtgt_princ(ctx, in.client, &in.server);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error building ticket name");
    status = krb5_get_credentials(ctx, 0, cache, &in, &old);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: cannot get current credentials");
    status = krb5_get_kdc_cred(ctx, cache, flags, NULL, NULL, old, &out);
#endif
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error renewing credentials");
    
    status = krb5_cc_initialize(ctx, cache, user);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error reinitializing cache");
    status = krb5_cc_store_cred(ctx, cache, out);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error storing credentials");
    krb5_free_principal(ctx, user);
#ifdef HAVE_KRB5_GET_RENEWED_CREDS
    krb5_free_cred_contents(ctx, &creds);
#else
    krb5_free_cred_contents(ctx, &in);
    if (old != NULL)
        krb5_free_creds(ctx, old);
    if (out != NULL)
        krb5_free_creds(ctx, out);
#endif

    /* If requested, run the aklog program. */
    if (aklog != NULL && aklog[0] != '\0')
        status = run_aklog(aklog, verbose);
    
    return status;
}


int
main(int argc, char *argv[])
{
    int option, result;
    char *cachename = NULL;
    char **command = NULL;
    char *pidfile = NULL;
    int background = 0;
    int keep_ticket = 0;
    int run_aklog = 0;
    int verbose = 0;
    char *aklog = NULL;
    krb5_context ctx;
    krb5_ccache cache;
    int status = 0;
    pid_t child = 0;

    /* Parse command-line options. */
    while ((option = getopt(argc, argv, "bhK:k:p:qtv")) != EOF)
        switch (option) {
        case 'b': background = 1;               break;
        case 'h': usage(0);                     break;
        case 'k': cachename = optarg;           break;
        case 'p': pidfile = optarg;             break;
        case 't': run_aklog = 1;                break;
        case 'v': verbose = 1;                  break;

        case 'K':
            keep_ticket = atoi(optarg);
            if (keep_ticket <= 0)
                die("-K interval argument %s out of range", optarg);
            break;

        default:
            usage(1);
            break;
        }

    /* Parse arguments.  If any are given, they will be the command to run. */
    argc -= optind;
    argv += optind;
    if (argc > 0)
        command = argv;

    /* Check the arguments for consistency. */
    if (background && keep_ticket == 0 && command == NULL)
        die("-b only makes sense with -K or a command to run");

    /* Set aklog from KINIT_PROG or the compiled-in default. */
    aklog = getenv("KINIT_PROG");
    if (aklog == NULL)
        aklog = PATH_AKLOG;
    if (aklog[0] == '\0' && run_aklog)
        die("set KINIT_PROG to specify the path to aklog");

    /* Establish a K5 context and set the ticket cache. */
    status = krb5_init_context(&ctx);
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error initializing Kerberos");
    if (cachename == NULL)
        status = krb5_cc_default(ctx, &cache);
    else {
        char *env;

        env = malloc(strlen(cachename) + strlen("KRB5CCNAME=") + 1);
        if (env == NULL)
            die("cannot allocate memory: %s", strerror(errno));
        sprintf(env, "KRB5CCNAME=%s", cachename);
        putenv(env);
        status = krb5_cc_resolve(ctx, cachename, &cache);
    }
    if (status != 0)
        krb5_err(ctx, 1, status, "krenew: error initializing ticket cache");

    /* If built with setpag support and we're running a command, create the
       new PAG now before the first authentication. */
    if (command != NULL && run_aklog)
        if (lsetpag() < 0)
            die("unable to create PAG: %s", strerror(errno));

    /* Now, do the initial ticket renewal even if it's not necessary so that
       we can catch any problems. */
    status = renew(ctx, cache, run_aklog ? aklog : NULL, verbose);

    /* If told to background, background ourselves.  We do this late so that
       we can report initial errors.  We have to do this before spawning the
       command, though, since we want to background the command as well and
       since otherwise we wouldn't be able to wait for the child process. */
    if (background)
        daemon(0, 0);

    /* Write out the PID file.  Note that we can't report failures usefully,
       since this is generally used with -b. */
    if (pidfile != NULL) {
        FILE *file;

        file = fopen(pidfile, "w");
        if (file != NULL) {
            fprintf(file, "%lu\n", (unsigned long) getpid());
            fclose(file);
        }
    }

    /* Spawn the external command, if we were told to run one. */
    if (command != NULL) {
        child = start_command(command[0], command);
        if (child < 0)
            die("unable to run command %s: %s", command[0], strerror(errno));
        if (keep_ticket == 0)
            keep_ticket = 60;
    }

    /* Loop if we're running as a daemon. */
    if (keep_ticket > 0) {
        struct timeval timeout;

        while (1) {
            if (command != NULL) {
                result = finish_command(child, &status);
                if (result < 0)
                    die("waitpid for %lu failed: %s", (unsigned long) child,
                        strerror(errno));
                if (result > 0)
                    goto done;
            }
            timeout.tv_sec = keep_ticket * 60;
            timeout.tv_usec = 0;
            select(0, NULL, NULL, NULL, &timeout);
            if (ticket_expired(ctx, cache, keep_ticket))
                status = renew(ctx, cache, aklog, verbose);
        }
    }

done:
    exit(status);
}
