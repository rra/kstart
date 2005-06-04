/*  $Id$
**
**  Kerberos v5 kinit replacement suitable for daemon authentication.
**
**  Copyright 1987, 1988 by the Massachusetts Institute of Technology.
**  Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004, 2005
**      Board of Trustees, Leland Stanford Jr. University
**
**  For copying and distribution information, please see README.
**
**  This is a replacement for the standard Kerberos v5 kinit that is more
**  suitable for use with programs.  It can run as a daemon and renew a ticket
**  periodically and can check the expiration of a ticket and only prompt to
**  renew if it's too old.
**
**  It is based very heavily on a modified Kerberos v4 kinit, changed to call
**  the Kerberos v5 initialization functions instead.  k5start is not as
**  useful for Kerberos v5 as kstart is for Kerberos v4, since the v5 kinit
**  supports more useful options, but -K and -H are still unique to it.
*/

#include "config.h"
#include "command.h"

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <krb5.h>

#ifndef HAVE_MKSTEMP
extern int mkstemp(char *);
#endif

/* The AFS headers don't prototype this. */
#ifdef HAVE_SETPAG
int setpag(void);
#endif

/* The default ticket lifetime in minutes.  Default to 10 hours. */
#define DEFAULT_LIFETIME (10 * 60)

/* The number of seconds of fudge to add to the check for whether we need to
   obtain a new ticket.  This is here to make sure that we don't wake up just
   as the ticket is expiring. */
#define EXPIRE_FUDGE 120

/* Make sure everything compiles even if no aklog program was found by
   configure. */
#ifndef PATH_AKLOG
# define PATH_AKLOG NULL
#endif

/* Holds the various command-line options for passing to functions, after
   processing in the main routine and conversion to internal K5 data
   structures where appropriate. */
struct options {
    krb5_principal kprinc;
    char *service;
    krb5_principal ksprinc;
    krb5_ccache ccache;
    krb5_get_init_creds_opt kopts;
    const char *keytab;
    int happy_ticket;
    int keep_ticket;
    int quiet;
    int run_aklog;
    const char *aklog;
    int stdin_passwd;
    int verbose;
};

/* The usage message. */
const char usage_message[] = "\
Usage: k5start [options] [name [command]]\n\
   -u <client principal>        (default: local username)\n\
   -i <client instance>         (default: null)\n\
   -S <service name>            (default: krbtgt)\n\
   -I <service instance>        (default: realm name)\n\
   -r <service realm>           (default: local realm)\n\
\n\
   -f <keytab>          Use <keytab> for authentication rather than password\n\
   -H <limit>           Check for a happy ticket, one that doesn't expire in\n\
                        less than <limit> minutes, and exit 0 if it's okay,\n\
                        otherwise obtain a ticket\n\
   -K <interval>        Run as daemon, renew ticket every <interval> minutes\n\
                        (implies -q unless -v is given)\n\
   -k <file>            Use <file> as the ticket cache\n\
   -l <lifetime>        Ticket lifetime in minutes\n\
   -P                   Use the first principal in the keytab as the client\n\
                        principal and don't look for a principal on the\n\
                        command line\n\
   -q                   Don't output any unnecessary text\n\
   -s                   Read password on standard input\n\
   -t                   Get AFS token via aklog or KINIT_PROG\n\
   -v                   Verbose\n\
\n\
If the environment variable KINIT_PROG is set to a program (such as aklog)\n\
then this program will be executed when requested by the -t flag, rather\n\
than whatever aklog program was compiled into k5start.\n";


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
    fprintf((status == 0) ? stdout : stderr, usage_message);
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
**  Check whether a ticket will expire within the given number of seconds.
**  Takes the context and the options.  Returns a Kerberos status code.
*/
static krb5_error_code
ticket_expired(krb5_context ctx, struct options *options)
{
    krb5_creds increds, *outcreds = NULL;
    time_t now, then;
    int status;

    /* Obtain the ticket. */
    memset(&increds, 0, sizeof(increds));
    increds.client = options->kprinc;
    increds.server = options->ksprinc;
    status = krb5_get_credentials(ctx, 0, options->ccache, &increds,
                                  &outcreds);

    /* Check the expiration time. */
    if (status == 0) {
        now = time(NULL);
        then = outcreds->times.endtime;
        if (then < now + 60 * options->keep_ticket + EXPIRE_FUDGE)
            status = KRB5KRB_AP_ERR_TKT_EXPIRED;
    }

    /* Free memory. */
    if (outcreds != NULL)
        krb5_free_creds(ctx, outcreds);

    return status;
}


/*
**  Authenticate, given the context and the processed command-line options.
**  Also takes care of running aklog if requested.  Normally dies on failure,
**  but if authentication succeeds and aklog just failed, return the exit
**  status of aklog instead (or 7 if it couldn't be run).
*/
static int
authenticate(krb5_context ctx, struct options *options)
{
    int k5_errno;
    int status = 0;
    krb5_keytab k5_keytab = NULL;
    krb5_creds creds;

    if (options->verbose) {
        char *p;

        k5_errno = krb5_unparse_name(ctx, options->kprinc, &p);
        if (k5_errno != 0)
            com_err("k5start", k5_errno, "when unparsing name");
        else {
            printf("Principal: %s\n", p);
            free(p);
        }
        printf("Service principal: %s\n", options->service);
    }
    if (options->keytab != NULL) {
        k5_errno = krb5_kt_resolve(ctx, options->keytab, &k5_keytab);
        if (k5_errno != 0) {
            com_err("k5start", k5_errno, "resolving keytab %s",
                    options->keytab);
            exit(1);
        }
        k5_errno = krb5_get_init_creds_keytab(ctx, &creds,
                                              options->kprinc, k5_keytab,
                                              0, options->service,
                                              &options->kopts);
    } else if (!options->stdin_passwd) {
        k5_errno = krb5_get_init_creds_password(ctx, &creds,
                                                options->kprinc, NULL,
                                                krb5_prompter_posix, NULL,
                                                0, options->service,
                                                &options->kopts);
    } else {
        char *p, buffer[BUFSIZ];

        if (!options->quiet)
            printf("Password: ");
        fgets(buffer, sizeof(buffer), stdin);
        p = strchr(buffer, '\n');
        if (p != NULL)
            *p = '\0';
        else
            die("password too long");
        k5_errno = krb5_get_init_creds_password(ctx, &creds,
                                                options->kprinc, buffer,
                                                krb5_prompter_posix, NULL,
                                                0, options->service,
                                                &options->kopts);
    }
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while getting initial credentials");
        exit(1);
    }
    k5_errno = krb5_cc_initialize(ctx, options->ccache, options->kprinc);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while initializing ticket cache");
        exit(1);
    }
    k5_errno = krb5_cc_store_cred(ctx, options->ccache, &creds);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while storing credentials");
        exit(1);
    }

    /* Make sure that we don't free princ; we use it later. */
    if (creds.client == options->kprinc)
        creds.client = NULL;
    krb5_free_cred_contents(ctx, &creds);
    if (k5_keytab != NULL)
        krb5_kt_close(ctx, k5_keytab);

    /* If requested, run the aklog program.  IRIX 6.5's WEXITSTATUS() macro is
       broken and can't cope with being called directly on the return value of
       system().  If we can't execute the aklog program, set the exit status
       to an arbitrary but distinct value. */
    if (options->run_aklog)
        status = run_aklog(options->aklog, options->verbose);
    return status;
}


/*
**  Find the principal of the first entry of a keytab and return it as a
**  string in newly allocated memory.  The caller is responsible for freeing.
**  Exit on error.
*/
static char *
first_principal(krb5_context ctx, const char *path)
{
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    int k5_errno;
    char *principal = NULL;

    k5_errno = krb5_kt_resolve(ctx, path, &keytab);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while opening %s", path);
        exit(1);
    }
    k5_errno = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while reading %s", path);
        exit(1);
    }
    k5_errno = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
    if (k5_errno == 0) {
        k5_errno = krb5_unparse_name(ctx, entry.principal, &principal);
        if (k5_errno != 0) {
            com_err("k5start", k5_errno, "while unparsing name from %s", path);
            exit(1);
        }
#ifdef HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS
        krb5_free_keytab_entry_contents(ctx, &entry);
#else
        krb5_kt_free_entry(ctx, &entry);
#endif
    }
    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    if (k5_errno == 0)
        return principal;
    else {
        die("no principal found in keytab file %s", path);
        return NULL;
    }
}


int
main(int argc, char *argv[])
{
    struct options options;
    int k5_errno, option, result;
    size_t length;
    const char *inst = NULL;
    const char *sname = NULL;
    const char *sinst = NULL;
    const char *srealm = NULL;
    char *cache = NULL;
    char *principal = NULL;
    char **command = NULL;
    int lifetime = DEFAULT_LIFETIME;
    krb5_context ctx;
    krb5_deltat life_secs;
    int status = 0;
    pid_t child = 0;
    int clean_cache = 0;
    int search_keytab = 0;

    /* Parse command-line options. */
    memset(&options, 0, sizeof(options));
    while ((option = getopt(argc, argv, "f:H:I:i:K:k:l:nPpqr:S:stu:v")) != EOF)
        switch (option) {
        case 'I': sinst = optarg;               break;
        case 'i': inst = optarg;                break;
        case 'k': cache = optarg;               break;
        case 'n': /* Ignored */                 break;
        case 'q': options.quiet = 1;            break;
        case 'P': search_keytab = 1;            break;
        case 'r': srealm = optarg;              break;
        case 'S': sname = optarg;               break;
        case 't': options.run_aklog = 1;        break;
        case 'v': options.verbose = 1;          break;
        case 'u': principal = optarg;           break;

        case 'f':
            options.keytab = optarg;
            if (options.stdin_passwd)
                die("cannot use both -s and -f flags");
            break;
        case 'H':
            options.happy_ticket = atoi(optarg);
            if (options.happy_ticket <= 0)
                die("-H limit argument %s out of range", optarg);
            break;
        case 'K':
            options.keep_ticket = atoi(optarg);
            if (options.keep_ticket <= 0)
                die("-K interval argument %s out of range", optarg);
            break;
        case 'l':
            k5_errno = krb5_string_to_deltat(optarg, &life_secs);
            if (k5_errno != 0 || life_secs == 0)
                die("bad lifetime value %s, use 10h 10m format", optarg);
            lifetime = life_secs / 60;
            break;
        case 'p':
        case 's':
            options.stdin_passwd = 1;
            if (options.keytab != NULL)
                die("cannot use both -s and -f flags");
            break;

        default:
            usage(1);
            break;
        }

    /* Parse arguments.  There must be at most one argument, which will be
       taken to be the username if the -u option wasn't already given. */
    argc -= optind;
    argv += optind;
    if (argc >= 1 && !search_keytab) {
        if (principal == NULL)
            principal = argv[0];
        else
            die("username specified both with -u and as an argument");
        argc--;
        argv++;
    }
    if (argc > 0)
        command = argv;

    /* Check the arguments for consistency. */
    if (options.keep_ticket > 0 && options.keytab == NULL)
        die("-K option requires a keytab be specified with -f");
    if (command != NULL && options.keytab == NULL)
        die("running a command requires a keytab be specified with -f");
    if (lifetime > 0 && options.keep_ticket > lifetime)
        die("-K limit %d must be smaller than lifetime %d",
            options.keep_ticket, lifetime);
    if (principal != NULL && strchr(principal, '/') != NULL && inst != NULL)
        die("instance specified in the principal and with -i");
    if (search_keytab && options.keytab == NULL)
        die("-p option requires a keytab be specified with -f");

    /* Set aklog from KINIT_PROG or the compiled-in default. */
    options.aklog = getenv("KINIT_PROG");
    if (options.aklog == NULL)
        options.aklog = PATH_AKLOG;
    if (options.aklog == NULL && options.run_aklog)
        die("set KINIT_PROG to specify the path to aklog");

    /* Establish a K5 context. */
    k5_errno = krb5_init_context(&ctx);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while initializing Kerberos 5 library");
        exit(1);
    }

    /* If the -P option was given, figure out the principal from the keytab. */
    if (search_keytab)
        principal = first_principal(ctx, options.keytab);

    /* The default principal is the name of the local user. */
    if (principal == NULL) {
        struct passwd *pwd;

        pwd = getpwuid(getuid());
        if (pwd == NULL)
            die("no username given and unable to obtain default value");
        principal = pwd->pw_name;
    }

    /* If requested, set a ticket cache.  Otherwise, if we're running a
       command, set the ticket cache to a mkstemp-generated file.  Also put it
       into the environment in case we're going to run aklog.  Either way, set
       up the cache in the Kerberos libraries. */
    if (cache == NULL && command != NULL) {
        int fd;

        cache = malloc(strlen("/tmp/krb5cc__XXXXXX") + 20 + 1);
        sprintf(cache, "/tmp/krb5cc_%d_XXXXXX", getuid());
        fd = mkstemp(cache);
        if (fd < 0)
            die("cannot create ticket cache file: %s", strerror(errno));
        if (fchmod(fd, 0600) < 0)
            die("cannot chmod ticket cache file: %s", strerror(errno));
        clean_cache = 1;
    }
    if (cache == NULL)
        k5_errno = krb5_cc_default(ctx, &options.ccache);
    else {
        char *env;

        env = malloc(strlen(cache) + 12);
        if (env == NULL)
            die("cannot allocate memory: %s", strerror(errno));
        sprintf(env, "KRB5CCNAME=%s", cache);
        putenv(env);
        k5_errno = krb5_cc_resolve(ctx, cache, &options.ccache);
    }
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while initializing ticket cache");
        exit(1);
    }

    /* If either -K or -H were given, set quiet automatically unless verbose
       was set. */
    if (options.keep_ticket > 0 || options.happy_ticket > 0)
        if (!options.verbose)
            options.quiet = 1;

    /* The easiest thing for us is if the user just specifies the full
       principal on the command line.  For backward compatibility, though,
       support the -u and -i flags being used independently by tacking the
       instance onto the end of the username. */
    if (inst != NULL) {
        size_t len;
        char *p;

        len = strlen(principal) + 1 + strlen(inst) + 1;
        p = malloc(len);
        if (p == NULL)
            die("unable to allocate memory: %s", strerror(errno));
        sprintf(p, "%s/%s", principal, inst);
        principal = p;
    }
    k5_errno = krb5_parse_name(ctx, principal, &options.kprinc);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "when parsing %s", principal);
        exit(1);
    }

    /* Display the identity that we're obtaining Kerberos tickets for.  We do
       this by unparsing the principal rather than using username and inst
       since that way we get the default realm appended by K5. */
    if (!options.quiet) {
        char *p;

        k5_errno = krb5_unparse_name(ctx, options.kprinc, &p);
        if (k5_errno != 0) {
            com_err("k5start", k5_errno, "when unparsing name %s", principal);
            exit(1);
        }
        printf("Kerberos initialization for %s", p);
        free(p);
        if (sname != NULL) {
            printf(" for service %s", sname);
            if (sinst != NULL)
                printf("/%s", sinst);
            if (srealm != NULL)
                printf("@%s", srealm);
        }
        printf("\n");
    }

    /* Flesh out the name of the service ticket that we're obtaining. */
    if (srealm == NULL)
        srealm = get_realm(ctx, options.kprinc);
    if (sname == NULL)
        sname = "krbtgt";
    if (sinst == NULL)
        sinst = srealm;
    length = strlen(sname) + 1 + strlen(sinst) + 1 + strlen(srealm) + 1;
    options.service = malloc(length);
    if (options.service == NULL)
        die("unable to allocate memory: %s", strerror(errno));
    sprintf(options.service, "%s/%s@%s", sname, sinst, srealm);
    status = krb5_build_principal(ctx, &options.ksprinc, strlen(srealm),
                                  srealm, sname, inst, (const char *) NULL);
    if (status != 0) {
        com_err("k5start", status, "while creating service principal name");
        exit(1);
    }

    /* Figure out our ticket lifetime and initialize the options. */
    life_secs = lifetime * 60;
    krb5_get_init_creds_opt_init(&options.kopts);
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS
    krb5_get_init_creds_opt_set_default_flags(ctx, "k5start",
                                              options.kprinc->realm,
                                              &options.kopts);
#endif
    krb5_get_init_creds_opt_set_tkt_life(&options.kopts, life_secs);

    /* If we're just checking the service ticket, do that and exit if okay. */
    if (options.happy_ticket > 0)
        if (!ticket_expired(ctx, &options))
            exit(0);

    /* If built with setpag support and we're running a command, create the
       new PAG now before the first authentication. */
#ifdef HAVE_SETPAG
    if (command != NULL && options.run_aklog)
        if (setpag() < 0)
            die("unable to create PAG: %s", strerror(errno));
#endif

    /* Now, the actual authentication part. */
    status = authenticate(ctx, &options);
    if (command != NULL) {
        child = start_command(command[0], command);
        if (child < 0)
            die("unable to run command %s: %s", command[0], strerror(errno));
        if (options.keep_ticket == 0) {
            options.keep_ticket = lifetime - EXPIRE_FUDGE / 60 - 1;
            if (options.keep_ticket <= 0)
                options.keep_ticket = 1;
        }
    }

    /* Loop if we're running as a daemon. */
    if (options.keep_ticket > 0) {
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
            timeout.tv_sec = options.keep_ticket * 60;
            timeout.tv_usec = 0;
            select(0, NULL, NULL, NULL, &timeout);
            if (ticket_expired(ctx, &options))
                status = authenticate(ctx, &options);
        }
    }

done:
    /* Otherwise, or when we're done, exit.  clean_cache is only set if we
       used mkstemp to generate the ticket cache name. */
    if (clean_cache)
        if (unlink(cache) < 0)
            fprintf(stderr, "k5start: unable to remove ticket cache %s: %s",
                    cache, strerror(errno));
    exit(status);
}
