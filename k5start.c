/*  $Id$
**
**  Kerberos v5 kinit replacement suitable for daemon authentication.
**
**  Copyright 1987, 1988 by the Massachusetts Institute of Technology.
**  Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004
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

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <krb5.h>

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

/* The usage message. */
const char usage_message[] = "\
Usage: k5start [options] [name]\n\
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
   -n                   Don't run aklog or KINIT_PROG\n\
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

    fprintf(stderr, "kstart: ");
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
**  Check whether a ticket will expire within the given number of seconds.
**  Takes the context, ticket cache, and principal, and then the service,
**  instance, and realm of a service for which to get a ticket and the minimum
**  number of seconds of lifetime that it must have.  Returns a Kerberos
**  status code.
*/
static krb5_error_code
ticket_expired(krb5_context ctx, krb5_ccache ccache, krb5_principal princ,
               const char *service, const char *inst, const char *realm,
               int minimum)
{
    krb5_creds increds, *outcreds = NULL;
    krb5_principal sprinc = NULL;
    time_t now, then;
    int status;

    /* Obtain the ticket. */
    memset(&increds, 0, sizeof(increds));
    status = krb5_build_principal(ctx, &sprinc, strlen(realm), realm,
                                  service, inst, (const char *) NULL);
    if (status != 0) {
        com_err("k5start", status, "while creating service principal name");
        return status;
    }
    increds.client = princ;
    increds.server = sprinc;
    status = krb5_get_credentials(ctx, 0, ccache, &increds, &outcreds);

    /* Check the expiration time. */
    if (status == 0) {
        now = time(NULL);
        then = outcreds->times.endtime;
        if (then < now + 60 * minimum + EXPIRE_FUDGE)
            status = KRB5KRB_AP_ERR_TKT_EXPIRED;
    }

    /* Free memory. */
    if (sprinc != NULL)
        krb5_free_principal(ctx, sprinc);
    if (outcreds != NULL)
        krb5_free_creds(ctx, outcreds);

    return status;
}


int
main(int argc, char *argv[])
{
    int k5_errno, option;
    size_t length;
    const char *inst = NULL;
    const char *realm = NULL;
    const char *sname = NULL;
    const char *sinst = NULL;
    const char *aklog = NULL;
    const char *cache = NULL;
    const char *keytab = NULL;
    char *username = NULL;
    char *service;
    int lifetime = DEFAULT_LIFETIME;
    int status = 0;
    int happy_ticket = 0;
    int keep_ticket = 0;
    int quiet = 0;
    int run_aklog = 0;
    int stdin_passwd = 0;
    int verbose = 0;

    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal princ;
    krb5_creds creds;
    krb5_get_init_creds_opt options;
    krb5_keytab k5_keytab = NULL;
    krb5_deltat life_secs;
    krb5_data *data;

    /* Parse command-line options. */
    while ((option = getopt(argc, argv, "f:H:I:i:K:k:l:npqr:S:stu:v")) != EOF)
        switch (option) {
        case 'd': /* Ignored */         break;
        case 'I': sinst = optarg;       break;
        case 'i': inst = optarg;        break;
        case 'k': cache = optarg;       break;
        case 'n': /* Ignored */         break;
        case 'q': ++quiet;              break;
        case 'r': realm = optarg;       break;
        case 'S': sname = optarg;       break;
        case 't': ++run_aklog;          break;
        case 'v': ++verbose;            break;
        case 'u': username = optarg;    break;

        case 'f':
            keytab = optarg;
            if (stdin_passwd)
                die("cannot use both -s and -f flags");
            break;
        case 'H':
            happy_ticket = atoi(optarg);
            if (happy_ticket <= 0)
                die("-H limit argument %s out of range", optarg);
            break;
        case 'K':
            keep_ticket = atoi(optarg);
            if (keep_ticket <= 0)
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
            stdin_passwd = 1;
            if (keytab != NULL)
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
    if (argc > 1)
        usage(1);
    if (argc == 1) {
        if (username == NULL)
            username = argv[0];
        else
            die("username specified both with -u and as an argument");
    }

    /* Check the arguments for consistency. */
    if (keep_ticket > 0 && keytab == NULL)
        die("-K option requires a keytab be specified with -f");
    if (lifetime > 0 && keep_ticket > lifetime)
        die("-K limit %d must be smaller than lifetime %d", keep_ticket,
            lifetime);

    /* Set aklog from KINIT_PROG or the compiled-in default. */
    aklog = getenv("KINIT_PROG");
    if (aklog == NULL)
        aklog = PATH_AKLOG;

    /* The default username is the name of the local user. */
    if (username == NULL) {
        struct passwd *pwd;

        pwd = getpwuid(getuid());
        if (pwd == NULL)
            die("no username given and unable to obtain default value");
        username = pwd->pw_name;
    }

    /* Establish a K5 context. */
    k5_errno = krb5_init_context(&ctx);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while initializing Kerberos 5 library");
        exit(1);
    }

    /* If requested, set a ticket cache.  Also put it into the environment in
       case we're going to run aklog.  Either way, set up the cache in the
       Kerberos libraries. */
    if (cache == NULL)
        k5_errno = krb5_cc_default(ctx, &ccache);
    else {
        char *env;

        env = malloc(strlen(cache) + 12);
        if (env == NULL)
            die("cannot allocate memory: %s", strerror(errno));
        sprintf(env, "KRB5CCACHE=%s", cache);
        putenv(env);
        free(env);
        k5_errno = krb5_cc_resolve(ctx, cache, &ccache);
    }
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while initializing ticket cache");
        exit(1);
    }

    /* If either -K or -H were given, set quiet automatically unless verbose
       was set. */
    if ((keep_ticket > 0 || happy_ticket > 0) && !verbose)
        quiet = 1;

    /* The easiest thing for us is if the user just specifies the full
       principal on the command line.  For backward compatibility, though,
       support the -u and -i flags being used independently by tacking the
       instance onto the end of the username. */
    if (inst != NULL) {
        size_t len;
        char *p;

        len = strlen(username) + 1 + strlen(inst) + 1;
        p = malloc(len);
        if (p == NULL)
            die("unable to allocate memory: %s", strerror(errno));
        sprintf(p, "%s/%s", username, inst);
        username = p;
    }
    if (username != NULL) {
        k5_errno = krb5_parse_name(ctx, username, &princ);
        if (k5_errno != 0) {
            com_err("k5start", k5_errno, "when parsing %s", username);
            username = NULL;
        }
    }

    /* Display the identity that we're obtaining Kerberos tickets for.  We do
       this by unparsing the principal rather than using username and inst
       since that way we get the default realm appended by K5.  This is a
       memory leak if the username was allocated above to append the instance,
       but since it isn't in a loop, we don't care. */
    if (username != NULL && !quiet) {
        k5_errno = krb5_unparse_name(ctx, princ, &username);
        if (k5_errno != 0) {
            com_err("k5start", k5_errno, "when unparsing name %s", username);
            exit(1);
        }
        printf("Kerberos initialization for %s", username);
        if (sname != NULL) {
            printf(" for service %s", sname);
            if (sinst != NULL)
                printf("/%s", sinst);
        }
        printf("\n");
    }

    /* Flesh out the name of the service ticket that we're obtaining. */
    if (realm == NULL) {
        data = krb5_princ_realm(ctx, princ);
        if (data == NULL)
            die("cannot get local Kerberos realm");
        realm = data->data;
    }
    if (sname == NULL)
        sname = "krbtgt";
    if (sinst == NULL)
        sinst = realm;
    length = strlen(sname) + 1 + strlen(sinst) + 1;
    service = malloc(length);
    if (service == NULL)
        die("unable to allocate memory: %s", strerror(errno));
    sprintf(service, "%s/%s", sname, sinst);

    /* If we're just checking the service ticket, do that and exit if okay. */
    if (happy_ticket > 0)
        if (!ticket_expired(ctx, ccache, princ, sname, sinst, realm,
                            happy_ticket))
            exit(0);

    /* Figure out our ticket lifetime and initialize the options. */
    life_secs = lifetime * 60;
    krb5_get_init_creds_opt_init(&options);
    krb5_get_init_creds_opt_set_tkt_life(&options, life_secs);

    /* Now, the actual authentication part.  This is where we loop back to if
       we're running as a daemon (with the -K option). */
repeat:
    if (keytab != NULL) {
        k5_errno = krb5_kt_resolve(ctx, keytab, &k5_keytab);
        if (k5_errno != 0) {
            com_err("k5start", k5_errno, "resolving keytab %s", keytab);
            exit(1);
        }
        k5_errno = krb5_get_init_creds_keytab(ctx, &creds, princ, k5_keytab,
                                              0, service, &options);
    } else if (!stdin_passwd) {
        k5_errno = krb5_get_init_creds_password(ctx, &creds, princ, NULL,
                                                krb5_prompter_posix, NULL,
                                                0, service, &options);
    } else {
        char *p, buffer[BUFSIZ];

        if (!quiet)
            printf("Password: ");
        fgets(buffer, sizeof(buffer), stdin);
        p = strchr(buffer, '\n');
        if (p != NULL)
            *p = '\0';
        else
            die("password too long");
        k5_errno = krb5_get_init_creds_password(ctx, &creds, princ, buffer,
                                                krb5_prompter_posix, NULL,
                                                0, service, &options);
    }
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while getting initial credentials");
        exit(1);
    }
    k5_errno = krb5_cc_initialize(ctx, ccache, princ);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while initializing ticket cache");
        exit(1);
    }
    k5_errno = krb5_cc_store_cred(ctx, ccache, &creds);
    if (k5_errno != 0) {
        com_err("k5start", k5_errno, "while storing credentials");
        exit(1);
    }

    /* Make sure that we don't free princ; we use it later. */
    if (creds.client == princ)
        creds.client = NULL;
    krb5_free_cred_contents(ctx, &creds);
    if (k5_keytab != NULL)
        krb5_kt_close(ctx, k5_keytab);

    /* If requested, run the aklog program.  IRIX 6.5's WEXITSTATUS() macro is
       broken and can't cope with being called directly on the return value of
       system().  If we can't execute the aklog program, set the exit status
       to an arbitrary but distinct value. */
    if (run_aklog) {
        if (aklog == NULL)
            die("set KINIT_PROG to specify the path to aklog");
        if (access(aklog, X_OK) == 0) {
            status = system(aklog);
            status = WEXITSTATUS(status);
            if (verbose)
                printf("%s exited with status %d", aklog, status);
        } else {
            if (verbose)
                printf("no execute access to %s", aklog);
            status = 7;
        }
    }

    /* Loop if we're running as a daemon. */
    if (keep_ticket > 0) {
        while (1) {
            sleep(keep_ticket * 60);
            if (ticket_expired(ctx, ccache, princ, sname, sinst, realm,
                               keep_ticket))
                goto repeat;
        }
    }

    /* Otherwise, just exit. */
    exit(status);
}
