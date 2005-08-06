/*  $Id$
**
**  Kerberos v4 kinit replacement suitable for daemon authentication.
**
**  Copyright 1987, 1988 by the Massachusetts Institute of Technology.
**  Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004, 2005
**      Board of Trustees, Leland Stanford Jr. University
**
**  For copying and distribution information, please see README.
**
**  This is a replacement for the standard Kerberos v4 kinit that is more
**  suitable for use with programs.  It takes more parameters as regular
**  command-line options, can run as a daemon and renew a ticket periodically,
**  can authenticate from a srvtab instead of a password, and can check the
**  expiration of a ticket and only prompt to renew it if it's too old.
**
**  It is based very heavily on a modified Kerberos v4 kinit.
*/

#include "config.h"
#include "command.h"

#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_KERBEROSIV_KRB_H
# include <kerberosIV/krb.h>
#else
# include <krb.h>
#endif

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#ifndef HAVE_MKSTEMP
extern int mkstemp(char *);
#endif

/* The AFS headers don't prototype this. */
#ifdef HAVE_SETPAG
int setpag(void);
#endif

/* We default to a ten hour ticket lifetime if the Kerberos headers don't
   provide a value. */
#ifndef DEFAULT_TKT_LIFE
# define DEFAULT_TKT_LIFE 120
#endif

/* The number of seconds of fudge to add to the check for whether we need to
   obtain a new ticket.  This is here to make sure that we don't wake up just
   as the ticket is expiring. */
#define EXPIRE_FUDGE 120

/* Make sure everything compiles even if no aklog program was found by
   configure. */
#ifndef PATH_AKLOG
# define PATH_AKLOG NULL
#endif

/* Holds the various command-line options for passing to functions. */
struct options {
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char sname[SNAME_SZ];
    char sinst[INST_SZ];
    const char *aklog;
    const char *srvtab;
    char *cache;
    int lifetime;
    int happy_ticket;
    int keep_ticket;
    int quiet;
    int no_aklog;
    int run_aklog;
    int stdin_passwd;
    int verbose;
};

/* The usage message. */
const char usage_message[] = "\
Usage: k4start [options] [name]\n\
   -u <client principal>        (default: local username)\n\
   -i <client instance>         (default: null)\n\
   -S <service name>            (default: krbtgt)\n\
   -I <service instance>        (default: realm name)\n\
   -r <service realm>           (default: local realm)\n\
\n\
   -b                   Fork and run in the background\n\
   -f <srvtab>          Read password from <srvtab>, as a srvtab key\n\
   -H <limit>           Check for a happy ticket, one that doesn't expire in\n\
                        less than <limit> minutes, and exit 0 if it's okay,\n\
                        otherwise obtain a ticket\n\
   -K <interval>        Run as daemon, renew ticket every <interval> minutes\n\
                        (implies -q unless -v is given)\n\
   -k <file>            Use <file> as the ticket cache\n\
   -l <lifetime>        Ticket lifetime in minutes\n\
   -n                   Don't run aklog or KINIT_PROG\n\
   -p <file>            Write process ID (PID) to <file>\n\
   -q                   Don't output any unnecessary text\n\
   -s                   Read password on standard input\n\
   -t                   Get AFS token via aklog or KINIT_PROG\n\
   -v                   Verbose\n\
\n\
If the environment variable KINIT_PROG is set to a program (such as aklog)\n\
then this program will automatically be executed after the ticket granting\n\
ticket has been retrieved unless -n is given.  Otherwise, the default is to\n\
not run any aklog program.\n";


/*
**  Report an error message to standard error and then exit.
*/
static void
die(const char *format, ...)
{
    va_list args;

    fprintf(stderr, "k4start: ");
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
**  Takes the options struct and looks at the service, instance, and realm of
**  a service for which to get a ticket and the minimum number of seconds of
**  lifetime that it must have.  Returns a Kerberos status code.
*/
static int
ticket_expired(struct options *options)
{
    CREDENTIALS cr;
    int status;
    time_t now, then;

    status = krb_get_cred(options->sname, options->sinst, options->realm, &cr);
    if (status == KSUCCESS) {
        now = time(NULL);
        then = krb_life_to_time(cr.issue_date, cr.lifetime);
        if (then < now + 60 * options->keep_ticket + EXPIRE_FUDGE)
            status = RD_AP_EXP;
    }
    return status;
}


/*
**  Authenticate, given a set of options.  Also handles running aklog if
**  requested.  Normally dies on failure, but if authentication succeeds and
**  aklog just failed, return the exit status of aklog instead (or 7 if it
**  couldn't be run).
*/
static int
authenticate(struct options *options, const char *aklog)
{
    int k_errno;
    int status = 0;

    if (options->verbose) {
        printf("Principal: %s.%s@%s\n", options->aname, options->inst,
               options->realm);
        printf("Service principal: %s.%s@%s\n", options->sname,
               options->sinst, options->realm);
    }
    if (options->srvtab != NULL)
        k_errno = krb_get_svc_in_tkt(options->aname, options->inst,
                                     options->realm, options->sname,
                                     options->sinst, options->lifetime,
                                     (char *) options->srvtab);
    else if (!options->stdin_passwd)
        k_errno = krb_get_pw_in_tkt(options->aname, options->inst,
                                    options->realm, options->sname,
                                    options->sinst, options->lifetime, NULL);
    else {
        char *p, buffer[BUFSIZ];

        if (!options->quiet)
            printf("Password: ");
        fgets(buffer, sizeof(buffer), stdin);
        p = strchr(buffer, '\n');
        if (p != NULL)
            *p = '\0';
        else
            die("password too long");
        k_errno = krb_get_pw_in_tkt(options->aname, options->inst,
                                    options->realm, options->sname,
                                    options->sinst, options->lifetime,
                                    buffer);
    }
    if (k_errno != KSUCCESS) {
        if (k_errno < 0 || k_errno > MAX_KRB_ERRORS)
            die("unknown Kerberos error");
        else
            die("Kerberos error: %s", krb_err_txt[k_errno]);
    }

    /* If requested, run the aklog program. */
    if (options->run_aklog && !options->no_aklog)
        status = run_aklog(aklog, options->verbose);
    return status;
}


int
main(int argc, char *argv[])
{
    struct options options;
    int k_errno, opt, result;
    char *username = NULL;
    char *aklog = NULL;
    char **command = NULL;
    char *pidfile = NULL;
    int background = 0;
    int lifetime = DEFAULT_TKT_LIFE;
    pid_t child = 0;
    int status = 0;
    int clean_cache = 0;

    /* Parse command-line options. */
    memset(&options, 0, sizeof(options));
    while ((opt = getopt(argc, argv, "bf:H:I:i:K:k:l:np:qr:S:stu:v")) != EOF)
        switch (opt) {
        case 'b': background = 1;               break;
        case 'k': options.cache = optarg;       break;
        case 'n': options.no_aklog = 1;         break;
        case 'p': pidfile = optarg;             break;
        case 'q': options.quiet = 1;            break;
        case 't': options.run_aklog = 1;        break;
        case 'v': options.verbose = 1;          break;
        case 'u': username = optarg;            break;

        case 'f':
            options.srvtab = optarg;
            if (options.stdin_passwd)
                die("cannot use both -s and -f flags");
            break;
        case 'H':
            options.happy_ticket = atoi(optarg);
            if (options.happy_ticket <= 0)
                die("-H limit argument %s out of range", optarg);
            break;
        case 'I':
            if (strlen(optarg) < sizeof(options.sinst))
                strcpy(options.sinst, optarg);
            else
                die("service instance %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(options.sinst));
            break;
        case 'i':
            if (strlen(optarg) < sizeof(options.inst))
                strcpy(options.inst, optarg);
            else
                die("instance %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(options.inst));
            break;
        case 'K':
            options.keep_ticket = atoi(optarg);
            if (options.keep_ticket <= 0)
                die("-K interval argument %s out of range", optarg);
            break;
        case 'l':
            lifetime = atoi(optarg);
            if (lifetime <= 0)
                die("-l lifetime argument %s out of range", optarg);
            break;
        case 'r':
            if (strlen(optarg) < sizeof(options.realm))
                strcpy(options.realm, optarg);
            else
                die("realm %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(options.realm));
            break;
        case 'S':
            if (strlen(optarg) < sizeof(options.sname))
                strcpy(options.sname, optarg);
            else
                die("service name %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(options.sname));
            break;
        case 's':
            options.stdin_passwd = 1;
            if (options.srvtab != NULL)
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
    if (argc >= 1) {
        if (username == NULL)
            username = argv[0];
        else
            die("username specified both with -u and as an argument");
    }
    if (argc > 1)
        command = argv + 1;

    /* Check the arguments for consistency. */
    if (background && options.srvtab == NULL)
        die("-b option requires a srvtab be specified with -f");
    if (background && options.keep_ticket == 0 && command == NULL)
        die("-b only makes sense with -K or a command to run");
    if (options.keep_ticket > 0 && options.srvtab == NULL)
        die("-K option requires a srvtab be specified with -f");
    if (command != NULL && options.srvtab == NULL)
        die("running a command requires a srvtab be specified with -f");
    if (lifetime > 0 && options.keep_ticket > lifetime)
        die("-K limit %d must be smaller than lifetime %d",
            options.keep_ticket, options.lifetime);

    /* Check to see if KINIT_PROG is set.  If it is, and no_aklog is not set,
       set run_aklog, since setting that environment variable changes the
       default. */
    aklog = getenv("KINIT_PROG");
    if (aklog == NULL)
        aklog = PATH_AKLOG;
    else
        options.run_aklog = 1;
    if (aklog == NULL && options.run_aklog && !options.no_aklog)
        die("set KINIT_PROG to specify the path to aklog");

    /* The default username is the name of the local user. */
    if (username == NULL) {
        struct passwd *pwd;

        pwd = getpwuid(getuid());
        if (pwd == NULL)
            die("no username given and unable to obtain default value");
        username = pwd->pw_name;
    }

    /* If requested, set a ticket cache.  Otherwise, if we're running a
       command, set the ticket cache to a mkstemp-generated file.  Also put
       the ticket cache, if we set one, into the environment in case we're
       going to run aklog or a command. */
    if (options.cache == NULL && command != NULL) {
        int fd;

        options.cache = malloc(strlen("/tmp/tkt_XXXXXX") + 20 + 1);
        sprintf(options.cache, "/tmp/tkt%d_XXXXXX", getuid());
        fd = mkstemp(options.cache);
        if (fd < 0)
            die("cannot create ticket cache file: %s", strerror(errno));
        if (fchmod(fd, 0600) < 0)
            die("cannot chmod ticket cache file: %s", strerror(errno));
        clean_cache = 1;
    }
    if (options.cache != NULL) {
        char *env;

        krb_set_tkt_string(options.cache);
        env = malloc(strlen(options.cache) + 11);
        if (env == NULL)
            die("cannot allocate memory: %s", strerror(errno));
        sprintf(env, "KRBTKFILE=%s", options.cache);
        putenv(env);
    }

    /* If -K, -H, or -b were given, set quiet automatically unless verbose was
       set. */
    if (options.keep_ticket > 0 || options.happy_ticket > 0 || background)
        if (!options.verbose)
            options.quiet = 1;

    /* Parse the username into its components. */
    k_errno = kname_parse(options.aname, options.inst, options.realm,
                          username);
    if (k_errno != KSUCCESS)
        die("parsing name: %s", krb_err_txt[k_errno]);

    /* Print out the initialization banner. */
    if (!options.quiet) {
        printf("Kerberos initialization for %s", options.aname);
        if (*options.inst != '\0')
            printf(".%s", options.inst);
        if (*options.realm != '\0')
            printf("@%s", options.realm);
        if (*options.sname != '\0') {
            printf(" for service %s", options.sname);
            if (*options.sinst != '\0')
                printf(".%s", options.sinst);
        }
        printf("\n");
    }

    /* Set the ticket lifetime.  The lifetime given on the command line will
       be in minutes, and we need to convert that to the Kerberos v4 lifetime
       code. */
    if (lifetime < 5)
        options.lifetime = 1;
    else
        options.lifetime = krb_time_to_life(0, lifetime * 60);
    if (options.lifetime > 255)
        options.lifetime = 255;

    /* Flesh out the name of the service ticket that we're obtaining. */
    if (*options.realm == '\0' && krb_get_lrealm(options.realm, 1) != KSUCCESS)
        die("cannot get local Kerberos realm");
    if (*options.sname == '\0') {
        strcpy(options.sname, "krbtgt");
        if (*options.sinst == '\0')
            strcpy(options.sinst, options.realm);
    }

    /* If we're just checking the service ticket, do that and exit if okay. */
    if (options.happy_ticket > 0)
        if (!ticket_expired(&options))
            exit(0);

    /* If built with setpag support and we're running a command, create the
       new PAG now before the first authentication. */
#ifdef HAVE_SETPAG
    if (command != NULL && options.run_aklog && !options.no_aklog)
        if (setpag() < 0)
            die("unable to create PAG: %s", strerror(errno));
#endif

    /* Now, do the actual authentication. */
    status = authenticate(&options, aklog);

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
            if (ticket_expired(&options))
                status = authenticate(&options, aklog);
        }
    }

done:
    /* Otherwise, or when we're done, exit.  clean_cache is only set if we
       used mkstemp to generate the ticket cache name. */
    if (clean_cache)
        if (unlink(options.cache) < 0)
            fprintf(stderr, "k4start: unable to remove ticket cache %s: %s",
                    options.cache, strerror(errno));
    exit(status);
}
