/*  $Id$
**
**  Kerberos v4 kinit replacement suitable for daemon authentication.
**
**  Copyright 1987, 1988 by the Massachusetts Institute of Technology.
**  Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004
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

#include <errno.h>
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

#ifdef HAVE_KERBEROSIV_KRB_H
# include <kerberosIV/krb.h>
#else
# include <krb.h>
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

/* The usage message. */
const char usage_message[] = "\
Usage: kstart [options] [name]\n\
   -u <client principal>        (default: local username)\n\
   -i <client instance>         (default: null)\n\
   -S <service name>            (default: krbtgt)\n\
   -I <service instance>        (default: realm name)\n\
   -r <service realm>           (default: local realm)\n\
\n\
   -f <srvtab>          Read password from <srvtab>, as a srvtab key\n\
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
**  Takes the service, instance, and realm of a service for which to get a
**  ticket and the minimum number of seconds of lifetime that it must have.
**  Returns a Kerberos status code.
*/
static int
ticket_expired(char *service, char *inst, char *realm, int minimum)
{
    CREDENTIALS cr;
    int status;
    time_t now, then;

    status = krb_get_cred(service, inst, realm, &cr);
    if (status == KSUCCESS) {
        now = time(NULL);
        then = krb_life_to_time(cr.issue_date, cr.lifetime);
        if (then < now + 60 * minimum + EXPIRE_FUDGE)
            status = RD_AP_EXP;
    }
    return status;
}


int
main(int argc, char *argv[])
{
    int k_errno, option;
    char aname[ANAME_SZ] = "";
    char inst[INST_SZ] = "";
    char realm[REALM_SZ] = "";
    char sname[SNAME_SZ] = "";
    char sinst[INST_SZ] = "";
    const char *aklog = NULL;
    const char *cache = NULL;
    const char *srvtab = NULL;
    char *username = NULL;
    int lifetime = 0;
    int status = 0;
    int happy_ticket = 0;
    int keep_ticket = 0;
    int quiet = 0;
    int no_aklog = 0;
    int run_aklog = 0;
    int stdin_passwd = 0;
    int verbose = 0;

    /* Parse command-line options. */
    while ((option = getopt(argc, argv, "f:H:I:i:K:k:l:npqr:S:stu:v")) != EOF)
        switch (option) {
        case 'k': cache = optarg;       break;
        case 'n': ++no_aklog;           break;
        case 'q': ++quiet;              break;
        case 't': ++run_aklog;          break;
        case 'v': ++verbose;            break;
        case 'u': username = optarg;    break;

        case 'f':
            srvtab = optarg;
            if (stdin_passwd)
                die("cannot use both -s and -f flags");
            break;
        case 'H':
            happy_ticket = atoi(optarg);
            if (happy_ticket <= 0)
                die("-H limit argument %s out of range", optarg);
            break;
        case 'I':
            if (strlen(optarg) < sizeof(sinst))
                strcpy(sinst, optarg);
            else
                die("service instance %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(sinst));
            break;
        case 'i':
            if (strlen(optarg) < sizeof(inst))
                strcpy(inst, optarg);
            else
                die("instance %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(inst));
            break;
        case 'K':
            keep_ticket = atoi(optarg);
            if (keep_ticket <= 0)
                die("-K interval argument %s out of range", optarg);
            break;
        case 'l':
            lifetime = atoi(optarg);
            if (lifetime <= 0)
                die("-l lifetime argument %s out of range", optarg);
            break;
        case 'r':
            if (strlen(optarg) < sizeof(realm))
                strcpy(realm, optarg);
            else
                die("realm %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(realm));
            break;
        case 'S':
            if (strlen(optarg) < sizeof(sname))
                strcpy(sname, optarg);
            else
                die("service name %s too long (%lu max)", optarg,
                    (unsigned long) sizeof(sname));
            break;
        case 'p':
        case 's':
            stdin_passwd = 1;
            if (srvtab != NULL)
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
    if (keep_ticket > 0 && srvtab == NULL)
        die("-K option requires a srvtab be specified with -f");
    if (lifetime > 0 && keep_ticket > lifetime)
        die("-K limit %d must be smaller than lifetime %d", keep_ticket,
            lifetime);

    /* Check to see if KINIT_PROG is set.  If it is, and no_aklog is not set,
       set run_aklog, since setting that environment variable changes the
       default. */
    aklog = getenv("KINIT_PROG");
    if (aklog == NULL)
        aklog = PATH_AKLOG;
    else
        run_aklog = 1;

    /* The default username is the name of the local user. */
    if (username == NULL) {
        struct passwd *pwd;

        pwd = getpwuid(getuid());
        if (pwd == NULL)
            die("no username given and unable to obtain default value");
        username = pwd->pw_name;
    }

    /* If requested, set a ticket cache.  Also put it into the environment in
       case we're going to run aklog. */
    if (cache != NULL) {
        char *env;

        krb_set_tkt_string(cache);
        env = malloc(strlen(cache) + 11);
        if (env == NULL)
            die("cannot allocate memory: %s", strerror(errno));
        sprintf(env, "KRBTKFILE=%s", cache);
        putenv(env);
    }

    /* If either -K or -H were given, set quiet automatically unless verbose
       was set. */
    if ((keep_ticket > 0 || happy_ticket > 0) && !verbose)
        quiet = 1;

    /* Parse the username into its components. */
    if (username != NULL) {
        k_errno = kname_parse(aname, inst, realm, username);
        if (k_errno != KSUCCESS) {
            fprintf(stderr, "kstart: parsing name: %s", krb_err_txt[k_errno]);
            username = NULL;
        }
    }

    /* Print out the initialization banner. */
    if (username != NULL && !quiet) {
        printf("Kerberos initialization for %s", aname);
        if (*inst != '\0')
            printf(".%s", inst);
        if (*realm != '\0')
            printf("@%s", realm);
        if (*sname != '\0') {
            printf(" for service %s", sname);
            if (*sinst != '\0')
                printf(".%s", sinst);
        }
        printf("\n");
    }

    /* Set the ticket lifetime.  The lifetime given on the command line will
       be in minutes, and we need to convert that to the Kerberos v4 lifetime
       code. */
    if (lifetime < 5)
        lifetime = 1;
    else
        lifetime = krb_time_to_life(0, lifetime * 60);
    if (lifetime > 255)
        lifetime = 255;

    /* Flesh out the name of the service ticket that we're obtaining. */
    if (*realm == '\0' && krb_get_lrealm(realm, 1) != KSUCCESS)
        die("cannot get local Kerberos realm");
    if (*sname == '\0')
        strcpy(sname, "krbtgt");
    if (*sinst == '\0')
        strcpy(sinst, realm);

    /* If we're just checking the service ticket, do that and exit if okay. */
    if (happy_ticket > 0)
        if (!ticket_expired(sname, sinst, realm, happy_ticket))
            exit(0);

    /* Now, the actual authentication part.  This is where we loop back to if
       we're running as a daemon (with the -K option). */
repeat:
    if (srvtab != NULL)
        k_errno = krb_get_svc_in_tkt(aname, inst, realm, sname, sinst,
                                     lifetime, (char *) srvtab);
    else if (!stdin_passwd)
        k_errno = krb_get_pw_in_tkt(aname, inst, realm, sname, sinst,
                                    lifetime, NULL);
    else {
        char *p, buffer[BUFSIZ];

        if (!quiet)
            printf("Password: ");
        fgets(buffer, sizeof(buffer), stdin);
        p = strchr(buffer, '\n');
        if (p != NULL)
            *p = '\0';
        else
            die("password too long");
        k_errno = krb_get_pw_in_tkt(aname, inst, realm, sname, sinst,
                                    lifetime, buffer);
    }
    if (verbose) {
        printf("Principal: %s.%s@%s\n", aname, inst, realm);
        printf("Service principal: %s.%s@%s\n", sname, sinst, realm);
        printf("%s\n", krb_err_txt[k_errno]);
    }
    if (k_errno != KSUCCESS)
        die("Kerberos error: %s", krb_err_txt[k_errno]);

    /* If requested, run the aklog program.  IRIX 6.5's WEXITSTATUS() macro is
       broken and can't cope with being called directly on the return value of
       system().  If we can't execute the aklog program, set the exit status
       to an arbitrary but distinct value. */
#ifdef DO_AKLOG
    if (run_aklog && !no_aklog) {
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
#endif

    /* Loop if we're running as a daemon. */
    if (keep_ticket > 0) {
        while (1) {
            sleep(keep_ticket * 60);
            if (ticket_expired(sname, sinst, realm, keep_ticket))
                goto repeat;
        }
    }

    /* Otherwise, just exit. */
    exit(status);
}
