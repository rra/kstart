/*
 * Kerberos v5 kinit replacement suitable for daemon authentication.
 *
 * This is a replacement for the standard Kerberos v5 kinit that is more
 * suitable for use with programs.  It can run as a daemon and renew a ticket
 * periodically and can check the expiration of a ticket and only prompt to
 * renew if it's too old.
 *
 * It is based very heavily on a modified Kerberos v4 kinit, changed to call
 * the Kerberos v5 initialization functions instead.  k5start is not as useful
 * for Kerberos v5 as kstart is for Kerberos v4, since the v5 kinit supports
 * more useful options, but -K and -H are still unique to it.
 *
 * Originally written by Robert Morgan and Booker C. Bense.
 * Substantial updates by Russ Allbery <rra@stanford.edu>
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 * Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007,
 *     2008, 2009 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <time.h>

#include <kafs/kafs.h>
#include <util/util.h>

/* The default ticket lifetime in minutes.  Default to 10 hours. */
#define DEFAULT_LIFETIME (10 * 60)

/*
 * The number of seconds of fudge to add to the check for whether we need to
 * obtain a new ticket.  This is here to make sure that we don't wake up just
 * as the ticket is expiring.
 */
#define EXPIRE_FUDGE 120

/*
 * Holds the various command-line options for passing to functions, after
 * processing in the main routine and conversion to internal K5 data
 * structures where appropriate.
 */
struct options {
    krb5_principal kprinc;
    char *service;
    krb5_principal ksprinc;
    krb5_ccache ccache;
    krb5_get_init_creds_opt kopts;
    const char *keytab;
    int happy_ticket;
    int keep_ticket;
    bool quiet;
    bool run_aklog;
    const char *aklog;
    bool stdin_passwd;
    bool verbose;
};

/* Set when k5start receives SIGALRM. */
static volatile sig_atomic_t alarm_signaled = 0;

/* The usage message. */
const char usage_message[] = "\
Usage: k5start [options] [name [command]]\n\
   -u <client principal>        (default: local username)\n\
   -i <client instance>         (default: null)\n\
   -S <service name>            (default: krbtgt)\n\
   -I <service instance>        (default: realm name)\n\
   -r <service realm>           (default: local realm)\n\
\n\
   -b                   Fork and run in the background\n\
   -c <file>            Write child process ID (PID) to <file>\n\
   -F                   Force non-forwardable tickets\n\
   -f <keytab>          Use <keytab> for authentication rather than password\n\
   -g <group>           Set ticket cache group to <group>\n\
   -H <limit>           Check for a happy ticket, one that doesn't expire in\n\
                        less than <limit> minutes, and exit 0 if it's okay,\n\
                        otherwise obtain a ticket\n\
   -h                   Display this usage message and exit\n\
   -K <interval>        Run as daemon, renew ticket every <interval> minutes\n\
                        (implies -q unless -v is given)\n\
   -k <file>            Use <file> as the ticket cache\n\
   -l <lifetime>        Ticket lifetime in minutes\n\
   -m <mode>            Set ticket cache permissions to <mode> (octal)\n\
   -o <owner>           Set ticket cache owner to <owner>\n\
   -P                   Force non-proxiable tickets\n\
   -p <file>            Write process ID (PID) to <file>\n\
   -q                   Don't output any unnecessary text\n\
   -s                   Read password on standard input\n\
   -t                   Get AFS token via aklog or AKLOG\n\
   -U                   Use the first principal in the keytab as the client\n\
                        principal and don't look for a principal on the\n\
                        command line\n\
   -v                   Verbose\n\
\n\
If the environment variable AKLOG (or KINIT_PROG for backward compatibility)\n\
is set to a program (such as aklog) then this program will be executed when\n\
requested by the -t flag.  Otherwise, %s.\n";


/*
 * Print out the usage message and then exit with the status given as the
 * only argument.  If status is zero, the message is printed to standard
 * output; otherwise, it is sent to standard error.
 */
static void
usage(int status)
{
    fprintf((status == 0) ? stdout : stderr, usage_message,
            ((PATH_AKLOG[0] == '\0')
             ? "using -t is an error"
             : "the program executed will be\n" PATH_AKLOG));
    exit(status);
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
 * Given a context and a principal, get the realm.  This works differently in
 * MIT Kerberos and Heimdal, unfortunately.
 */
static char *
get_realm(krb5_context ctx UNUSED, krb5_principal princ)
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
    if (data == NULL || data->data == NULL)
        die("cannot get local Kerberos realm");
    return data->data;
#endif
}


/*
 * Check whether a ticket will expire within the given number of seconds.
 * Takes the context and the options.  Returns a Kerberos status code.
 */
static krb5_error_code
ticket_expired(krb5_context ctx, struct options *options)
{
    krb5_creds in, *out = NULL;
    time_t now, then, offset;
    krb5_error_code status;

    /* Obtain the ticket. */
    memset(&in, 0, sizeof(in));
    in.client = options->kprinc;
    in.server = options->ksprinc;
    status = krb5_get_credentials(ctx, 0, options->ccache, &in, &out);

    /*
     * Check the expiration time.  We may be looking for a ticket that lasts a
     * particuliar length of time based on either keep_ticket or happy_ticket.
     * Only one of those options will be set; at least one of them will always
     * be zero.
     */
    if (status == 0) {
        now = time(NULL);
        then = out->times.endtime;
        if (options->happy_ticket > 0)
            offset = 60 * options->happy_ticket;
        else
            offset = 60 * options->keep_ticket + EXPIRE_FUDGE;
        if (then < now + offset)
            status = KRB5KRB_AP_ERR_TKT_EXPIRED;
    }

    /* Free memory. */
    if (out != NULL)
        krb5_free_creds(ctx, out);

    return status;
}


/*
 * Authenticate, given the context and the processed command-line options.
 * Dies on failure.
 */
static void
authenticate(krb5_context ctx, struct options *options)
{
    krb5_error_code status;
    krb5_keytab keytab = NULL;
    krb5_creds creds;

    if (options->verbose) {
        char *p;

        status = krb5_unparse_name(ctx, options->kprinc, &p);
        if (status != 0)
            warn_krb5(ctx, status, "error unparsing name");
        else {
            printf("Principal: %s\n", p);
            free(p);
        }
        printf("Service principal: %s\n", options->service);
    }
    if (options->keytab != NULL) {
        status = krb5_kt_resolve(ctx, options->keytab, &keytab);
        if (status != 0)
            die_krb5(ctx, status, "error resolving keytab %s",
                     options->keytab);
        status = krb5_get_init_creds_keytab(ctx, &creds, options->kprinc,
                                            keytab, 0, options->service,
                                            &options->kopts);
    } else if (!options->stdin_passwd) {
        status = krb5_get_init_creds_password(ctx, &creds, options->kprinc,
                                              NULL, krb5_prompter_posix, NULL,
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
        status = krb5_get_init_creds_password(ctx, &creds, options->kprinc,
                                              buffer, NULL, NULL, 0,
                                              options->service,
                                              &options->kopts);
    }
    if (status != 0)
        die_krb5(ctx, status, "error getting credentials");
    status = krb5_cc_initialize(ctx, options->ccache, options->kprinc);
    if (status != 0)
        die_krb5(ctx, status, "error initializing ticket cache");
    status = krb5_cc_store_cred(ctx, options->ccache, &creds);
    if (status != 0)
        die_krb5(ctx, status, "error storing credentials");

    /* Make sure that we don't free princ; we use it later. */
    if (creds.client == options->kprinc)
        creds.client = NULL;
    krb5_free_cred_contents(ctx, &creds);
    if (keytab != NULL)
        krb5_kt_close(ctx, keytab);
}


/*
 * Find the principal of the first entry of a keytab and return it as a
 * string in newly allocated memory.  The caller is responsible for freeing.
 * Exit on error.
 */
static char *
first_principal(krb5_context ctx, const char *path)
{
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code status;
    char *principal = NULL;

    status = krb5_kt_resolve(ctx, path, &keytab);
    if (status != 0)
        die_krb5(ctx, status, "error opening %s", path);
    status = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (status != 0)
        die_krb5(ctx, status, "error reading %s", path);
    status = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
    if (status == 0) {
        status = krb5_unparse_name(ctx, entry.principal, &principal);
        if (status != 0)
            die_krb5(ctx, status, "error unparsing name from %s", path);
#ifdef HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS
        krb5_free_keytab_entry_contents(ctx, &entry);
#else
        krb5_kt_free_entry(ctx, &entry);
#endif
    }
    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    krb5_kt_close(ctx, keytab);
    if (status == 0)
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
    int opt, result;
    krb5_error_code code;
    const char *inst = NULL;
    const char *sname = NULL;
    const char *sinst = NULL;
    const char *srealm = NULL;
    const char *owner = NULL;
    const char *group = NULL;
    const char *mode = NULL;
    const char *cache = NULL;
    char *principal = NULL;
    char **command = NULL;
    char *childfile = NULL;
    char *pidfile = NULL;
    bool background = false;
    bool nonforwardable = false;
    bool nonproxiable = false;
    int lifetime = DEFAULT_LIFETIME;
    krb5_context ctx;
    krb5_deltat life_secs;
    int status = 0;
    pid_t child = 0;
    bool clean_cache = false;
    bool search_keytab = false;
    static const char optstring[] = "bc:Ff:g:H:hI:i:K:k:l:m:no:Pp:qr:S:stUu:v";

    /* Initialize logging. */
    message_program_name = "k5start";

    /* Parse command-line options. */
    memset(&options, 0, sizeof(options));
    while ((opt = getopt(argc, argv, optstring)) != EOF)
        switch (opt) {
        case 'b': background = true;            break;
        case 'c': childfile = optarg;           break;
        case 'F': nonforwardable = true;        break;
        case 'g': group = optarg;               break;
        case 'h': usage(0);                     break;
        case 'I': sinst = optarg;               break;
        case 'i': inst = optarg;                break;
        case 'm': mode = optarg;                break;
        case 'n': /* Ignored */                 break;
        case 'o': owner = optarg;               break;
        case 'P': nonproxiable = true;          break;
        case 'p': pidfile = optarg;             break;
        case 'q': options.quiet = true;         break;
        case 'r': srealm = optarg;              break;
        case 'S': sname = optarg;               break;
        case 't': options.run_aklog = true;     break;
        case 'v': options.verbose = true;       break;
        case 'U': search_keytab = true;         break;
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
        case 'k':
            cache = concat("FILE:", optarg, (char *) 0);
            break;
        case 'l':
            code = krb5_string_to_deltat(optarg, &life_secs);
            if (code != 0 || life_secs == 0)
                die("bad lifetime value %s, use 10h 10m format", optarg);
            lifetime = life_secs / 60;
            break;
        case 's':
            options.stdin_passwd = true;
            if (options.keytab != NULL)
                die("cannot use both -s and -f flags");
            break;

        default:
            usage(1);
            break;
        }

    /*
     * Parse arguments.  The first argument will be taken to be the 
     * username if the -u or -U options weren't given.  Anything else is
     * a command.
     */
    argc -= optind;
    argv += optind;
    if (argc >= 1 && !search_keytab && principal == NULL) {
        principal = argv[0];
        argc--;
        argv++;
    }
    if (argc >= 1 && strcmp(argv[0], "--") == 0) {
        argc--;
        argv++;
    }
    if (argc >= 1)  
        command = argv;

    /* Check the arguments for consistency. */
    if (background && options.keytab == NULL)
        die("-b option requires a keytab be specified with -f");
    if (background && options.keep_ticket == 0 && command == NULL)
        die("-b only makes sense with -K or a command to run");
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
        die("-U option requires a keytab be specified with -f");
    if (options.happy_ticket > 0 && options.keep_ticket > 0)
        die("-H and -K options cannot be used at the same time");
    if (childfile != NULL && command == NULL)
        die("-c option only makes sense with a command to run");

    /* Set aklog from AKLOG, KINIT_PROG, or the compiled-in default. */
    options.aklog = getenv("AKLOG");
    if (options.aklog == NULL)
        options.aklog = getenv("KINIT_PROG");
    if (options.aklog == NULL)
        options.aklog = PATH_AKLOG;
    if (options.aklog[0] == '\0' && options.run_aklog)
        die("set AKLOG to specify the path to aklog");

    /* Establish a K5 context. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        die_krb5(ctx, code, "error initializing Kerberos");

    /* If the -U option was given, figure out the principal from the keytab. */
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

    /*
     * If requested, set a ticket cache.  Otherwise, if we're running a
     * command, set the ticket cache to a mkstemp-generated file.  Also put it
     * into the environment in case we're going to run aklog.  Either way, set
     * up the cache in the Kerberos libraries.
     */
    if (cache == NULL && command != NULL) {
        int fd;
        char *tmp;

        if (xasprintf(&tmp, "/tmp/krb5cc_%d_XXXXXX", (int) getuid()) < 0)
            die("cannot format ticket cache name");
        fd = mkstemp(tmp);
        if (fd < 0)
            sysdie("cannot create ticket cache file");
        if (fchmod(fd, 0600) < 0)
            sysdie("cannot chmod ticket cache file");
        cache = tmp;
        clean_cache = true;
    }
    if (cache == NULL) {
        code = krb5_cc_default(ctx, &options.ccache);
        if (code == 0)
            cache = krb5_cc_get_name(ctx, options.ccache);
    } else {
        if (setenv("KRB5CCNAME", cache, 1) != 0)
            die("cannot set KRB5CCNAME environment variable");
        code = krb5_cc_resolve(ctx, cache, &options.ccache);
    }
    if (code != 0)
        die_krb5(ctx, code, "error initializing ticket cache");

    /*
     * If -K, -H, or -b were given, set quiet automatically unless verbose was
     * set.
     */
    if (options.keep_ticket > 0 || options.happy_ticket > 0 || background)
        if (!options.verbose)
            options.quiet = true;

    /*
     * The easiest thing for us is if the user just specifies the full
     * principal on the command line.  For backward compatibility, though,
     * support the -u and -i flags being used independently by tacking the
     * instance onto the end of the username.
     */
    if (inst != NULL) {
        size_t len;
        char *p;

        len = strlen(principal) + 1 + strlen(inst) + 1;
        if (xasprintf(&p, "%s/%s", principal, inst) < 0)
            die("cannot format principal name");
        principal = p;
    }
    code = krb5_parse_name(ctx, principal, &options.kprinc);
    if (code != 0)
        die_krb5(ctx, code, "error parsing %s", principal);

    /*
     * Display the identity that we're obtaining Kerberos tickets for.  We do
     * this by unparsing the principal rather than using username and inst
     * since that way we get the default realm appended by K5.
     */
    if (!options.quiet) {
        char *p;

        code = krb5_unparse_name(ctx, options.kprinc, &p);
        if (code != 0)
            die_krb5(ctx, code, "error unparsing name %s", principal);
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
    if (xasprintf(&options.service, "%s/%s@%s", sname, sinst, srealm) < 0)
        die("cannot format service principal name");
    code = krb5_build_principal(ctx, &options.ksprinc, strlen(srealm),
                                srealm, sname, sinst, (const char *) NULL);
    if (code != 0)
        die_krb5(ctx, code, "error creating service principal name");

    /* Figure out our ticket lifetime and initialize the options. */
    life_secs = lifetime * 60;
    krb5_get_init_creds_opt_init(&options.kopts);
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS
    krb5_get_init_creds_opt_set_default_flags(ctx, "k5start",
                                              options.kprinc->realm,
                                              &options.kopts);
#endif
    krb5_get_init_creds_opt_set_tkt_life(&options.kopts, life_secs);
    if (nonforwardable)
        krb5_get_init_creds_opt_set_forwardable(&options.kopts, 0);
    if (nonproxiable)
        krb5_get_init_creds_opt_set_proxiable(&options.kopts, 0);

    /*
     * If we're just checking the service ticket, do that and exit if okay.
     * Still re-run aklog if requested, though, since the token may have
     * expired or we may be initializing a new PAG from an existing ticket
     * cache.
     */
    if (options.happy_ticket > 0 && command == NULL)
        if (!ticket_expired(ctx, &options)) {
            if (options.run_aklog)
                command_run(options.aklog, options.verbose);
            exit(0);
        }

    /*
     * If built with setpag support and we're running a command, create the
     * new PAG now before the first authentication.
     */
    if (command != NULL && options.run_aklog) {
        if (k_hasafs()) {
            if (k_setpag() < 0)
                sysdie("unable to create PAG");
        } else {
            die("cannot create PAG: AFS support is not available");
        }
    }

    /*
     * Now, the actual authentication part.  If -H wasn't set, always
     * authenticate.  If -H was set, authenticate only if the ticket isn't
     * expired.
     */
    if (options.happy_ticket == 0 || ticket_expired(ctx, &options))
        authenticate(ctx, &options);

    /* If requested, run the aklog program. */
    if (options.run_aklog)
        command_run(options.aklog, options.verbose);

    /* If requested, set the owner, group, and mode of the resulting cache. */
    if (owner != NULL || group != NULL || mode != NULL)
        file_permissions(cache, owner, group, mode);

    /*
     * If told to background, set signal handlers and background ourselves.
     * We do this late so that we can report initial errors.  We have to do
     * this before spawning the command, though, since we want to background
     * the command as well and since otherwise we wouldn't be able to wait for
     * the child process.
     */
    if (background)
        daemon(0, 0);

    /*
     * If we're backgrounded, check our ticket and possibly do the
     * authentication again.  Normally this will never trigger, but on Mac OS
     * X our ticket cache isn't going to survive the setsid that daemon does
     * and we've now lost our credentials.
     */
    if (background && ticket_expired(ctx, &options))
        authenticate(ctx, &options);

    /*
     * Write out the PID file.  Note that we can't report failures usefully,
     * since this is generally used with -b.
     */
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
        child = command_start(command[0], command);
        if (child < 0)
            sysdie("unable to run command %s", command[0]);
        if (options.keep_ticket == 0) {
            options.keep_ticket = lifetime - EXPIRE_FUDGE / 60 - 1;
            if (options.keep_ticket <= 0)
                options.keep_ticket = 1;
        }
    }

    /* Write out the child PID file.  Again, no useful error reporting. */
    if (childfile != NULL) {
        FILE *file;

        file = fopen(childfile, "w");
        if (file != NULL) {
            fprintf(file, "%lu\n", (unsigned long) child);
            fclose(file);
        }
    }

    /* Loop if we're running as a daemon. */
    if (options.keep_ticket > 0) {
        struct timeval timeout;
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = alarm_handler;
        if (sigaction(SIGALRM, &sa, NULL) < 0)
            sysdie("cannot set SIGALRM handler");
        while (1) {
            if (command != NULL) {
                result = command_finish(child, &status);
                if (result < 0)
                    sysdie("waitpid for %lu failed", (unsigned long) child);
                if (result > 0)
                    break;
            }
            timeout.tv_sec = options.keep_ticket * 60;
            timeout.tv_usec = 0;
            select(0, NULL, NULL, NULL, &timeout);
            if (alarm_signaled || ticket_expired(ctx, &options)) {
                authenticate(ctx, &options);
                if (options.run_aklog)
                    command_run(options.aklog, options.verbose);
                if (owner != NULL || group != NULL || mode != NULL)
                    file_permissions(cache, owner, group, mode);
                alarm_signaled = 0;
            }
        }
    }

    /*
     * Otherwise, or when we're done, exit.  clean_cache is only set if we
     * used mkstemp to generate the ticket cache name.
     */
    if (clean_cache) {
        code = krb5_cc_destroy(ctx, options.ccache);
        if (code != 0)
            die_krb5(ctx, code, "unable to destroy ticket cache %s", cache);
    }
    exit(status);
}
