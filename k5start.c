/*
 * Kerberos kinit replacement suitable for daemon authentication.
 *
 * This is a replacement for the standard Kerberos kinit that is more suitable
 * for use with programs.  It can run as a daemon and renew a ticket
 * periodically and can check the expiration of a ticket and only prompt to
 * renew if it's too old.
 *
 * It is based very heavily on a modified Kerberos v4 kinit, changed to call
 * the Kerberos v5 initialization functions instead.
 *
 * Originally written by Robert Morgan and Booker C. Bense.
 * Substantial updates by Russ Allbery <eagle@eyrie.org>
 * Copyright 1995, 1996, 1997, 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007,
 *     2008, 2009, 2010, 2011, 2012, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>

#include <internal.h>
#include <util/concat.h>
#include <util/macros.h>
#include <util/messages.h>
#include <util/messages-krb5.h>
#include <util/xmalloc.h>

/* The default ticket lifetime in minutes.  Default to 10 hours. */
#define DEFAULT_LIFETIME (10 * 60)

/*
 * Holds the various command-line options for passing to functions, after
 * processing in the main routine and conversion to internal Kerberos data
 * structures where appropriate.
 */
struct k5start_private {
    char *service;              /* Service for which to get credentials. */
    krb5_principal ksprinc;     /* Service principal. */
    const char *keytab;         /* Keytab to use to authenticate. */
    bool quiet;                 /* Whether to silence even normal output. */
    bool stdin_passwd;          /* Whether to get the password from stdin. */
    uid_t owner;                /* Owner of created ticket cache. */
    uid_t group;                /* Group of created ticket cache. */
    mode_t mode;                /* Mode of created ticket cache. */
    bool set_perms;             /* Whether to set owner and perms on cache. */
    const char *cache;          /* Path to destination cache. */
    krb5_get_init_creds_opt *kopts;
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
   -a                   Renew on each wakeup when running as a daemon\n\
   -b                   Fork and run in the background\n\
   -c <file>            Write child process ID (PID) to <file>\n\
   -F                   Force non-forwardable tickets\n\
   -f <keytab>          Use <keytab> for authentication rather than password\n\
   -g <group>           Set ticket cache group to <group>\n\
   -H <limit>           Check for a happy ticket, one that doesn't expire in\n\
                        less than <limit> minutes, and exit 0 if it's okay,\n\
                        otherwise obtain a ticket\n\
   -h                   Display this usage message and exit\n\
   -K <interval>        Run as daemon, check ticket every <interval> minutes\n\
                        (implies -q unless -v is given)\n\
   -k <file>            Use <file> as the ticket cache\n\
   -L                   Log messages via syslog as well as stderr\n\
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
   -x                   Exit immediately on any error\n\
\n\
If the environment variable AKLOG (or KINIT_PROG for backward compatibility)\n\
is set to a program (such as aklog) then this program will be executed when\n\
requested by the -t flag.  Otherwise, %s.\n";

/* Included in the usage message if AFS support is compiled in. */
const char usage_message_kafs[] = "\n\
When invoked with -t and a command, k5start will create a new AFS PAG for\n\
the command before running the AKLOG program to keep its AFS credentials\n\
isolated from other processes.\n";


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
#ifdef HAVE_KAFS
    fprintf((status == 0) ? stdout : stderr, usage_message_kafs);
#endif
    exit(status);
}


/*
 * Given the path to a file and the private configuration information, set the
 * owner, group, or mode.  Owner and group may be either the name of a user or
 * group or a numeric UID or GID (as a string).  If the owner is specified as
 * a username (but not if it is specified as a UID), set the GID, if
 * unspecified, to the primary group of that user.
 *
 * Returns an errno on failure and zero on success.
 */
static krb5_error_code
set_permissions(const char *file, const struct k5start_private *private)
{
    if (private->owner != (uid_t) -1 || private->group != (gid_t) -1)
        if (chown(file, private->owner, private->group) < 0) {
            syswarn("cannot chown %s to %ld:%ld", file, (long) private->owner,
                    (long) private->group);
            return errno;
        }
    if (private->mode != 0)
        if (chmod(file, private->mode) < 0) {
            syswarn("cannot chmod %s to %o", file,
                    (unsigned int) private->mode);
            return errno;
        }
    return 0;
}


/*
 * Authenticate, given the context and the processed command-line options.
 * Dies on failure.
 */
static krb5_error_code
authenticate(krb5_context ctx, struct config *config,
             krb5_error_code status UNUSED)
{
    struct k5start_private *private = config->private.k5start;
    krb5_error_code code;
    krb5_keytab keytab = NULL;
    krb5_creds creds;
    const char *cache = config->cache;
    krb5_ccache ccache = NULL;
    int oerrno;

    /*
     * If we have owner, group, or mode information, we have to create a
     * separate temporary ticket cache, change its ownership, and then rename
     * it.
     */
    if (private->set_perms) {
        int fd;
        char *tmp;

        if (xasprintf(&tmp, "%s_XXXXXX", config->cache) < 0)
            die("cannot format ticket cache name");
        fd = mkstemp(tmp);
        if (fd < 0) {
            syswarn("cannot create temporary ticket cache file");
            return errno;
        }
        if (fchmod(fd, 0600) < 0) {
            syswarn("cannot chmod temporary ticket cache file");
            oerrno = errno;
            unlink(tmp);
            return oerrno;
        }
        close(fd);
        cache = tmp;
    }

    /* Verbose logging of what we're doing. */
    if (config->verbose) {
        char *p;

        code = krb5_unparse_name(ctx, config->client, &p);
        if (code != 0)
            warn_krb5(ctx, code, "error unparsing name");
        else {
            notice("authenticating as %s", p);
            krb5_free_unparsed_name(ctx, p);
        }
        notice("getting tickets for %s", private->service);
    }

    /* Obtain new credentials. */
    memset(&creds, 0, sizeof(creds));
    if (private->keytab != NULL) {
        code = krb5_kt_resolve(ctx, private->keytab, &keytab);
        if (code != 0) {
            warn_krb5(ctx, code, "error resolving keytab %s",
                      private->keytab);
            goto done;
        }
        code = krb5_get_init_creds_keytab(ctx, &creds, config->client,
                                          keytab, 0, private->service,
                                          private->kopts);
    } else if (!private->stdin_passwd) {
        code = krb5_get_init_creds_password(ctx, &creds, config->client,
                                            NULL, krb5_prompter_posix, NULL,
                                            0, private->service,
                                            private->kopts);
    } else {
        char *p, buffer[BUFSIZ];

        if (!private->quiet)
            printf("Password: ");
        fgets(buffer, sizeof(buffer), stdin);
        p = strchr(buffer, '\n');
        if (p != NULL)
            *p = '\0';
        else {
            warn("password too long");
            code = KRB5_LIBOS_CANTREADPWD;
            goto done;
        }
        code = krb5_get_init_creds_password(ctx, &creds, config->client,
                                            buffer, NULL, NULL, 0,
                                            private->service,
                                            private->kopts);
    }
    if (code != 0) {
        warn_krb5(ctx, code, "error getting credentials");
        goto done;
    }

    /* Set up the new ticket cache. */
    code = krb5_cc_resolve(ctx, cache, &ccache);
    if (code != 0) {
        warn_krb5(ctx, code, "error creating ticket cache");
        goto done;
    }
    code = krb5_cc_initialize(ctx, ccache, config->client);
    if (code != 0) {
        warn_krb5(ctx, code, "error initializing ticket cache");
        goto done;
    }
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    if (code != 0) {
        warn_krb5(ctx, code, "error storing credentials");
        goto done;
    }
    krb5_cc_close(ctx, ccache);
    ccache = NULL;

    /*
     * If we aren't changing ownership or permissions, we're done.  If we are,
     * set the owner, group, and mode of the resulting cache, and then rename
     * it into place.
     */
    if (private->set_perms) {
        code = set_permissions(cache, private);
        if (code != 0)
            goto done;
        if (rename(cache, config->cache) < 0) {
            code = errno;
            goto done;
        }
    }

done:
    /* If we failed and were generating a separate cache, unlink it. */
    if (private->set_perms)
        unlink(cache);

    /* Make sure that we don't free princ; we use it later. */
    if (creds.client == config->client)
        creds.client = NULL;
    if (cache != config->cache)
        free((char *) cache);
    if (ccache != NULL)
        krb5_cc_close(ctx, ccache);
    krb5_free_cred_contents(ctx, &creds);
    if (keytab != NULL)
        krb5_kt_close(ctx, keytab);
    return code;
}


/*
 * Find the principal of the first entry of a keytab and return it as a string
 * in newly allocated memory.  The caller is responsible for freeing the
 * result with krb5_free_unparsed_name.  Exit on error.
 */
static char *
first_principal(krb5_context ctx, const char *path)
{
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code code;
    char *principal = NULL;

    code = krb5_kt_resolve(ctx, path, &keytab);
    if (code != 0)
        die_krb5(ctx, code, "error opening %s", path);
    code = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (code != 0)
        die_krb5(ctx, code, "error reading %s", path);
    code = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
    if (code == 0) {
        code = krb5_unparse_name(ctx, entry.principal, &principal);
        if (code != 0)
            die_krb5(ctx, code, "error unparsing name from %s", path);
        krb5_kt_free_entry(ctx, &entry);
    }
    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    krb5_kt_close(ctx, keytab);
    if (code == 0)
        return principal;
    else {
        die("no principal found in keytab file %s", path);
        return NULL;
    }
}


/*
 * Strips the cache prefix from the Kerberos ticket cache name if it's a
 * file-based cache.  Otherwise, dies with an error indicating that cache type
 * is not allowed with -o, -g, or -m options.
 */
static const char *
strip_cache_prefix(const char *cache)
{
    const char *p;

    if (strncmp(cache, "FILE:", strlen("FILE:")) == 0)
        return cache + strlen("FILE:");
    if (strncmp(cache, "WRFILE:", strlen("WRFILE:")) == 0)
        return cache += strlen("WRFILE:");
    for (p = cache; *p != '\0'; p++) {
        if (p > cache && *p == ':')
            die("cache type %.*s not allowed with -o, -g, or -m",
                (int) (p - cache), cache);
        else if (!isupper((unsigned char) *p))
            return cache;
    }
    return cache;
}


int
main(int argc, char *argv[])
{
    struct config config;
    struct k5start_private private;
    int opt;
    const char *inst = NULL;
    const char *sname = NULL;
    const char *sinst = NULL;
    const char *srealm = NULL;
    char *principal = NULL;
    bool nonforwardable = false;
    bool nonproxiable = false;
    int lifetime = DEFAULT_LIFETIME;
    krb5_error_code code;
    struct passwd *pw = NULL;
    struct group *gr;
    krb5_context ctx;
    krb5_deltat life_secs;
    bool run_as_daemon;
    bool search_keytab = false;
    static const char optstring[]
        = "abc:Ff:g:H:hI:i:K:k:Ll:m:no:Pp:qr:S:stUu:vx";

    /* Initialize logging. */
    message_program_name = "k5start";

    /* Set up confguration and parse command-line options. */
    memset(&config, 0, sizeof(config));
    memset(&private, 0, sizeof(private));
    config.private.k5start = &private;
    config.auth = authenticate;
    private.owner = (uid_t) -1;
    private.group = (gid_t) -1;
    while ((opt = getopt(argc, argv, optstring)) != EOF)
        switch (opt) {
        case 'a': config.always_renew = true;   break;
        case 'b': config.background = true;     break;
        case 'c': config.childfile = optarg;    break;
        case 'F': nonforwardable = true;        break;
        case 'h': usage(0);                     break;
        case 'I': sinst = optarg;               break;
        case 'i': inst = optarg;                break;
        case 'k': config.cache = optarg;        break;
        case 'n': /* Ignored */                 break;
        case 'P': nonproxiable = true;          break;
        case 'p': config.pidfile = optarg;      break;
        case 'q': private.quiet = true;         break;
        case 'r': srealm = optarg;              break;
        case 'S': sname = optarg;               break;
        case 't': config.do_aklog = true;       break;
        case 'v': config.verbose = true;        break;
        case 'U': search_keytab = true;         break;
        case 'u': principal = optarg;           break;
        case 'x': config.exit_errors = true;    break;

        case 'f':
            private.keytab = optarg;
            break;
        case 'g':
            private.group = convert_number(optarg, 10);
            if (private.group == (gid_t) -1) {
                gr = getgrnam(optarg);
                if (gr == NULL)
                    die("unknown group %s", optarg);
                private.group = gr->gr_gid;
            }
            private.set_perms = true;
            break;
        case 'H':
            config.happy_ticket = convert_number(optarg, 10);
            if (config.happy_ticket <= 0)
                die("-H limit argument %s invalid", optarg);
            break;
        case 'K':
            config.keep_ticket = convert_number(optarg, 10);
            if (config.keep_ticket <= 0)
                die("-K interval argument %s invalid", optarg);
            config.ignore_errors = true;
            break;
        case 'L':
            openlog(message_program_name, LOG_PID, LOG_DAEMON);
            message_handlers_notice(2, message_log_stdout,
                                    message_log_syslog_notice);
            message_handlers_warn(2, message_log_stderr,
                                  message_log_syslog_warning);
            message_handlers_die(2, message_log_stderr,
                                 message_log_syslog_err);
            break;
        case 'l':
            code = krb5_string_to_deltat(optarg, &life_secs);
            if (code != 0 || life_secs == 0)
                die("bad lifetime value %s, use 10h 10m format", optarg);
            lifetime = life_secs / 60;
            break;
        case 'm':
            private.mode = convert_number(optarg, 8);
            if (private.mode <= 0)
                die("-m mode argument %s invalid", optarg);
            private.set_perms = true;
            break;
        case 'o':
            private.owner = convert_number(optarg, 10);
            if (private.owner == (uid_t) -1) {
                pw = getpwnam(optarg);
                if (pw == NULL)
                    die("unknown user %s", optarg);
                private.owner = pw->pw_uid;
            }
            private.set_perms = true;
            break;
        case 's':
            private.stdin_passwd = true;
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
        config.command = argv;

    /* If -x was given, we still want to exit on initial auth failure. */
    if (config.exit_errors)
        config.ignore_errors = false;

    /*
     * If an owner was provided but no group, and the owner was given as a
     * username, set the group to the primary group of that user.
     */
    if (private.group == (gid_t) -1 && pw != NULL)
        private.group = pw->pw_gid;

    /* Check the arguments for consistency. */
    run_as_daemon = (config.keep_ticket != 0 || config.command != NULL);
    if (config.always_renew && run_as_daemon)
        die("-a only makes sense with -K or a command to run");
    if (config.background && private.keytab == NULL)
        die("-b option requires a keytab be specified with -f");
    if (config.background && run_as_daemon)
        die("-b only makes sense with -K or a command to run");
    if (config.keep_ticket > 0 && private.keytab == NULL)
        die("-K option requires a keytab be specified with -f");
    if (config.command != NULL && private.keytab == NULL)
        die("running a command requires a keytab be specified with -f");
    if (lifetime > 0 && config.keep_ticket > lifetime)
        die("-K limit %d must be smaller than lifetime %d",
            config.keep_ticket, lifetime);
    if (principal != NULL && strchr(principal, '/') != NULL && inst != NULL)
        die("instance specified in the principal and with -i");
    if (search_keytab && private.keytab == NULL)
        die("-U option requires a keytab be specified with -f");
    if (search_keytab && (principal != NULL || inst != NULL))
        die("-U option cannot be used with -u or -i options");
    if (config.happy_ticket > 0 && config.command != NULL)
        die("-H option cannot be used with a command");
    if (config.childfile != NULL && config.command == NULL)
        die("-c option only makes sense with a command to run");
    if (private.keytab != NULL && private.stdin_passwd)
        die("cannot use both -s and -f flags");

    /* Establish a Kerberos context. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        die_krb5(ctx, code, "error initializing Kerberos");

    /* If the -U option was given, figure out the principal from the keytab. */
    if (search_keytab)
        principal = first_principal(ctx, private.keytab);

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
    if (config.cache == NULL && config.command != NULL) {
        int fd;
        char *tmp, *cache;

        if (xasprintf(&tmp, "/tmp/krb5cc_%d_XXXXXX", (int) getuid()) < 0)
            die("cannot format ticket cache name");
        fd = mkstemp(tmp);
        if (fd < 0)
            sysdie("cannot create ticket cache file");
        if (fchmod(fd, 0600) < 0)
            sysdie("cannot chmod ticket cache file");
        if (xasprintf(&cache, "FILE:%s", tmp) < 0)
            die("cannot format ticket cache name");
        free(tmp);
        config.cache = cache;
        config.clean_cache = true;
    } else {
        krb5_ccache ccache;

        if (config.cache == NULL)
            code = krb5_cc_default(ctx, &ccache);
        else
            code = krb5_cc_resolve(ctx, config.cache, &ccache);
        if (code != 0)
            die_krb5(ctx, code, "error opening ticket cache");
        code = krb5_cc_get_full_name(ctx, ccache, (char **) &config.cache);
        if (code != 0)
            die_krb5(ctx, code, "error getting ticket cache name");
        krb5_cc_close(ctx, ccache);
    }
    if (setenv("KRB5CCNAME", config.cache, 1) != 0)
        die("cannot set KRB5CCNAME environment variable");
    if (private.set_perms)
        config.cache = strip_cache_prefix(config.cache);

    /*
     * If -K, -H, or -b were given, set quiet automatically unless verbose was
     * set.
     */
    if (config.keep_ticket > 0 || config.happy_ticket > 0 || config.background)
        if (!config.verbose)
            private.quiet = true;

    /*
     * The easiest thing for us is if the user just specifies the full
     * principal on the command line.  For backward compatibility, though,
     * support the -u and -i flags being used independently by tacking the
     * instance onto the end of the username.
     */
    if (inst != NULL)
        if (xasprintf(&principal, "%s/%s", principal, inst) < 0)
            die("cannot format principal name");
    code = krb5_parse_name(ctx, principal, &config.client);
    if (code != 0)
        die_krb5(ctx, code, "error parsing %s", principal);

    /*
     * Display the identity that we're obtaining Kerberos tickets for.  We do
     * this by unparsing the principal rather than using username and inst
     * since that way we get the default realm appended by the Kerberos
     * libraries.
     *
     * We intentionally don't use notice() here to avoid prepending k5start.
     */
    if (!private.quiet) {
        char *p;

        code = krb5_unparse_name(ctx, config.client, &p);
        if (code != 0)
            die_krb5(ctx, code, "error unparsing name %s", principal);
        printf("Kerberos initialization for %s", p);
        krb5_free_unparsed_name(ctx, p);
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
        srealm = krb5_principal_get_realm(ctx, config.client);
    if (srealm == NULL)
        die_krb5(ctx, code, "cannot get service ticket realm");
    if (sname == NULL)
        sname = "krbtgt";
    if (sinst == NULL)
        sinst = srealm;
    if (xasprintf(&private.service, "%s/%s@%s", sname, sinst, srealm) < 0)
        die("cannot format service principal name");
    code = krb5_build_principal(ctx, &private.ksprinc, strlen(srealm),
                                srealm, sname, sinst, (const char *) NULL);
    if (code != 0)
        die_krb5(ctx, code, "error creating service principal name");

    /* Figure out our ticket lifetime and initialize the options. */
    life_secs = lifetime * 60;
    code = krb5_get_init_creds_opt_alloc(ctx, &private.kopts);
    if (code != 0)
        die_krb5(ctx, code, "error allocating credential options");
    krb5_get_init_creds_opt_set_default_flags(ctx, "k5start",
                                              config.client->realm,
                                              private.kopts);
    krb5_get_init_creds_opt_set_tkt_life(private.kopts, life_secs);
    if (nonforwardable)
        krb5_get_init_creds_opt_set_forwardable(private.kopts, 0);
    if (nonproxiable)
        krb5_get_init_creds_opt_set_proxiable(private.kopts, 0);

    /* Do the actual work. */
    run_framework(ctx, &config);
}
