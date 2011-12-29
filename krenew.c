/*
 * Automatically renew a Kerberos ticket.
 *
 * Similar to k5start, krenew can run as a daemon or run a specified program
 * and wait until it completes.  Rather than obtaining fresh Kerberos
 * credentials, however, it uses an existing Kerberos ticket cache and tries
 * to renew the tickets until it exits or until the ticket cannot be renewed
 * any longer.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008, 2009, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <sys/stat.h>
#include <syslog.h>
#include <time.h>

#include <internal.h>
#include <util/concat.h>
#include <util/macros.h>
#include <util/messages.h>
#include <util/messages-krb5.h>
#include <util/xmalloc.h>

/* The usage message. */
const char usage_message[] = "\
Usage: krenew [options] [command]\n\
   -b                   Fork and run in the background\n\
   -c <file>            Write child process ID (PID) to <file>\n\
   -H <limit>           Check for a happy ticket, one that doesn't expire in\n\
                        less than <limit> minutes, and exit 0 if it's okay,\n\
                        otherwise renew the ticket\n\
   -h                   Display this usage message and exit\n\
   -K <interval>        Run as daemon, renew ticket every <interval> minutes\n\
   -k <file>            Use <file> as the ticket cache\n\
   -L                   Log messages via syslog as well as stderr\n\
   -p <file>            Write process ID (PID) to <file>\n\
   -t                   Get AFS token via aklog or AKLOG\n\
   -v                   Verbose\n\
\n\
If the environment variable AKLOG (or KINIT_PROG for backward compatibility)\n\
is set to a program (such as aklog) then this program will be executed when\n\
requested by the -t flag.  Otherwise, %s.\n";

/* Included in the usage message if AFS support is compiled in. */
const char usage_message_kafs[] = "\n\
When invoked with -t and a command, krenew will create a new AFS PAG for\n\
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
 * Given the Kerberos context and a pointer to the ticket cache, copy that
 * ticket cache to a new cache and return a newly allocated string for the
 * name of the cache.
 */
static char *
copy_cache(krb5_context ctx, krb5_ccache *cache)
{
    krb5_error_code status;
    krb5_ccache old, new;
    krb5_principal princ = NULL;
    char *name;
    int fd;

    if (xasprintf(&name, "/tmp/krb5cc_%d_XXXXXX", (int) getuid()) < 0)
        die("cannot format ticket cache name");
    fd = mkstemp(name);
    if (fd < 0)
        sysdie("cannot create ticket cache file");
    if (fchmod(fd, 0600) < 0)
        sysdie("cannot chmod ticket cache file");
    status = krb5_cc_resolve(ctx, name, &new);
    if (status != 0)
        die_krb5(ctx, status, "error initializing new ticket cache");
    old = *cache;
    status = krb5_cc_get_principal(ctx, old, &princ);
    if (status != 0)
        die_krb5(ctx, status, "error getting principal from old cache");
    status = krb5_cc_initialize(ctx, new, princ);
    if (status != 0)
        die_krb5(ctx, status, "error initializing new cache");
    krb5_free_principal(ctx, princ);
    status = krb5_cc_copy_cache(ctx, old, new);
    if (status != 0)
        die_krb5(ctx, status, "error copying credentials");
    status = krb5_cc_close(ctx, old);
    if (status != 0)
        die_krb5(ctx, status, "error closing old ticket cache");
    *cache = new;
    return name;
}


/*
 * Renew the user's tickets, warning if this isn't possible.  This is the
 * callback passed to the generic framework.  Takes the context, the
 * configuration, and a status code.  For the first authentication or on
 * SIGALRM, the status code will be 0; for other authentications, the status
 * code will be whatever is returned by ticket_expired, and therefore will be
 * KRB5KRB_AP_ERR_TKT_EXPIRED if the ticket needs to be renewed.  If the code
 * is KRB5KDC_ERR_KEY_EXP, that means we cannot renew the ticket for long
 * enough.
 *
 * Returns a Kerberos error code, which the framework chooses whether or not
 * to ignore.
 */
static krb5_error_code
renew(krb5_context ctx, struct config *config, krb5_error_code status)
{
    krb5_error_code code;
    krb5_principal user = NULL;
    krb5_creds creds;
    bool creds_valid = false;

    /*
     * If we can't read the cache, or if we can't renew tickets for long
     * enough, exit unless run with -i.
     */
    if (status != 0 && status != KRB5KRB_AP_ERR_TKT_EXPIRED) {
        if (status == KRB5KDC_ERR_KEY_EXP)
            warn("ticket cannot be renewed for long enough");
        if (!config->ignore_errors)
            exit_cleanup(ctx, config, 1);
        return status;
    }
    memset(&creds, 0, sizeof(creds));
    code = krb5_cc_get_principal(ctx, config->cache, &user);
    if (code != 0) {
        warn_krb5(ctx, code, "error reading cache");
        if (!config->ignore_errors)
            exit_cleanup(ctx, config, 1);
        return code;
    }
    if (config->verbose) {
        char *name;

        code = krb5_unparse_name(ctx, user, &name);
        if (code != 0)
            warn_krb5(ctx, code, "error unparsing name");
        else {
            notice("renewing credentials for %s", name);
            krb5_free_unparsed_name(ctx, name);
        }
    }

    /*
     * If we just can't renew or store tickets, we keep trying unless -x was
     * given, which means we return an error code and let the framework handle
     * it.
     */
    code = krb5_get_renewed_creds(ctx, &creds, user, config->cache, NULL);
    creds_valid = true;
    if (code != 0) {
        warn_krb5(ctx, code, "error renewing credentials");
        goto done;
    }
    
    /*
     * In theory, we don't want to reinitialize the cache and instead want to
     * just store the new credentials.  By reinitializing the cache, we create
     * a window where the credentials aren't valid.  However, I don't know how
     * to just store the renewed credentials without creating a cache that
     * grows forever.
     */
    code = krb5_cc_initialize(ctx, config->cache, user);
    if (code != 0) {
        warn_krb5(ctx, code, "error reinitializing cache");
        goto done;
    }
    code = krb5_cc_store_cred(ctx, config->cache, &creds);
    if (code != 0) {
        warn_krb5(ctx, code, "error storing credentials");
        goto done;
    }

done:
    if (user != NULL)
        krb5_free_principal(ctx, user);
    if (creds_valid)
        krb5_free_cred_contents(ctx, &creds);
    return code;
}


int
main(int argc, char *argv[])
{
    int option;
    char *cachename = NULL;
    krb5_context ctx;
    krb5_error_code code;
    struct config config;

    /* Initialize logging. */
    message_program_name = "krenew";

    /* Set up configuration and parse command-line options. */
    memset(&config, 0, sizeof(config));
    config.private.krenew = NULL;
    config.auth = renew;
    while ((option = getopt(argc, argv, "bc:H:hiK:k:Lp:qtv")) != EOF)
        switch (option) {
        case 'b': config.background = true;     break;
        case 'c': config.childfile = optarg;    break;
        case 'h': usage(0);                     break;
        case 'i': config.ignore_errors = true;  break;
        case 'p': config.pidfile = optarg;      break;
        case 't': config.do_aklog = true;       break;
        case 'v': config.verbose = true;        break;

        case 'H':
            config.happy_ticket = atoi(optarg);
            if (config.happy_ticket <= 0)
                die("-H limit argument %s out of range", optarg);
            break;
        case 'K':
            config.keep_ticket = atoi(optarg);
            if (config.keep_ticket <= 0)
                die("-K interval argument %s out of range", optarg);
            break;
        case 'k':
            cachename = concat("FILE:", optarg, (char *) 0);
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

        default:
            usage(1);
            break;
        }

    /* Parse arguments.  If any are given, they will be the command to run. */
    argc -= optind;
    argv += optind;
    if (argc > 0)
        config.command = argv;

    /* Check the arguments for consistency. */
    if (config.background && config.keep_ticket == 0 && config.command == NULL)
        die("-b only makes sense with -K or a command to run");
    if (config.happy_ticket > 0 && config.keep_ticket > 0)
        die("-H and -K options cannot be used at the same time");
    if (config.happy_ticket > 0 && config.command != NULL)
        die("-H option cannot be used with a command");
    if (config.childfile != NULL && config.command == NULL)
        die("-c option only makes sense with a command to run");

    /* Establish a Kerberos context and set the ticket cache. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        die_krb5(ctx, code, "error initializing Kerberos");
    if (cachename == NULL)
        code = krb5_cc_default(ctx, &config.cache);
    else
        code = krb5_cc_resolve(ctx, cachename, &config.cache);
    if (code != 0)
        die_krb5(ctx, code, "error initializing ticket cache");
    if (config.command != NULL) {
        cachename = copy_cache(ctx, &config.cache);
        config.clean_cache = true;
    }
    if (cachename != NULL)
        if (setenv("KRB5CCNAME", cachename, 1) != 0) {
            warn("cannot set KRB5CCNAME environment variable");
            exit_cleanup(ctx, &config, 1);
        }

    /* Do the actual work. */
    run_framework(ctx, &config);
}
