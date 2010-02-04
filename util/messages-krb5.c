/*
 * Error handling for Kerberos v5.
 *
 * Provides versions of die and warn that take a Kerberos context and a
 * Kerberos error code and append the Kerberos error message to the provided
 * formatted message.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <util/macros.h>
#include <util/messages.h>
#include <util/messages-krb5.h>
#include <util/xmalloc.h>


/*
 * Report a Kerberos error and exit.
 */
void
die_krb5(krb5_context ctx, krb5_error_code code, const char *format, ...)
{
    const char *k5_msg = NULL;
    char *message;
    va_list args;

    k5_msg = krb5_get_error_message(ctx, code);
    va_start(args, format);
    if (xvasprintf(&message, format, args) < 0)
        die("internal error: unable to format error message");
    va_end(args);
    die("%s: %s", message, k5_msg);
}


/*
 * Report a Kerberos error.
 */
void
warn_krb5(krb5_context ctx, krb5_error_code code, const char *format, ...)
{
    const char *k5_msg = NULL;
    char *message;
    va_list args;

    k5_msg = krb5_get_error_message(ctx, code);
    va_start(args, format);
    if (xvasprintf(&message, format, args) < 0)
        die("internal error: unable to format error message");
    va_end(args);
    warn("%s: %s", message, k5_msg);
    free(message);
    krb5_free_error_message(ctx, k5_msg);
}
