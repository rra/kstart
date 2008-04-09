/* $Id$
 *
 * Error handling for Kerberos v5.
 *
 * Provides versions of die and warn that take a Kerberos context and a
 * Kerberos error code and append the Kerberos error message to the provided
 * formatted message.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <krb5.h>
#if !defined(HAVE_KRB5_GET_ERROR_MESSAGE) && !defined(HAVE_KRB5_GET_ERR_TEXT)
# if defined(HAVE_IBM_SVC_KRB5_SVC_H)
#  include <ibm_svc/krb5_svc.h>
# elif defined(HAVE_ET_COM_ERR_H)
#  include <et/com_err.h>
# else
#  include <com_err.h>
# endif
#endif

#include <util/util.h>

/*
 * This string is returned for unknown error messages.  We use a static
 * variable so that we can be sure not to free it.
 */
static const char error_unknown[] = "unknown error";


/*
 * Given a Kerberos error code, return the corresponding error.  Prefer the
 * Kerberos interface if available since it will provide context-specific
 * error information, whereas the error_message() call will only provide a
 * fixed message.
 */
static const char *
get_error(krb5_context ctx UNUSED, krb5_error_code code)
{
    const char *msg = NULL;

#if defined(HAVE_KRB5_GET_ERROR_MESSAGE)
    msg = krb5_get_error_message(ctx, code);
#elif defined(HAVE_KRB5_GET_ERR_TEXT)
    msg = krb5_get_err_text(ctx, code);
#elif defined(HAVE_KRB5_SVC_GET_MSG)
    krb5_svc_get_msg(code, &msg);
#else
    msg = error_message(code);
#endif
    if (msg == NULL)
        return error_unknown;
    else
        return msg;
}


/*
 * Free an error string if necessary.
 */
static void
free_error(krb5_context ctx UNUSED, const char *msg)
{
    if (msg == error_unknown)
        return;
#if defined(HAVE_KRB5_FREE_ERROR_MESSAGE)
    krb5_free_error_message(ctx, msg);
#elif defined(HAVE_KRB5_SVC_GET_MSG)
    krb5_free_string((char *) msg);
#endif
}


/*
 * Report a Kerberos error and exit.
 */
void
die_krb5(krb5_context ctx, krb5_error_code code, const char *format, ...)
{
    const char *k5_msg = NULL;
    char *message;
    va_list args;

    k5_msg = get_error(ctx, code);
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

    k5_msg = get_error(ctx, code);
    va_start(args, format);
    if (xvasprintf(&message, format, args) < 0)
        die("internal error: unable to format error message");
    va_end(args);
    warn("%s: %s", message, k5_msg);
    free(message);
    free_error(ctx, k5_msg);
}
