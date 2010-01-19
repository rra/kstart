/*
 * Prototypes for error handling for Kerberos.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008, 2009, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#ifndef UTIL_MESSAGES_KRB5_H
#define UTIL_MESSAGES_KRB5_H 1

#include <config.h>
#include <portable/macros.h>

#include <krb5.h>
#include <sys/types.h>

BEGIN_DECLS

/* Default to a hidden visibility for all util functions. */
#pragma GCC visibility push(hidden)

/*
 * The Kerberos versions of the reporting functions.  These take a context and
 * an error code to get the Kerberos error.
 */
void die_krb5(krb5_context, krb5_error_code, const char *, ...)
    __attribute__((__nonnull__, __noreturn__, __format__(printf, 3, 4)));
void warn_krb5(krb5_context, krb5_error_code, const char *, ...)
    __attribute__((__nonnull__, __format__(printf, 3, 4)));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* UTIL_MESSAGES_KRB5_H */
