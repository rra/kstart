/*  $Id$
**
**  Portability wrapper around <krb5.h>.
**
**  This header file includes krb5.h and then adjusts for various portability
**  issues, including defining krb5_err and krb5_warn if they're not provided
**  by the Kerberos implementation.
*/

#ifndef PORTABLE_KRB5_H
#define PORTABLE_KRB5_H 1

#include <config.h>
#include <system.h>

#include <krb5.h>

BEGIN_DECLS

#if !HAVE_KRB5_ERR
krb5_error_code krb5_err(krb5_context, int, krb5_error_code, const char *, ...)
    __attribute__((__format__(printf, 4, 5)));
krb5_error_code krb5_warn(krb5_context, krb5_error_code, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));
#endif

END_DECLS

#endif /* !PORTABLE_KRB5_H */
