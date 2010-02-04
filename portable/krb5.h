/*
 * Portability wrapper around krb5.h.
 *
 * This header includes krb5.h and then adjusts for various portability
 * issues, primarily between MIT Kerberos and Heimdal, so that code can be
 * written to a consistent API.
 *
 * Unfortunately, due to the nature of the differences between MIT Kerberos
 * and Heimdal, it's not possible to write code to either one of the APIs and
 * adjust for the other one.  In general, this header tries to make available
 * the Heimdal API and fix it for MIT Kerberos, but there are places where MIT
 * Kerberos requires a more specific call.  For those cases, it provides the
 * most specific interface.
 *
 * For example, MIT Kerberos has krb5_free_unparsed_name() whereas Heimdal
 * prefers the generic krb5_xfree().  In this case, this header provides
 * krb5_free_unparsed_name() for both APIs since it's the most specific call.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * This work is hereby placed in the public domain by its author.
 */

#ifndef PORTABLE_KRB5_H
#define PORTABLE_KRB5_H 1

#include <config.h>
#include <portable/macros.h>

#include <krb5.h>

BEGIN_DECLS

/* Default to a hidden visibility for all portability functions. */
#pragma GCC visibility push(hidden)

/* Heimdal: krb5_cc_copy_cache, MIT: krb5_cc_copy_creds. */
#ifndef HAVE_KRB5_CC_COPY_CACHE
# define krb5_cc_copy_cache(c, o, n) krb5_cc_copy_creds((c), (o), (n))
#endif

/* Heimdal: krb5_xfree, MIT: krb5_free_unparsed_name. */
#ifdef HAVE_KRB5_XFREE
# define krb5_free_unparsed_name(c, p) krb5_xfree(p)
#endif

/*
 * krb5_{get,free}_error_message are the preferred APIs for both current MIT
 * and current Heimdal, but there are tons of older APIs we may have to fall
 * back on for earlier versions.
 *
 * This function should be called immediately after the corresponding error
 * without any intervening Kerberos calls.  Otherwise, the correct error
 * message and supporting information may not be returned.
 */
#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
const char *krb5_get_error_message(krb5_context, krb5_error_code);
#endif
#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
void krb5_free_error_message(krb5_context, const char *);
#endif

/*
 * Both current MIT and current Heimdal prefer _opt_alloc, but older versions
 * of both require allocating your own struct and calling _opt_init.
 */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
krb5_error_code krb5_get_init_creds_opt_alloc(krb5_context,
                                              krb5_get_init_creds_opt **);
#endif

/* Heimdal-specific. */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS
#define krb5_get_init_creds_opt_set_default_flags(c, p, r, o) /* empty */
#endif

/* Available in current MIT and Heimdal, but not older versions of Heimdal. */
#ifndef HAVE_KRB5_GET_RENEWED_CREDS
krb5_error_code krb5_get_renewed_creds(krb5_context, krb5_creds *,
                                       krb5_const_principal, krb5_ccache,
                                       const char *);
#endif

/* Heimdal: krb5_kt_free_entry, MIT: krb5_free_keytab_entry_contents. */
#ifndef HAVE_KRB5_KT_FREE_ENTRY
# define krb5_kt_free_entry(c, e) krb5_free_keytab_entry_contents((c), (e))
#endif

/*
 * Heimdal provides a nice function that just returns a const char *.  On MIT,
 * there's an accessor macro that returns the krb5_data pointer, wihch
 * requires more work to get at the underlying char *.
 */
#ifndef HAVE_KRB5_PRINCIPAL_GET_REALM
const char *krb5_principal_get_realm(krb5_context, krb5_const_principal);
#endif

/* Undo default visibility change. */
#pragma GCC visibility pop

#endif /* !PORTABLE_KRB5_H */
