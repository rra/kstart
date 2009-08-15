/*
 * Portability wrapper around krb.h.
 *
 * This header file includes krb.h, wherever it was found, and then adjusts
 * for various portability issues.
 */

#ifndef PORTABLE_KRB4_H
#define PORTABLE_KRB4_H 1

#include <config.h>
#include <portable/macros.h>

#ifdef HAVE_KERBEROSIV_KRB_H
# include <kerberosIV/krb.h>
#else
# include <krb.h>
#endif

/*
 * We default to a ten hour ticket lifetime if the Kerberos headers don't
 * provide a value.
 */
#ifndef DEFAULT_TKT_LIFE
# define DEFAULT_TKT_LIFE 120
#endif

BEGIN_DECLS

/* Default to a hidden visibility for all portability functions. */
#pragma GCC visibility push(hidden)

#if !HAVE_KRB_LIFE_TO_TIME
time_t krb_life_to_time(time_t, int);
int krb_time_to_life(KRB4_32, KRB4_32);
#endif

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PORTABLE_KRB5_H */
