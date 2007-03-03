/*  $Id$
**
**  Compatibility krb5_err function for MIT Kerberos.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  This work is hereby placed in the public domain by its author.
**
**  Provides krb5_err and krb5_warn (a Heimdal function) for MIT Kerberos,
**  implemented in terms of com_err.  These functions are used by preference
**  where available since the API is nicer to deal with and since otherwise
**  getting good error reporting on Heimdal is annoying.
*/

#include <config.h>
#include <system.h>

#include <krb5.h>

#ifndef KRB5_GET_ERROR_MESSAGE
# if HAVE_ET_COM_ERR_H
#  include <et/com_err.h>
# else
#  include <com_err.h>
# endif
# define krb5_get_error_message(c, s)  (char *) error_message(s)
# define krb5_free_error_message(c, m) /* empty */
#endif

extern krb5_error_code krb5_err(krb5_context, int, krb5_error_code,
                                const char *, ...)
    __attribute__((__format__(printf, 4, 5)));
extern krb5_error_code krb5_warn(krb5_context, krb5_error_code,
                                 const char *, ...)
    __attribute__((__format__(printf, 3, 4)));

krb5_error_code
krb5_err(krb5_context context UNUSED, int eval, krb5_error_code code,
         const char *format, ...)
{
    va_list args;
    char *message;

    message = krb5_get_error_message(context, code);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, ": %s\n", message);
    krb5_free_error_message(context, message);
    exit(eval);
}

krb5_error_code
krb5_warn(krb5_context context UNUSED, krb5_error_code code,
          const char *format, ...)
{
    va_list args;
    char *message;

    message = krb5_get_error_message(context, code);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, ": %s\n", message);
    krb5_free_error_message(context, message);
    return 0;
}
