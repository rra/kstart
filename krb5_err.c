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

#include <stdarg.h>
#include <stdlib.h>

#include <krb5.h>
#if HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif

krb5_error_code
krb5_err(krb5_context context, int eval, krb5_error_code code,
         const char *format, ...)
{
    va_list args;

    va_start(args, format);
    com_err_va("k5start", code, format, args);
    va_end(args);
    exit(eval);
}

krb5_error_code
krb5_warn(krb5_context context, krb5_error_code code, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    com_err_va("k5start", code, format, args);
    va_end(args);
    return 0;
}
