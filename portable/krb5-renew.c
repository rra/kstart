/*
 * Replacement for a missing krb5_get_renewed_creds.
 *
 * A replacement implementation of krb5_get_renewed_creds for older versions
 * of Heimdal.  This source will not compile with MIT Kerberos (krb5_kdc_flags
 * is Heimdal-specific), but MIT Kerberos has had this function for over a
 * decade.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <https://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006-2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>


/*
 * Obtain renewed credentials for the given service using the existing
 * credentials in the provided ticket cache.
 */
krb5_error_code
krb5_get_renewed_creds(krb5_context ctx, krb5_creds *creds,
                       krb5_const_principal client, krb5_ccache ccache,
                       const char *in_tkt_service)
{
    krb5_kdc_flags flags;
    krb5_creds in, *old = NULL, *out = NULL;
    krb5_error_code code;

    flags.i = 0;
    flags.b.renewable = 1;
    flags.b.renew = 1;
    memset(&in, 0, sizeof(in));
    code = krb5_copy_principal(ctx, client, &in.client);
    if (code != 0)
        goto done;
    if (in_tkt_service == NULL) {
        const char *realm;

        realm = krb5_principal_get_realm(ctx, client);
        if (realm == NULL) {
            code = KRB5_CONFIG_NODEFREALM;
            goto done;
        }
        code = krb5_build_principal(ctx, &in.server, strlen(realm), realm,
                                    "krbtgt", realm, (const char *) NULL);
        if (code != 0)
            goto done;
    } else {
        code = krb5_parse_name(ctx, in_tkt_service, &in.server);
        if (code != 0)
            goto done;
    }
    code = krb5_get_credentials(ctx, 0, ccache, &in, &old);
    if (code != 0)
        goto done;
    flags.b.forwardable = old->flags.b.forwardable;
    flags.b.proxiable = old->flags.b.proxiable;
    code = krb5_get_kdc_cred(ctx, ccache, flags, NULL, NULL, old, &out);
    if (code != 0)
        goto done;
#ifdef HAVE_KRB5_COPY_CREDS_CONTENTS
    code = krb5_copy_creds_contents(ctx, out, creds);
    krb5_free_creds(ctx, out);
#else
    /* No good alternative -- hope this works. */
    *creds = *out;
    free(out);
#endif

done:
    krb5_free_cred_contents(ctx, &in);
    if (old != NULL)
        krb5_free_creds(ctx, old);
    return code;
}
