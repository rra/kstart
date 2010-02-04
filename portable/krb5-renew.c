/*
 * Replacement for a missing krb5_get_renewed_creds.
 *
 * A replacement implementation of krb5_get_renewed_creds for older versions
 * of Heimdal.  This source will not compile with MIT Kerberos (krb5_kdc_flags
 * is Heimdal-specific), but MIT Kerberos has had this function for over a
 * decade.
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
        code = krb5_parse_name(context, in_tkt_service, &in.server);
        if (code != 0)
            goto done;
    }
    code = krb5_get_credentials(ctx, 0, cache, &in, &old);
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
