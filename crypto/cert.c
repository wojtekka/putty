/*
 * OpenSSH certificates
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "ssh.h"

// XXX there must be a better way to do this, right?
static strbuf *get_strbuf(BinarySource *src)
{
    strbuf *res = strbuf_new();
    put_datapl(res, get_string(src));
    return res;
}

ssh_cert *ssh_cert_new(const char *ssh_id, ptrlen nonce)
{
    ssh_cert *cert = snew(ssh_cert);
    cert->nonce = strbuf_new();
    put_datapl(cert->nonce, nonce);
    cert->serial = 0;
    cert->type = 0;
    cert->key_id = NULL;
    cert->valid_principals = NULL;
    cert->valid_after = 0xffffffffffffffffULL;
    cert->valid_before = 0;
    cert->critical_options = NULL;
    cert->extensions = NULL;
    cert->reserved = NULL;
    cert->signature_key = NULL;
    cert->signature = NULL;
}

void ssh_cert_get(ssh_cert *cert, BinarySource *src)
{
    cert->serial = get_uint64(src);
    cert->type = get_uint32(src);
    cert->key_id = get_strbuf(src);
    cert->valid_principals = get_strbuf(src);
    cert->valid_after = get_uint64(src);
    cert->valid_before = get_uint64(src);
    cert->critical_options = get_strbuf(src);
    cert->extensions = get_strbuf(src);
    cert->reserved = get_strbuf(src);
    cert->signature_key = get_strbuf(src);
    cert->signature = get_strbuf(src);
}

void ssh_cert_free(ssh_cert *cert)
{
    if (cert->nonce != NULL) {
        strbuf_free(cert->nonce);
        cert->nonce = NULL;
    }
    if (cert->key_id != NULL) {
        strbuf_free(cert->key_id);
        cert->key_id = NULL;
    }
    if (cert->valid_principals != NULL) {
        strbuf_free(cert->valid_principals);
        cert->valid_principals = NULL;
    }
    if (cert->critical_options != NULL) {
        strbuf_free(cert->critical_options);
        cert->critical_options = NULL;
    }
    if (cert->extensions != NULL) {
        strbuf_free(cert->extensions);
        cert->extensions = NULL;
    }
    if (cert->reserved != NULL) {
        strbuf_free(cert->reserved);
        cert->reserved = NULL;
    }
    if (cert->signature_key != NULL) {
        strbuf_free(cert->signature_key);
        cert->signature_key = NULL;
    }
    if (cert->signature != NULL) {
        strbuf_free(cert->signature);
        cert->signature = NULL;
    }
    sfree(cert);
}
