/**
 * @file    se_tls_user.c
 * @brief   Compare TLS peer leaf SPKI to the embedded home-PC user key
 */
#include "se_tls_user.h"
#include "se_cert_spki.h"
#include "fw_creds.h"

int se_tls_user_pin_peer(WOLFSSL *ssl)
{
    WOLFSSL_X509 *x509;
    const unsigned char *der;
    const uint8_t *spki;
    uint32_t spki_len;
    uint8_t diff;
    uint32_t i;
    int der_sz = 0;
    int rc;

    if (ssl == NULL) {
        return -1;
    }
    if (fw_user_spki_len == 0U) {
        return -1;
    }
    x509 = wolfSSL_get_peer_certificate(ssl);
    if (x509 == NULL) {
        return -1;
    }
    der = wolfSSL_X509_get_der(x509, &der_sz);
    if ((der == NULL) || (der_sz <= 0) ||
        (se_cert_spki_raw(der, (uint32_t)der_sz, &spki, &spki_len) != 0) ||
        (spki_len != fw_user_spki_len)) {
        wolfSSL_X509_free(x509);
        return -1;
    }
    diff = 0U;
    for (i = 0U; i < spki_len; i++) {
        diff = (uint8_t)(diff | (spki[i] ^ fw_user_spki[i]));
    }
    rc = (diff == 0U) ? 0 : -1;
    wolfSSL_X509_free(x509);
    return rc;
}
