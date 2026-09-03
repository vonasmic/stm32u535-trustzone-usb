/**
 * @file    se_cert_spki.h
 * @brief   Extract raw SubjectPublicKeyInfo BIT STRING payload from an X.509 DER cert
 */
#ifndef SE_CERT_SPKI_H
#define SE_CERT_SPKI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Point @p out at the raw public-key bits inside @p der (no copy).
 * @return 0 on success
 */
int se_cert_spki_raw(const uint8_t *der, uint32_t der_len, const uint8_t **out,
                     uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SE_CERT_SPKI_H */
