/**
 * @file    se_creds.h
 * @brief   Runtime SAE CA + device client cert (Secure flash page 21)
 */
#ifndef SE_CREDS_H
#define SE_CREDS_H

#include <stdint.h>
#include "libtropic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SE_CREDS_DER_MAX 4000u

int se_creds_has_sae_ca(void);
int se_creds_has_device_cert(void);
lt_ret_t se_creds_get_sae_ca(uint8_t *out, uint16_t *len, uint16_t cap);
lt_ret_t se_creds_get_device_cert(uint8_t *out, uint16_t *len, uint16_t cap);
lt_ret_t se_creds_set_sae_ca(const uint8_t *der, uint16_t len);
lt_ret_t se_creds_set_device_cert(const uint8_t *der, uint16_t len);
lt_ret_t se_creds_clear(void);

/** 1 when owner + device cert + wrapped SK are present (ENCRYPT/DECRYPT). */
int se_ready_encrypt(void);
/** 1 when encrypt-ready plus SAE CA and ML-KEM pk (PROVISION). */
int se_ready_provision(void);

#ifdef __cplusplus
}
#endif

#endif /* SE_CREDS_H */
