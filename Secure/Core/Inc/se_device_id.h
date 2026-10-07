/**
 * @file    se_device_id.h
 * @brief   On-device ML-DSA-44 identity (never imported over USB)
 */
#ifndef SE_DEVICE_ID_H
#define SE_DEVICE_ID_H

#include <stdint.h>
#include "libtropic.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generate ML-DSA-44 in NV if no device SK is present. */
lt_ret_t se_device_id_ensure(void);

/** Copy raw ML-DSA-44 public key. LT_FAIL when SK is missing. */
lt_ret_t se_device_id_export_pub(uint8_t *out, uint16_t *len, uint16_t cap);

/**
 * Public key in the existing device buffer. Valid until se_device_id_close_pub.
 * LT_FAIL when SK is missing.
 */
lt_ret_t se_device_id_open_pub(const uint8_t **pub, uint16_t *len);
void se_device_id_close_pub(void);

/** 1 when cert BIT STRING matches the on-device ML-DSA public key. */
int se_device_id_cert_matches(const uint8_t *cert, uint16_t cert_len);

#ifdef __cplusplus
}
#endif

#endif /* SE_DEVICE_ID_H */
