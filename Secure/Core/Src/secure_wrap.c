/**
 * @file    secure_wrap.c
 * @brief   U535 software AES-256-GCM unwrap (DWK + chip UID HKDF)
 */
#include "secure_wrap.h"
#include "wrapped_client_key.h"
#include "stm32u5xx_hal.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <string.h>

#define SECURE_WRAP_VERSION   1u
#define SECURE_WRAP_NONCE_LEN 12u
#define SECURE_WRAP_TAG_LEN   16u
#define SECURE_WRAP_KEY_LEN   32u
#define SECURE_WRAP_DEV_ZERO_UID 1

static int secure_wrap_derive_key(byte *outKey, word32 outKeyLen)
{
    byte salt[12];

#if SECURE_WRAP_DEV_ZERO_UID
    (void)memset(salt, 0, sizeof(salt));
#else
    salt[0]  = (byte)(HAL_GetUIDw0() & 0xFFU);
    salt[1]  = (byte)((HAL_GetUIDw0() >> 8) & 0xFFU);
    salt[2]  = (byte)((HAL_GetUIDw0() >> 16) & 0xFFU);
    salt[3]  = (byte)((HAL_GetUIDw0() >> 24) & 0xFFU);
    salt[4]  = (byte)(HAL_GetUIDw1() & 0xFFU);
    salt[5]  = (byte)((HAL_GetUIDw1() >> 8) & 0xFFU);
    salt[6]  = (byte)((HAL_GetUIDw1() >> 16) & 0xFFU);
    salt[7]  = (byte)((HAL_GetUIDw1() >> 24) & 0xFFU);
    salt[8]  = (byte)(HAL_GetUIDw2() & 0xFFU);
    salt[9]  = (byte)((HAL_GetUIDw2() >> 8) & 0xFFU);
    salt[10] = (byte)((HAL_GetUIDw2() >> 16) & 0xFFU);
    salt[11] = (byte)((HAL_GetUIDw2() >> 24) & 0xFFU);
#endif

    return wc_HKDF(WC_SHA256, secure_dwk, secure_dwk_len, salt, (word32)sizeof(salt),
                   (const byte *)"SE_firmware_wrap_v1", 19U, outKey, outKeyLen);
}

int secure_wrap_unwrap_client_key(byte *out, word32 *outLen, word32 outCap)
{
    Aes aes;
    byte key[SECURE_WRAP_KEY_LEN];
    const byte *nonce;
    const byte *ct;
    const byte *tag;
    word32 ctLen;
    int ret;

    if (out == NULL || outLen == NULL || outCap == 0U) {
        return BAD_FUNC_ARG;
    }
    if (secure_wrapped_client_key_len < (1U + SECURE_WRAP_NONCE_LEN + SECURE_WRAP_TAG_LEN)) {
        return BAD_FUNC_ARG;
    }
    if (secure_wrapped_client_key[0] != SECURE_WRAP_VERSION) {
        return BUFFER_E;
    }

    nonce = &secure_wrapped_client_key[1];
    ctLen = secure_wrapped_client_key_len - 1U - SECURE_WRAP_NONCE_LEN - SECURE_WRAP_TAG_LEN;
    ct = &secure_wrapped_client_key[1U + SECURE_WRAP_NONCE_LEN];
    tag = &secure_wrapped_client_key[secure_wrapped_client_key_len - SECURE_WRAP_TAG_LEN];

    if (ctLen == 0U || ctLen > outCap) {
        return BUFFER_E;
    }

    ret = secure_wrap_derive_key(key, sizeof(key));
    if (ret != 0) {
        wc_ForceZero(key, sizeof(key));
        return ret;
    }

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, sizeof(key));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, out, ct, ctLen, nonce, SECURE_WRAP_NONCE_LEN,
                               tag, SECURE_WRAP_TAG_LEN, NULL, 0);
    }
    wc_AesFree(&aes);
    wc_ForceZero(key, sizeof(key));

    if (ret == 0) {
        *outLen = ctLen;
    }
    return ret;
}
