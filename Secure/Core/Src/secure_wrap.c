/**
 * @file    secure_wrap.c
 * @brief   AES-256-GCM wrap/unwrap of the device ML-DSA key (HKDF from dwk)
 */
#include "secure_client_key.h"
#include "se_nv.h"
#include "se_tropic_port.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <string.h>

#define SECURE_WRAP_VERSION   2u
#define SECURE_WRAP_NONCE_LEN 12u
#define SECURE_WRAP_TAG_LEN   16u
#define SECURE_WRAP_KEY_LEN   32u

static int secure_wrap_derive_key(byte *outKey, word32 outKeyLen)
{
    uint8_t dwk[SE_NV_DWK_LEN];
    int ret;

    if (se_tropic_port_dwk(dwk) != LT_OK) {
        return MEMORY_E;
    }
    ret = wc_HKDF(WC_SHA384, dwk, SE_NV_DWK_LEN, NULL, 0,
                  (const byte *)"SE_firmware_wrap_v2", 19U, outKey, outKeyLen);
    wc_ForceZero(dwk, sizeof(dwk));
    return ret;
}

int secure_wrap_wrap_client_key(const byte *der, word32 derLen, byte *out, word32 *outLen,
                                word32 outCap)
{
    Aes aes;
    byte key[SECURE_WRAP_KEY_LEN];
    byte nonce[SECURE_WRAP_NONCE_LEN];
    word32 need;
    int ret;

    if ((der == NULL) || (derLen == 0U) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }
    need = 1U + SECURE_WRAP_NONCE_LEN + derLen + SECURE_WRAP_TAG_LEN;
    if (need > outCap) {
        return BUFFER_E;
    }
    if (se_tropic_port_nv_random(nonce, sizeof(nonce)) != LT_OK) {
        return RNG_FAILURE_E;
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
        out[0] = (byte)SECURE_WRAP_VERSION;
        (void)memcpy(out + 1, nonce, SECURE_WRAP_NONCE_LEN);
        ret = wc_AesGcmEncrypt(&aes, out + 1U + SECURE_WRAP_NONCE_LEN, der, derLen, nonce,
                               SECURE_WRAP_NONCE_LEN, out + 1U + SECURE_WRAP_NONCE_LEN + derLen,
                               SECURE_WRAP_TAG_LEN, NULL, 0);
    }
    wc_AesFree(&aes);
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(nonce, sizeof(nonce));
    if (ret == 0) {
        *outLen = need;
    }
    return ret;
}

int secure_wrap_unwrap_buf(const byte *blob, word32 blobLen, byte *out, word32 *outLen,
                           word32 outCap)
{
    Aes aes;
    byte key[SECURE_WRAP_KEY_LEN];
    const byte *nonce;
    const byte *ct;
    const byte *tag;
    word32 ctLen;
    int ret;

    if ((blob == NULL) || (out == NULL) || (outLen == NULL) || (outCap == 0U)) {
        return BAD_FUNC_ARG;
    }
    if (blobLen < (1U + SECURE_WRAP_NONCE_LEN + SECURE_WRAP_TAG_LEN)) {
        return BAD_FUNC_ARG;
    }
    if (blob[0] != SECURE_WRAP_VERSION) {
        return BUFFER_E;
    }
    nonce = &blob[1];
    ctLen = blobLen - 1U - SECURE_WRAP_NONCE_LEN - SECURE_WRAP_TAG_LEN;
    ct = &blob[1U + SECURE_WRAP_NONCE_LEN];
    tag = &blob[blobLen - SECURE_WRAP_TAG_LEN];
    if ((ctLen == 0U) || (ctLen > outCap)) {
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
        ret = wc_AesGcmDecrypt(&aes, out, ct, ctLen, nonce, SECURE_WRAP_NONCE_LEN, tag,
                               SECURE_WRAP_TAG_LEN, NULL, 0);
    }
    wc_AesFree(&aes);
    wc_ForceZero(key, sizeof(key));
    if (ret == 0) {
        *outLen = ctLen;
    }
    return ret;
}

int secure_wrap_unwrap_client_key(byte *out, word32 *outLen, word32 outCap)
{
    uint8_t wrap[SE_NV_WRAP_MAX];
    uint16_t wlen = 0U;
    int ret;

    if (se_nv_get_wrap(wrap, &wlen, (uint16_t)sizeof(wrap)) != LT_OK) {
        return BAD_FUNC_ARG;
    }
    ret = secure_wrap_unwrap_buf(wrap, wlen, out, outLen, outCap);
    wc_ForceZero(wrap, sizeof(wrap));
    return ret;
}
