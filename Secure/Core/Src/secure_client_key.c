/**
 * @file    secure_client_key.c
 * @brief   Load ML-DSA client private key from NV into wolfSSL (Secure only)
 */
#include "secure_client_key.h"
#include "se_nv.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/memory.h"
#include <string.h>

int secure_client_key_load(WOLFSSL_CTX *ctx)
{
    static uint8_t der[SE_NV_SK_MAX];
    uint16_t derLen = 0U;
    int ret;

    if (ctx == NULL) {
        return -1;
    }

    ret = (int)se_nv_get_device_sk(der, &derLen, (uint16_t)sizeof(der));
    if (ret != LT_OK) {
        wc_ForceZero(der, sizeof(der));
        return -1;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, (long)derLen, WOLFSSL_FILETYPE_ASN1);
    wc_ForceZero(der, sizeof(der));
    return (ret == WOLFSSL_SUCCESS) ? 0 : -1;
}
