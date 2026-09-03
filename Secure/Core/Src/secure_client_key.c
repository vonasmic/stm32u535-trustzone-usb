/**
 * @file    secure_client_key.c
 * @brief   Unwrap ML-DSA client private key into wolfSSL (Secure only)
 */
#include "secure_client_key.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <string.h>

int secure_client_key_load(WOLFSSL_CTX *ctx)
{
    static byte der[4096];
    word32 derLen = 0U;
    int ret;

    if (ctx == NULL) {
        return -1;
    }

    ret = secure_wrap_unwrap_client_key(der, &derLen, (word32)sizeof(der));
    if (ret != 0) {
        wc_ForceZero(der, sizeof(der));
        return ret;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, (long)derLen,
                                            WOLFSSL_FILETYPE_ASN1);
    wc_ForceZero(der, sizeof(der));
    return (ret == WOLFSSL_SUCCESS) ? 0 : -1;
}
