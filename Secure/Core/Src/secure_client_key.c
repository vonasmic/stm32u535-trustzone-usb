/**
 * @file    secure_client_key.c
 * @brief   Regenerate ML-DSA-65 client key from the NV seed for wolfSSL (Secure only)
 */
#include "secure_client_key.h"
#include "se_device_id.h"
#include "se_ram.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/memory.h"
#include <string.h>

int secure_client_key_load(WOLFSSL_CTX *ctx)
{
    uint8_t *der;
    int derLen;
    int ret;

    if (ctx == NULL) {
        return -1;
    }

    der = (uint8_t *)se_mem_alloc(SE_DER_SCRATCH_SIZE, 0);
    if (der == NULL) {
        return -1;
    }
    derLen = se_device_id_export_private_der(der, SE_DER_SCRATCH_SIZE);
    if (derLen <= 0) {
        wc_ForceZero(der, SE_DER_SCRATCH_SIZE);
        se_mem_free(der);
        return -1;
    }

    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, (long)derLen, WOLFSSL_FILETYPE_ASN1);
    wc_ForceZero(der, SE_DER_SCRATCH_SIZE);
    se_mem_free(der);
    return (ret == WOLFSSL_SUCCESS) ? 0 : -1;
}
