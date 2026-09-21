/**
 * @file    se_device_id.c
 * @brief   Generate/export ML-DSA-44 device identity in Secure NV
 */
#include "se_device_id.h"
#include "se_cert_spki.h"
#include "se_nv.h"
#include "se_tropic.h"
#include "se_tropic_port.h"
#include <string.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>

#define SE_DEVICE_ID_PUB_MAX SE_NV_OWNER_SPKI_MAX

static dilithium_key s_id_key;
static uint8_t s_id_der[SE_NV_SK_MAX];
static uint8_t s_id_pub[SE_DEVICE_ID_PUB_MAX];

static void id_wipe_key(void)
{
    wc_dilithium_free(&s_id_key);
    wc_ForceZero(s_id_der, sizeof(s_id_der));
    wc_ForceZero(s_id_pub, sizeof(s_id_pub));
}

static lt_ret_t id_load_sk(uint16_t *der_len)
{
    int rc;
    word32 idx = 0U;
    uint16_t n = 0U;
    lt_ret_t ret;

    ret = se_nv_get_device_sk(s_id_der, &n, (uint16_t)sizeof(s_id_der));
    if (ret != LT_OK) {
        return ret;
    }
    rc = wc_dilithium_init_ex(&s_id_key, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_dilithium_set_level(&s_id_key, WC_ML_DSA_44);
    }
    if (rc == 0) {
        rc = wc_Dilithium_PrivateKeyDecode(s_id_der, &idx, &s_id_key, n);
    }
    if (rc != 0) {
        id_wipe_key();
        return LT_CRYPTO_ERR;
    }
    if (der_len != NULL) {
        *der_len = n;
    }
    return LT_OK;
}

lt_ret_t se_device_id_ensure(void)
{
    WC_RNG rng;
    int rc;
    int der_sz;
    lt_ret_t ret;

    if (se_nv_has_device_sk() != 0) {
        return LT_OK;
    }

    (void)memset(&rng, 0, sizeof(rng));
    rc = wc_dilithium_init_ex(&s_id_key, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_dilithium_set_level(&s_id_key, WC_ML_DSA_44);
    }
    if (rc == 0) {
        rc = wc_InitRng(&rng);
    }
    if (rc == 0) {
        rc = wc_dilithium_make_key(&s_id_key, &rng);
    }
    der_sz = 0;
    if (rc == 0) {
        /* Priv-only DER does not set pubKeySet on decode; CLIENT CSR needs the pub. */
        der_sz = wc_Dilithium_KeyToDer(&s_id_key, s_id_der, (word32)sizeof(s_id_der));
        if (der_sz <= 0) {
            rc = der_sz;
        }
    }
    wc_FreeRng(&rng);
    if (rc != 0) {
        id_wipe_key();
        return LT_CRYPTO_ERR;
    }
    ret = se_nv_set_device_sk(s_id_der, (uint16_t)der_sz);
    id_wipe_key();
    if (ret != LT_OK) {
        return ret;
    }
    return LT_OK;
}

lt_ret_t se_device_id_export_pub(uint8_t *out, uint16_t *len, uint16_t cap)
{
    word32 pub_len = (word32)sizeof(s_id_pub);
    int rc;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    *len = 0U;
    ret = id_load_sk(NULL);
    if (ret != LT_OK) {
        return ret;
    }
    rc = wc_dilithium_export_public(&s_id_key, s_id_pub, &pub_len);
    if (rc != 0) {
        id_wipe_key();
        return LT_CRYPTO_ERR;
    }
    if (pub_len > (word32)cap) {
        id_wipe_key();
        return LT_PARAM_ERR;
    }
    (void)memcpy(out, s_id_pub, pub_len);
    *len = (uint16_t)pub_len;
    id_wipe_key();
    return LT_OK;
}

int se_device_id_cert_matches(const uint8_t *cert, uint16_t cert_len)
{
    const uint8_t *spki = NULL;
    uint32_t spki_len = 0U;
    uint8_t pub[SE_DEVICE_ID_PUB_MAX];
    uint16_t pub_len = 0U;
    int match;

    if ((cert == NULL) || (cert_len == 0U)) {
        return 0;
    }
    if (se_cert_spki_raw(cert, cert_len, &spki, &spki_len) != 0) {
        return 0;
    }
    if (se_device_id_export_pub(pub, &pub_len, (uint16_t)sizeof(pub)) != LT_OK) {
        return 0;
    }
    match = ((spki_len == (uint32_t)pub_len) && (memcmp(spki, pub, pub_len) == 0)) ? 1 : 0;
    wc_ForceZero(pub, sizeof(pub));
    return match;
}
