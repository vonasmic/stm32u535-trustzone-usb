/**
 * @file    se_tropic_mlkem.c
 * @brief   ML-KEM-768 provisioning, public-key export, PIN-gated decapsulation
 */
#include "se_tropic_mlkem.h"
#include "se_tropic.h"
#include "se_tropic_pin.h"
#include "se_tropic_port.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

static const uint8_t k_mlkem_kek_info[] = "SE_tropic_mlkem_kek_v4";
static const uint8_t k_seed_aad[] = "SE_tropic_mlkem_seed_v2";

/* Large key material lives in BSS, not on the USB/TLS task stack. */
static MlKemKey s_mlkem;
static uint8_t s_mlkem_open;
static uint8_t s_pk_cache[SE_TROPIC_MLKEM_PK_LEN];
static uint8_t s_pk_cache_valid;

static lt_ret_t mlkem_derive_kek(const uint8_t final_key[SE_TROPIC_PIN_HMAC_LEN], uint8_t kek[32])
{
    uint8_t dwk[32];
    int ret;
    lt_ret_t lret;

    lret = se_tropic_port_device_aead_key(dwk);
    if (lret != LT_OK) {
        return lret;
    }
    ret = wc_HKDF(WC_SHA384, final_key, SE_TROPIC_PIN_HMAC_LEN, dwk, 32U, k_mlkem_kek_info,
                  (word32)(sizeof(k_mlkem_kek_info) - 1U), kek, 32U);
    wc_ForceZero(dwk, sizeof(dwk));
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

static lt_ret_t mlkem_wrap_seed(lt_handle_t *h, const uint8_t kek[32], const uint8_t seed[64])
{
    return se_tropic_encrypt_and_write_to_rmem(h, SE_TROPIC_MLKEM_SEED_SLOT, kek, k_seed_aad,
                                    (uint16_t)(sizeof(k_seed_aad) - 1U), seed,
                                    SE_TROPIC_MLKEM_SEED_LEN);
}

static lt_ret_t mlkem_unwrap_seed(lt_handle_t *h, const uint8_t kek[32], uint8_t seed[64])
{
    uint16_t got = 0U;
    lt_ret_t ret;

    ret = se_tropic_read_and_decrypt_from_rmem(h, SE_TROPIC_MLKEM_SEED_SLOT, kek, k_seed_aad,
                                    (uint16_t)(sizeof(k_seed_aad) - 1U), seed,
                                    SE_TROPIC_MLKEM_SEED_LEN, &got);
    if (ret != LT_OK) {
        return ret;
    }
    return (got == SE_TROPIC_MLKEM_SEED_LEN) ? LT_OK : LT_FAIL;
}

lt_ret_t se_tropic_mlkem_seed_occupied(lt_handle_t *h, uint32_t *occupied)
{
    uint8_t probe[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t got = 0U;
    lt_ret_t ret;

    if ((h == NULL) || (occupied == NULL)) {
        return LT_PARAM_ERR;
    }

    ret = lt_r_mem_data_read(h, SE_TROPIC_MLKEM_SEED_SLOT, probe, sizeof(probe), &got);
    if (ret == LT_L3_R_MEM_DATA_READ_SLOT_EMPTY) {
        *occupied = 0U;
        return LT_OK;
    }
    if (ret == LT_OK) {
        *occupied = (got > 0U) ? 1U : 0U;
        return LT_OK;
    }
    *occupied = 1U;
    return LT_OK;
}

static lt_ret_t mlkem_make_key_from_seed(const uint8_t seed[64], uint8_t *pk_out,
                                         uint16_t pk_max, uint16_t *pk_len)
{
    int ret;

    if ((pk_out == NULL) || (pk_len == NULL) || (pk_max < SE_TROPIC_MLKEM_PK_LEN)) {
        return LT_PARAM_ERR;
    }

    ret = wc_MlKemKey_Init(&s_mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        return LT_CRYPTO_ERR;
    }

    ret = wc_MlKemKey_MakeKeyWithRandom(&s_mlkem, seed, WC_ML_KEM_MAKEKEY_RAND_SZ);
    if (ret != 0) {
        wc_MlKemKey_Free(&s_mlkem);
        return LT_CRYPTO_ERR;
    }

    ret = wc_MlKemKey_EncodePublicKey(&s_mlkem, pk_out, SE_TROPIC_MLKEM_PK_LEN);
    if (ret != 0) {
        wc_MlKemKey_Free(&s_mlkem);
        return LT_CRYPTO_ERR;
    }

    *pk_len = SE_TROPIC_MLKEM_PK_LEN;
    s_mlkem_open = 1U;
    return LT_OK;
}

static lt_ret_t mlkem_check_pk(const uint8_t *pk, uint16_t pk_len)
{
    const uint8_t *emb = se_tropic_port_mlkem_pk();
    unsigned int emb_len = se_tropic_port_mlkem_pk_len();

    if (emb_len == 0U) {
        return LT_OK;
    }
    if ((pk_len != SE_TROPIC_MLKEM_PK_LEN) || (emb_len != SE_TROPIC_MLKEM_PK_LEN) ||
        (emb == NULL)) {
        return LT_FAIL;
    }
    if (memcmp(pk, emb, SE_TROPIC_MLKEM_PK_LEN) != 0) {
        se_tropic_log("ML-KEM pk mismatch vs NV");
        return LT_FAIL;
    }
    return LT_OK;
}

lt_ret_t se_tropic_mlkem_provision(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                   const uint8_t *add, uint8_t add_len, uint8_t *pk_out,
                                   uint16_t pk_max, uint16_t *pk_len)
{
    uint8_t master[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t seed[SE_TROPIC_MLKEM_SEED_LEN];
    uint8_t final_key[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t kek[32];
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint16_t got = 0U;
    uint32_t occ = 0U;
    lt_ret_t ret;

    if ((h == NULL) || (pin == NULL) || (pk_out == NULL) || (pk_len == NULL)) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_mlkem_seed_occupied(h, &occ);
    if ((ret == LT_OK) && (occ != 0U)) {
        se_tropic_log("KEM INIT refused: slot 510 occupied");
        return LT_FAIL;
    }

    ret = lt_random_value_get(h, master, sizeof(master));
    if (ret == LT_OK) {
        ret = lt_random_value_get(h, seed, sizeof(seed));
    }
    if (ret != LT_OK) {
        goto exit;
    }

    ret = se_tropic_pin_setup(h, master, pin, pin_len, add, add_len, final_key);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = mlkem_derive_kek(final_key, kek);
    if (ret == LT_OK) {
        ret = mlkem_make_key_from_seed(seed, pk, sizeof(pk), &got);
    }
    if (ret == LT_OK) {
        ret = mlkem_wrap_seed(h, kek, seed);
    }
    if (ret == LT_OK) {
        (void)memcpy(pk_out, pk, SE_TROPIC_MLKEM_PK_LEN);
        *pk_len = SE_TROPIC_MLKEM_PK_LEN;
        (void)memcpy(s_pk_cache, pk, SE_TROPIC_MLKEM_PK_LEN);
        s_pk_cache_valid = 1U;
        (void)se_nv_set_mlkem_pk(pk, SE_TROPIC_MLKEM_PK_LEN);
        se_tropic_mlkem_key_close();
    }

exit:
    wc_ForceZero(master, sizeof(master));
    wc_ForceZero(seed, sizeof(seed));
    wc_ForceZero(final_key, sizeof(final_key));
    wc_ForceZero(kek, sizeof(kek));
    wc_ForceZero(pk, sizeof(pk));
    return ret;
}

uint32_t se_tropic_mlkem_pub_read(uint8_t *pk, uint16_t pk_max, uint16_t *pk_len)
{
    const uint8_t *emb = se_tropic_port_mlkem_pk();
    unsigned int emb_len = se_tropic_port_mlkem_pk_len();

    if ((pk == NULL) || (pk_len == NULL) || (pk_max < SE_TROPIC_MLKEM_PK_LEN)) {
        return SE_TROPIC_ERR;
    }

    if ((emb != NULL) && (emb_len == SE_TROPIC_MLKEM_PK_LEN)) {
        (void)memcpy(pk, emb, SE_TROPIC_MLKEM_PK_LEN);
        *pk_len = SE_TROPIC_MLKEM_PK_LEN;
        return SE_TROPIC_OK;
    }
    if (s_pk_cache_valid != 0U) {
        (void)memcpy(pk, s_pk_cache, SE_TROPIC_MLKEM_PK_LEN);
        *pk_len = SE_TROPIC_MLKEM_PK_LEN;
        return SE_TROPIC_OK;
    }

    return SE_TROPIC_NOT_READY;
}

uint32_t se_tropic_mlkem_pub_recover(const uint8_t *pin, uint8_t pin_len, const uint8_t *add,
                                     uint8_t add_len)
{
    lt_handle_t *h;
    lt_ret_t ret;

    if ((pin == NULL) || (pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
        return SE_TROPIC_ERR;
    }
    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return SE_TROPIC_ERR;
    }

    ret = se_tropic_mlkem_key_open(h, pin, pin_len, add, add_len);
    se_tropic_mlkem_key_close();
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return SE_TROPIC_TAMPERED;
    }
    if (ret != LT_OK) {
        return SE_TROPIC_ERR;
    }
    return SE_TROPIC_OK;
}

uint32_t se_tropic_kem_init_probe(void)
{
    lt_handle_t *h;
    uint32_t occ = 0U;
    lt_ret_t ret;

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return SE_TROPIC_ERR;
    }

    ret = se_tropic_mlkem_seed_occupied(h, &occ);
    if (ret != LT_OK) {
        return SE_TROPIC_ERR;
    }
    if (occ != 0U) {
        se_tropic_log("KEM INIT refused: slot 510 occupied");
        return SE_TROPIC_SLOT_OCC;
    }
    se_tropic_log("slot 510 empty");
    return SE_TROPIC_OK;
}

uint32_t se_tropic_kem_init_confirm(const uint8_t *pin, uint8_t pin_len, const uint8_t *add,
                                    uint8_t add_len)
{
    lt_handle_t *h;
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint16_t pk_len = 0U;
    lt_ret_t ret;

    if ((pin == NULL) || (pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
        return SE_TROPIC_ERR;
    }
    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return SE_TROPIC_ERR;
    }

    ret = se_tropic_mlkem_provision(h, pin, pin_len, add, add_len, pk, sizeof(pk), &pk_len);
    if (ret != LT_OK) {
        se_tropic_log("KEM INIT fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    se_tropic_log("KEM INIT ok; ML-KEM pk stored in NV");
    se_tropic_log("TROPIC KEM pub:");
    se_tropic_log_hex(NULL, pk, pk_len);
    return SE_TROPIC_OK;
}

uint32_t se_tropic_kem_pub_dump(void)
{
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint16_t pk_len = 0U;
    uint32_t st;

    st = se_tropic_mlkem_pub_read(pk, sizeof(pk), &pk_len);
    if (st != SE_TROPIC_OK) {
        se_tropic_log("ML-KEM pk missing (run TROPIC KEM INIT)");
        return st;
    }
    se_tropic_log("TROPIC KEM pub:");
    se_tropic_log_hex(NULL, pk, pk_len);
    return SE_TROPIC_OK;
}

lt_ret_t se_tropic_mlkem_key_open(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                  const uint8_t *add, uint8_t add_len)
{
    uint8_t final_key[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t kek[32];
    uint8_t seed[SE_TROPIC_MLKEM_SEED_LEN];
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint16_t pk_len = 0U;
    lt_ret_t ret;

    if (s_mlkem_open != 0U) {
        se_tropic_mlkem_key_close();
    }

    ret = se_tropic_pin_check(h, pin, pin_len, add, add_len, final_key);
    if (ret != LT_OK) {
        return ret;
    }

    ret = mlkem_derive_kek(final_key, kek);
    wc_ForceZero(final_key, sizeof(final_key));
    if (ret != LT_OK) {
        return ret;
    }

    ret = mlkem_unwrap_seed(h, kek, seed);
    wc_ForceZero(kek, sizeof(kek));
    if (ret != LT_OK) {
        wc_ForceZero(seed, sizeof(seed));
        return ret;
    }

    ret = mlkem_make_key_from_seed(seed, pk, sizeof(pk), &pk_len);
    wc_ForceZero(seed, sizeof(seed));
    if (ret != LT_OK) {
        return ret;
    }

    ret = mlkem_check_pk(pk, pk_len);
    if (ret == LT_OK) {
        (void)memcpy(s_pk_cache, pk, SE_TROPIC_MLKEM_PK_LEN);
        s_pk_cache_valid = 1U;
    }
    wc_ForceZero(pk, sizeof(pk));
    if (ret != LT_OK) {
        se_tropic_mlkem_key_close();
        return ret;
    }

    return LT_OK;
}

lt_ret_t se_tropic_mlkem_decapsulate(const uint8_t ct[SE_TROPIC_KEM_CT_LEN],
                                     uint8_t ss[SE_TROPIC_MLKEM_SS_LEN])
{
    int ret;

    if ((ct == NULL) || (ss == NULL) || (s_mlkem_open == 0U)) {
        return LT_PARAM_ERR;
    }

    ret = wc_MlKemKey_Decapsulate(&s_mlkem, ss, ct, SE_TROPIC_KEM_CT_LEN);
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

void se_tropic_mlkem_key_close(void)
{
    if (s_mlkem_open != 0U) {
        wc_MlKemKey_Free(&s_mlkem);
        s_mlkem_open = 0U;
    }
}
