/**
 * @file    se_tropic_pin.c
 * @brief   MAC-and-Destroy PIN (lt_hmac_sha256 / wolfCrypt)
 */
#include "se_tropic_pin.h"
#include "se_tropic_port.h"
#include "se_tropic_rmem.h"
#include "lt_hmac_sha256.h"
#include "libtropic.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>

static const uint8_t k_pin_pepper_info[] = "SE_tropic_pin_pepper_v2";

/** Persistent MAC-and-Destroy PIN blob (R-MEM slot SE_TROPIC_PIN_NVM_SLOT). */
struct se_tropic_pin_nvm_t {
    uint8_t i;  /**< Remaining attempts; also the next M&D slot to consume. Starts at
                     SE_TROPIC_PIN_ROUNDS, decremented before each check, restored on success.
                     Zero means the budget is exhausted and the KEK is unrecoverable. */
    uint8_t ci[SE_TROPIC_PIN_ROUNDS * TR01_MAC_AND_DESTROY_DATA_SIZE];  /**< Per-slot wrap of
                     the master secret: ci[slot] = master_secret XOR HMAC(w_slot, PIN||add||pepper).
                     Pepper is MCU-only. Check XORs with the same HMAC to recover s_. */
    uint8_t t[LT_HMAC_SHA256_HASH_LEN];  /**< Auth tag HMAC(master_secret, 0x00). Check
                     recomputes HMAC(s_, 0x00) and compares; mismatch means wrong PIN. */
} __attribute__((packed));

static void xor32(const uint8_t *data, const uint8_t *key, uint8_t *dst)
{
    uint8_t i;
    for (i = 0; i < 32u; i++) {
        dst[i] = (uint8_t)(data[i] ^ key[i]);
    }
}

/** HKDF-SHA384(device-seal key, "SE_tropic_pin_pepper_v2") — never leaves the MCU. */
static lt_ret_t pin_pepper(uint8_t out[SE_TROPIC_PIN_PEPPER_SIZE])
{
    uint8_t dwk[32];
    int wret;
    lt_ret_t ret;

    ret = se_tropic_port_device_aead_key(dwk);
    if (ret != LT_OK) {
        return ret;
    }
    wret = wc_HKDF(WC_SHA384, dwk, (word32)sizeof(dwk), NULL, 0, k_pin_pepper_info,
                   (word32)(sizeof(k_pin_pepper_info) - 1U), out, SE_TROPIC_PIN_PEPPER_SIZE);
    wc_ForceZero(dwk, sizeof(dwk));
    return (wret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

/** kdf_in = PIN || add || pepper. */
static lt_ret_t pin_kdf_in(const uint8_t *pin, uint8_t pin_len, const uint8_t *add, uint8_t add_len,
                           uint8_t *kdf_in, uint32_t *kdf_len)
{
    uint8_t pepper[SE_TROPIC_PIN_PEPPER_SIZE];
    uint8_t add_checked = add_len;
    lt_ret_t ret;

    if (add == NULL) {
        add_checked = 0;
    }
    ret = pin_pepper(pepper);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memcpy(kdf_in, pin, pin_len);
    if (add_checked > 0u) {
        (void)memcpy(kdf_in + pin_len, add, add_checked);
    }
    (void)memcpy(kdf_in + pin_len + add_checked, pepper, SE_TROPIC_PIN_PEPPER_SIZE);
    *kdf_len = (uint32_t)pin_len + add_checked + SE_TROPIC_PIN_PEPPER_SIZE;
    wc_ForceZero(pepper, sizeof(pepper));
    return LT_OK;
}

lt_ret_t se_tropic_pin_setup(lt_handle_t *h, const uint8_t *master_secret, const uint8_t *pin,
                             uint8_t pin_len, const uint8_t *add, uint8_t add_len,
                             uint8_t *final_key)
{
    uint8_t kdf_in[SE_TROPIC_PIN_SIZE_MAX + SE_TROPIC_PIN_ADD_SIZE_MAX + SE_TROPIC_PIN_PEPPER_SIZE];
    uint32_t kdf_len = 0;
    uint8_t v[LT_HMAC_SHA256_HASH_LEN];
    uint8_t w_i[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t k_i[LT_HMAC_SHA256_HASH_LEN];
    uint8_t u[LT_HMAC_SHA256_HASH_LEN];
    const uint8_t zeros[32] = {0};
    struct se_tropic_pin_nvm_t nvm;
    lt_ret_t ret;
    int i;

    if ((h == NULL) || (master_secret == NULL) || (pin == NULL) || (final_key == NULL) ||
        (pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX) ||
        (add_len > SE_TROPIC_PIN_ADD_SIZE_MAX)) {
        return LT_PARAM_ERR;
    }

    (void)memset(final_key, 0, TR01_MAC_AND_DESTROY_DATA_SIZE);
    (void)memset(&nvm, 0, sizeof(nvm));
    ret = pin_kdf_in(pin, pin_len, add, add_len, kdf_in, &kdf_len);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = lt_r_mem_data_erase(h, SE_TROPIC_PIN_NVM_SLOT);
    if (ret != LT_OK) {
        se_tropic_log("PIN setup erase fail %s", lt_ret_verbose(ret));
        goto exit;
    }

    nvm.i = (uint8_t)SE_TROPIC_PIN_ROUNDS;

    ret = lt_hmac_sha256(master_secret, TR01_MAC_AND_DESTROY_DATA_SIZE, (const uint8_t[]){0x00}, 1u,
                         nvm.t);
    if (ret != LT_OK) {
        goto exit;
    }
    ret = lt_hmac_sha256(master_secret, TR01_MAC_AND_DESTROY_DATA_SIZE, (const uint8_t[]){0x01}, 1u,
                         u);
    if (ret != LT_OK) {
        goto exit;
    }
    ret = lt_hmac_sha256(zeros, sizeof(zeros), kdf_in, kdf_len, v);
    if (ret != LT_OK) {
        goto exit;
    }

    for (i = 0; i < (int)nvm.i; i++) {
        uint8_t ignore[TR01_MAC_AND_DESTROY_DATA_SIZE];

        ret = lt_mac_and_destroy(h, (lt_mac_and_destroy_slot_t)i, u, ignore);
        if (ret != LT_OK) {
            se_tropic_log("PIN setup M&D init fail %s", lt_ret_verbose(ret));
            goto exit;
        }
        ret = lt_mac_and_destroy(h, (lt_mac_and_destroy_slot_t)i, v, w_i);
        if (ret != LT_OK) {
            se_tropic_log("PIN setup M&D wrap fail %s", lt_ret_verbose(ret));
            goto exit;
        }
        ret = lt_mac_and_destroy(h, (lt_mac_and_destroy_slot_t)i, u, ignore);
        if (ret != LT_OK) {
            goto exit;
        }
        ret = lt_hmac_sha256(w_i, sizeof(w_i), kdf_in, kdf_len, k_i);
        if (ret != LT_OK) {
            goto exit;
        }
        xor32(master_secret, k_i, nvm.ci + ((size_t)i * TR01_MAC_AND_DESTROY_DATA_SIZE));
    }

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_PIN_NVM_SLOT, (const uint8_t *)&nvm, sizeof(nvm));
    if (ret != LT_OK) {
        se_tropic_log("PIN setup NVM write fail %s", lt_ret_verbose(ret));
        goto exit;
    }

    ret = lt_hmac_sha256(master_secret, TR01_MAC_AND_DESTROY_DATA_SIZE, (const uint8_t *)"2", 1u,
                         final_key);

exit:
    (void)memset(kdf_in, 0, sizeof(kdf_in));
    (void)memset(u, 0, sizeof(u));
    (void)memset(v, 0, sizeof(v));
    (void)memset(w_i, 0, sizeof(w_i));
    (void)memset(k_i, 0, sizeof(k_i));
    (void)memset(&nvm, 0, sizeof(nvm));
    return ret;
}

lt_ret_t se_tropic_pin_check(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                             const uint8_t *add, uint8_t add_len, uint8_t *final_key)
{
    uint8_t kdf_in[SE_TROPIC_PIN_SIZE_MAX + SE_TROPIC_PIN_ADD_SIZE_MAX + SE_TROPIC_PIN_PEPPER_SIZE];
    uint32_t kdf_len = 0;
    uint8_t v_[LT_HMAC_SHA256_HASH_LEN];
    uint8_t w_i[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t k_i[LT_HMAC_SHA256_HASH_LEN];
    uint8_t s_[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t t_[LT_HMAC_SHA256_HASH_LEN];
    uint8_t u[LT_HMAC_SHA256_HASH_LEN];
    const uint8_t zeros[32] = {0};
    struct se_tropic_pin_nvm_t nvm;
    uint16_t read_size = 0;
    lt_ret_t ret;
    int x;

    if ((h == NULL) || (pin == NULL) || (final_key == NULL) ||
        (pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX) ||
        (add_len > SE_TROPIC_PIN_ADD_SIZE_MAX)) {
        return LT_PARAM_ERR;
    }
    if (h->l3.session_status != LT_SECURE_SESSION_ON) {
        return LT_HOST_NO_SESSION;
    }

    (void)memset(final_key, 0, TR01_MAC_AND_DESTROY_DATA_SIZE);
    (void)memset(&nvm, 0, sizeof(nvm));
    ret = pin_kdf_in(pin, pin_len, add, add_len, kdf_in, &kdf_len);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = se_tropic_read_and_decrypt_mcu_sealed_from_rmem(h, SE_TROPIC_PIN_NVM_SLOT, (uint8_t *)&nvm, sizeof(nvm), &read_size);
    if (ret != LT_OK) {
        se_tropic_log("PIN check NVM read fail %s", lt_ret_verbose(ret));
        goto exit;
    }
    if (read_size < sizeof(nvm)) {
        se_tropic_log("PIN check NVM short read");
        ret = LT_FAIL;
        goto exit;
    }
    if (nvm.i == 0u) {
        se_tropic_log("PIN check: no attempts left");
        ret = LT_FAIL;
        goto exit;
    }

    nvm.i--;
    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_PIN_NVM_SLOT, (const uint8_t *)&nvm, sizeof(nvm));
    if (ret != LT_OK) {
        goto exit;
    }

    ret = lt_hmac_sha256(zeros, sizeof(zeros), kdf_in, kdf_len, v_);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = lt_mac_and_destroy(h, (lt_mac_and_destroy_slot_t)nvm.i, v_, w_i);
    if (ret != LT_OK) {
        se_tropic_log("PIN check M&D fail %s", lt_ret_verbose(ret));
        goto exit;
    }

    ret = lt_hmac_sha256(w_i, sizeof(w_i), kdf_in, kdf_len, k_i);
    if (ret != LT_OK) {
        goto exit;
    }
    xor32(nvm.ci + ((size_t)nvm.i * TR01_MAC_AND_DESTROY_DATA_SIZE), k_i, s_);

    ret = lt_hmac_sha256(s_, sizeof(s_), (const uint8_t[]){0x00}, 1u, t_);
    if (ret != LT_OK) {
        goto exit;
    }
    if (memcmp(nvm.t, t_, sizeof(t_)) != 0) {
        se_tropic_log("PIN check: tag mismatch (wrong PIN)");
        ret = LT_FAIL;
        goto exit;
    }

    ret = lt_hmac_sha256(s_, sizeof(s_), (const uint8_t[]){0x01}, 1u, u);
    if (ret != LT_OK) {
        goto exit;
    }
    for (x = (int)nvm.i; x < (int)SE_TROPIC_PIN_ROUNDS; x++) {
        uint8_t ignore[TR01_MAC_AND_DESTROY_DATA_SIZE];
        ret = lt_mac_and_destroy(h, (lt_mac_and_destroy_slot_t)x, u, ignore);
        if (ret != LT_OK) {
            goto exit;
        }
    }

    nvm.i = (uint8_t)SE_TROPIC_PIN_ROUNDS;
    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_PIN_NVM_SLOT, (const uint8_t *)&nvm, sizeof(nvm));
    if (ret != LT_OK) {
        goto exit;
    }

    ret = lt_hmac_sha256(s_, sizeof(s_), (const uint8_t *)"2", 1u, final_key);

exit:
    (void)memset(kdf_in, 0, sizeof(kdf_in));
    (void)memset(w_i, 0, sizeof(w_i));
    (void)memset(k_i, 0, sizeof(k_i));
    (void)memset(v_, 0, sizeof(v_));
    (void)memset(s_, 0, sizeof(s_));
    (void)memset(t_, 0, sizeof(t_));
    (void)memset(u, 0, sizeof(u));
    (void)memset(&nvm, 0, sizeof(nvm));
    return ret;
}
