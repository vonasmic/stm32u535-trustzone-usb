/**
 * @file    se_tropic_pin.c
 * @brief   MAC-and-Destroy PIN (HMAC-SHA384 / wolfCrypt)
 */
#include "se_tropic_pin.h"
#include "se_tropic_port.h"
#include "se_tropic_rmem.h"
#include "libtropic.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha512.h>

static const uint8_t k_pin_pepper_info[] = "SE_tropic_pin_pepper_v2";

/** Persistent MAC-and-Destroy PIN blob (R-MEM slot SE_TROPIC_PIN_NVM_SLOT). */
struct se_tropic_pin_nvm_t {
    uint8_t i;  /**< Remaining attempts. Hardware slots for attempt i are
                     2i and 2i+1. Starts at SE_TROPIC_PIN_ROUNDS, decremented
                     before each check, restored on success. Zero means the
                     budget is exhausted and the KEK is unrecoverable. */
    uint8_t ci[SE_TROPIC_PIN_ROUNDS * SE_TROPIC_PIN_HMAC_LEN];  /**< Per-attempt
                     wrap of the 48-byte master: ci[i] = master XOR
                     HMAC-SHA384(S1||S2, PIN||add||pepper). Pepper is MCU-only. */
    uint8_t t[SE_TROPIC_PIN_HMAC_LEN];  /**< Auth tag HMAC-SHA384(master, 0x00). */
} __attribute__((packed));

_Static_assert(sizeof(struct se_tropic_pin_nvm_t) <= SE_TROPIC_RMEM_PLAIN_MAX,
               "PIN NVM exceeds R-MEM plaintext");
_Static_assert(SE_TROPIC_PIN_HMAC_LEN == WC_SHA384_DIGEST_SIZE,
               "PIN HMAC width must match SHA-384");

static void xor48(const uint8_t *data, const uint8_t *key, uint8_t *dst)
{
    uint8_t i;
    for (i = 0; i < SE_TROPIC_PIN_HMAC_LEN; i++) {
        dst[i] = (uint8_t)(data[i] ^ key[i]);
    }
}

static lt_ret_t pin_hmac_sha384(const uint8_t *key, uint32_t key_len, const uint8_t *input,
                                uint32_t input_len, uint8_t out[SE_TROPIC_PIN_HMAC_LEN])
{
    Hmac hmac;
    int wret;

    wret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (wret != 0) {
        return LT_CRYPTO_ERR;
    }
    wret = wc_HmacSetKey(&hmac, WC_SHA384, key, key_len);
    if (wret == 0) {
        wret = wc_HmacUpdate(&hmac, input, input_len);
    }
    if (wret == 0) {
        wret = wc_HmacFinal(&hmac, out);
    }
    wc_HmacFree(&hmac);
    return (wret == 0) ? LT_OK : LT_CRYPTO_ERR;
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

static lt_ret_t pin_md_pair(lt_handle_t *h, unsigned attempt, const uint8_t *in,
                            uint8_t s1[TR01_MAC_AND_DESTROY_DATA_SIZE],
                            uint8_t s2[TR01_MAC_AND_DESTROY_DATA_SIZE])
{
    lt_mac_and_destroy_slot_t a =
        (lt_mac_and_destroy_slot_t)(attempt * SE_TROPIC_PIN_MD_PER_TRY);
    lt_mac_and_destroy_slot_t b = (lt_mac_and_destroy_slot_t)((unsigned)a + 1u);
    lt_ret_t ret;

    ret = lt_mac_and_destroy(h, a, in, s1);
    if (ret != LT_OK) {
        return ret;
    }
    return lt_mac_and_destroy(h, b, in, s2);
}

static lt_ret_t pin_wrap_key(const uint8_t s1[TR01_MAC_AND_DESTROY_DATA_SIZE],
                             const uint8_t s2[TR01_MAC_AND_DESTROY_DATA_SIZE],
                             const uint8_t *kdf_in, uint32_t kdf_len,
                             uint8_t k_i[SE_TROPIC_PIN_HMAC_LEN])
{
    uint8_t k[TR01_MAC_AND_DESTROY_DATA_SIZE * SE_TROPIC_PIN_MD_PER_TRY];
    lt_ret_t ret;

    (void)memcpy(k, s1, TR01_MAC_AND_DESTROY_DATA_SIZE);
    (void)memcpy(k + TR01_MAC_AND_DESTROY_DATA_SIZE, s2, TR01_MAC_AND_DESTROY_DATA_SIZE);
    ret = pin_hmac_sha384(k, (uint32_t)sizeof(k), kdf_in, kdf_len, k_i);
    wc_ForceZero(k, sizeof(k));
    return ret;
}

lt_ret_t se_tropic_pin_setup(lt_handle_t *h, const uint8_t *master_secret, const uint8_t *pin,
                             uint8_t pin_len, const uint8_t *add, uint8_t add_len,
                             uint8_t *final_key)
{
    uint8_t kdf_in[SE_TROPIC_PIN_SIZE_MAX + SE_TROPIC_PIN_ADD_SIZE_MAX + SE_TROPIC_PIN_PEPPER_SIZE];
    uint32_t kdf_len = 0;
    uint8_t v[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t s1[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t s2[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t k_i[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t u[SE_TROPIC_PIN_HMAC_LEN];
    const uint8_t zeros[SE_TROPIC_PIN_HMAC_LEN] = {0};
    struct se_tropic_pin_nvm_t nvm;
    lt_ret_t ret;
    int i;

    if ((h == NULL) || (master_secret == NULL) || (pin == NULL) || (final_key == NULL) ||
        (pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX) ||
        (add_len > SE_TROPIC_PIN_ADD_SIZE_MAX)) {
        return LT_PARAM_ERR;
    }

    (void)memset(final_key, 0, SE_TROPIC_PIN_HMAC_LEN);
    (void)memset(&nvm, 0, sizeof(nvm));
    ret = pin_kdf_in(pin, pin_len, add, add_len, kdf_in, &kdf_len);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = lt_r_mem_data_erase(h, SE_TROPIC_PIN_NVM_SLOT);
    if (ret != LT_OK) {
        se_tropic_log_fail("PIN setup erase fail", ret);
        goto exit;
    }

    nvm.i = (uint8_t)SE_TROPIC_PIN_ROUNDS;

    ret = pin_hmac_sha384(master_secret, SE_TROPIC_PIN_HMAC_LEN, (const uint8_t[]){0x00}, 1u, nvm.t);
    if (ret != LT_OK) {
        goto exit;
    }
    ret = pin_hmac_sha384(master_secret, SE_TROPIC_PIN_HMAC_LEN, (const uint8_t[]){0x01}, 1u, u);
    if (ret != LT_OK) {
        goto exit;
    }
    ret = pin_hmac_sha384(zeros, sizeof(zeros), kdf_in, kdf_len, v);
    if (ret != LT_OK) {
        goto exit;
    }

    for (i = 0; i < (int)nvm.i; i++) {
        uint8_t ignore[TR01_MAC_AND_DESTROY_DATA_SIZE];

        ret = pin_md_pair(h, (unsigned)i, u, ignore, ignore);
        if (ret != LT_OK) {
            se_tropic_log_fail("PIN setup M&D init fail", ret);
            goto exit;
        }
        ret = pin_md_pair(h, (unsigned)i, v, s1, s2);
        if (ret != LT_OK) {
            se_tropic_log_fail("PIN setup M&D wrap fail", ret);
            goto exit;
        }
        ret = pin_md_pair(h, (unsigned)i, u, ignore, ignore);
        if (ret != LT_OK) {
            goto exit;
        }
        ret = pin_wrap_key(s1, s2, kdf_in, kdf_len, k_i);
        if (ret != LT_OK) {
            goto exit;
        }
        xor48(master_secret, k_i, nvm.ci + ((size_t)i * SE_TROPIC_PIN_HMAC_LEN));
    }

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_PIN_NVM_SLOT,
                                                         (const uint8_t *)&nvm, sizeof(nvm));
    if (ret != LT_OK) {
        se_tropic_log_fail("PIN setup NVM write fail", ret);
        goto exit;
    }

    ret = pin_hmac_sha384(master_secret, SE_TROPIC_PIN_HMAC_LEN, (const uint8_t *)"2", 1u, final_key);

exit:
    (void)memset(kdf_in, 0, sizeof(kdf_in));
    (void)memset(u, 0, sizeof(u));
    (void)memset(v, 0, sizeof(v));
    (void)memset(s1, 0, sizeof(s1));
    (void)memset(s2, 0, sizeof(s2));
    (void)memset(k_i, 0, sizeof(k_i));
    (void)memset(&nvm, 0, sizeof(nvm));
    return ret;
}

lt_ret_t se_tropic_pin_check(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                             const uint8_t *add, uint8_t add_len, uint8_t *final_key)
{
    uint8_t kdf_in[SE_TROPIC_PIN_SIZE_MAX + SE_TROPIC_PIN_ADD_SIZE_MAX + SE_TROPIC_PIN_PEPPER_SIZE];
    uint32_t kdf_len = 0;
    uint8_t v_[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t s1[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t s2[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t k_i[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t s_[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t t_[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t u[SE_TROPIC_PIN_HMAC_LEN];
    const uint8_t zeros[SE_TROPIC_PIN_HMAC_LEN] = {0};
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

    (void)memset(final_key, 0, SE_TROPIC_PIN_HMAC_LEN);
    (void)memset(&nvm, 0, sizeof(nvm));
    ret = pin_kdf_in(pin, pin_len, add, add_len, kdf_in, &kdf_len);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = se_tropic_read_and_decrypt_mcu_sealed_from_rmem(h, SE_TROPIC_PIN_NVM_SLOT, (uint8_t *)&nvm,
                                                          sizeof(nvm), &read_size);
    if (ret != LT_OK) {
        se_tropic_log_fail("PIN check NVM read fail", ret);
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
    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_PIN_NVM_SLOT,
                                                         (const uint8_t *)&nvm, sizeof(nvm));
    if (ret != LT_OK) {
        goto exit;
    }

    ret = pin_hmac_sha384(zeros, sizeof(zeros), kdf_in, kdf_len, v_);
    if (ret != LT_OK) {
        goto exit;
    }

    ret = pin_md_pair(h, (unsigned)nvm.i, v_, s1, s2);
    if (ret != LT_OK) {
        se_tropic_log_fail("PIN check M&D fail", ret);
        goto exit;
    }

    ret = pin_wrap_key(s1, s2, kdf_in, kdf_len, k_i);
    if (ret != LT_OK) {
        goto exit;
    }
    xor48(nvm.ci + ((size_t)nvm.i * SE_TROPIC_PIN_HMAC_LEN), k_i, s_);

    ret = pin_hmac_sha384(s_, SE_TROPIC_PIN_HMAC_LEN, (const uint8_t[]){0x00}, 1u, t_);
    if (ret != LT_OK) {
        goto exit;
    }
    if (memcmp(nvm.t, t_, sizeof(t_)) != 0) {
        se_tropic_log("PIN check: tag mismatch (wrong PIN)");
        ret = LT_FAIL;
        goto exit;
    }

    ret = pin_hmac_sha384(s_, SE_TROPIC_PIN_HMAC_LEN, (const uint8_t[]){0x01}, 1u, u);
    if (ret != LT_OK) {
        goto exit;
    }
    for (x = (int)nvm.i; x < (int)SE_TROPIC_PIN_ROUNDS; x++) {
        uint8_t ignore[TR01_MAC_AND_DESTROY_DATA_SIZE];
        ret = pin_md_pair(h, (unsigned)x, u, ignore, ignore);
        if (ret != LT_OK) {
            goto exit;
        }
    }

    nvm.i = (uint8_t)SE_TROPIC_PIN_ROUNDS;
    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_PIN_NVM_SLOT,
                                                         (const uint8_t *)&nvm, sizeof(nvm));
    if (ret != LT_OK) {
        goto exit;
    }

    ret = pin_hmac_sha384(s_, SE_TROPIC_PIN_HMAC_LEN, (const uint8_t *)"2", 1u, final_key);

exit:
    (void)memset(kdf_in, 0, sizeof(kdf_in));
    (void)memset(s1, 0, sizeof(s1));
    (void)memset(s2, 0, sizeof(s2));
    (void)memset(k_i, 0, sizeof(k_i));
    (void)memset(v_, 0, sizeof(v_));
    (void)memset(s_, 0, sizeof(s_));
    (void)memset(t_, 0, sizeof(t_));
    (void)memset(u, 0, sizeof(u));
    (void)memset(&nvm, 0, sizeof(nvm));
    return ret;
}
