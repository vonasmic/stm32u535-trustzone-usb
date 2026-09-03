/**
 * @file    sae_qkd.c
 * @brief   SAE-side slot seal and slot-size probe for host model tests
 */
#include "sae_qkd.h"
#include "se_nv.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

lt_ret_t sae_qkd_encrypt_pad_image(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN], uint16_t slot,
                           const uint8_t *plain, uint16_t plain_len,
                           const uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN], uint8_t *image,
                           uint16_t *image_len)
{
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[2];
    lt_ret_t ret;

    if ((ss == NULL) || (plain == NULL) || (nonce == NULL) || (image == NULL) ||
        (image_len == NULL)) {
        return LT_PARAM_ERR;
    }

    ret = se_nv_get_fill_id(fill_id);
    if (ret != LT_OK) {
        return LT_FAIL;
    }

    write_storage_slot_binding(slot, binding);

    ret = se_tropic_get_pad_encryption_key(ss, fill_id, slot, key);
    if (ret == LT_OK) {
        ret = se_tropic_encrypt_storage_blob(key, binding, sizeof(binding), plain, plain_len,
                                             nonce, image, image_len);
    }
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(fill_id, sizeof(fill_id));
    return ret;
}

lt_ret_t sae_rmem_probe_slot_max(lt_handle_t *h, uint16_t slot)
{
    uint8_t fill[SE_TROPIC_RMEM_PLAIN_MAX];
    uint8_t back[SE_TROPIC_RMEM_PLAIN_MAX];
    uint16_t plain_max;
    uint16_t got = 0U;
    lt_ret_t ret;
    unsigned int i;

    if (h == NULL) {
        return LT_PARAM_ERR;
    }

    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    if (plain_max == 0U) {
        return LT_FAIL;
    }

    for (i = 0U; i < plain_max; i++) {
        fill[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, slot, fill, plain_max);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_read_and_decrypt_mcu_sealed_from_rmem(h, slot, back, sizeof(back), &got);
    if ((ret != LT_OK) || (got != plain_max) || (memcmp(back, fill, plain_max) != 0)) {
        return LT_FAIL;
    }

    fill[0] = 0x5Au;
    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, slot, fill, (uint16_t)(plain_max + 1u));
    return (ret == LT_PARAM_ERR) ? LT_OK : LT_FAIL;
}
