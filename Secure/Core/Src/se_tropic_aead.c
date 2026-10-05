/**
 * @file    se_tropic_aead.c
 * @brief   R-MEM slot map and AES-GCM storage blobs
 */
#include "se_tropic_rmem.h"
#include "se_tropic_rmem_internal.h"
#include "se_tropic_pin.h"
#include "se_tropic_port.h"
#include "se_nv.h"
#include <string.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/memory.h>

static const uint8_t k_slot_label[] = "SE_tropic_qkd_slot_v3";
#define SLOT_LABEL_LEN (sizeof(k_slot_label) - 1u)
uint16_t se_tropic_get_rmem_slot_max_size(const lt_handle_t *h)
{
    if ((h != NULL) && (h->tr01_attrs.r_mem_udata_slot_size_max > 0U)) {
        return h->tr01_attrs.r_mem_udata_slot_size_max;
    }
    return SE_TROPIC_RMEM_SLOT_MAX;
}

uint16_t se_tropic_get_rmem_slot_plaintext_max_size(const lt_handle_t *h)
{
    uint16_t slot_max = se_tropic_get_rmem_slot_max_size(h);

    if (slot_max <= SE_TROPIC_RMEM_OVERHEAD) {
        return 0U;
    }
    return (uint16_t)(slot_max - SE_TROPIC_RMEM_OVERHEAD);
}

int se_tropic_slot_is_keystream(uint16_t phys)
{
    if ((phys < SE_TROPIC_PAD_FIRST) || (phys > SE_TROPIC_QKD_SLOT_LAST)) {
        return 0;
    }
    if ((phys == SE_TROPIC_MLKEM_SEED_SLOT) || (phys == SE_TROPIC_PIN_NVM_SLOT)) {
        return 0;
    }
    return 1;
}

lt_ret_t se_tropic_get_slot_index_from_phys(uint16_t phys, uint16_t *slot_index)
{
    if ((slot_index == NULL) || (se_tropic_slot_is_keystream(phys) == 0)) {
        return LT_PARAM_ERR;
    }
    *slot_index = (uint16_t)(phys - SE_TROPIC_PAD_FIRST);
    return LT_OK;
}

lt_ret_t se_tropic_get_phys_from_slot_index(uint16_t slot_index, uint16_t *phys)
{
    uint32_t slot;

    if (phys == NULL) {
        return LT_PARAM_ERR;
    }
    if (slot_index >= SE_TROPIC_PAD_COUNT) {
        return LT_PARAM_ERR;
    }
    slot = (uint32_t)SE_TROPIC_PAD_FIRST + (uint32_t)slot_index;
    if (slot > SE_TROPIC_QKD_SLOT_LAST) {
        return LT_PARAM_ERR;
    }
    *phys = (uint16_t)slot;
    if (se_tropic_slot_is_keystream(*phys) == 0) {
        return LT_PARAM_ERR;
    }
    return LT_OK;
}
/** @p index 0 returns @p base; higher indices walk forward across keystream slots. */
uint16_t se_tropic_keystream_slot_at_offset(uint16_t base, uint16_t index)
{
    uint32_t slot = (uint32_t)base + (uint32_t)index;

    if (slot > SE_TROPIC_QKD_SLOT_LAST) {
        return (uint16_t)(SE_TROPIC_QKD_SLOT_LAST + 1u);
    }
    return (uint16_t)slot;
}
lt_ret_t se_tropic_encrypt_storage_blob(const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                        const uint8_t *binding, uint16_t binding_len,
                                        const uint8_t *plain, uint16_t plain_len,
                                        const uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN],
                                        uint8_t *blob, uint16_t *blob_len)
{
    Aes aes;
    uint8_t *ct;
    uint8_t *tag;
    int wret;

    if ((key == NULL) || (plain == NULL) || (nonce == NULL) || (blob == NULL) || (blob_len == NULL) ||
        ((binding == NULL) && (binding_len != 0U)) || (plain_len == 0u) ||
        (plain_len > SE_TROPIC_STORAGE_PLAIN_MAX)) {
        return LT_PARAM_ERR;
    }
    if (*blob_len < (uint16_t)(SE_TROPIC_RMEM_OVERHEAD + plain_len)) {
        return LT_PARAM_ERR;
    }

    blob[0] = SE_TROPIC_RMEM_VER;
    (void)memcpy(blob + 1, nonce, SE_TROPIC_RMEM_NONCE_LEN);
    ct = blob + 1u + SE_TROPIC_RMEM_NONCE_LEN;
    tag = ct + plain_len;

    wret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (wret == 0) {
        wret = wc_AesGcmSetKey(&aes, key, SE_TROPIC_RMEM_AES_KEY_LEN);
    }
    if (wret == 0) {
        wret = wc_AesGcmEncrypt(&aes, ct, plain, plain_len, nonce, SE_TROPIC_RMEM_NONCE_LEN, tag,
                                SE_TROPIC_RMEM_TAG_LEN, binding, binding_len);
    }
    wc_AesFree(&aes);

    if (wret != 0) {
        return LT_CRYPTO_ERR;
    }
    *blob_len = (uint16_t)(SE_TROPIC_RMEM_OVERHEAD + plain_len);
    return LT_OK;
}

lt_ret_t se_tropic_decrypt_storage_blob(const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                          const uint8_t *binding, uint16_t binding_len,
                                          const uint8_t *blob, uint16_t blob_len,
                                          uint8_t *plain, uint16_t plain_max,
                                          uint16_t *plain_len)
{
    Aes aes;
    const uint8_t *nonce;
    const uint8_t *ct;
    const uint8_t *tag;
    uint16_t ct_len;
    int wret;

    if ((key == NULL) || (blob == NULL) || (plain == NULL) || (plain_len == NULL) ||
        ((binding == NULL) && (binding_len != 0U)) || (blob_len < SE_TROPIC_RMEM_OVERHEAD)) {
        return LT_PARAM_ERR;
    }
    if (blob[0] != SE_TROPIC_RMEM_VER) {
        return LT_FAIL;
    }

    ct_len = (uint16_t)(blob_len - SE_TROPIC_RMEM_OVERHEAD);
    if ((ct_len == 0u) || (ct_len > plain_max) || (ct_len > SE_TROPIC_STORAGE_PLAIN_MAX)) {
        return LT_PARAM_ERR;
    }

    nonce = blob + 1;
    ct = blob + 1u + SE_TROPIC_RMEM_NONCE_LEN;
    tag = ct + ct_len;

    wret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (wret == 0) {
        wret = wc_AesGcmSetKey(&aes, key, SE_TROPIC_RMEM_AES_KEY_LEN);
    }
    if (wret == 0) {
        wret = wc_AesGcmDecrypt(&aes, plain, ct, ct_len, nonce, SE_TROPIC_RMEM_NONCE_LEN, tag,
                                SE_TROPIC_RMEM_TAG_LEN, binding, binding_len);
    }
    wc_AesFree(&aes);

    if (wret != 0) {
        wc_ForceZero(plain, ct_len);
        return LT_CRYPTO_ERR;
    }
    *plain_len = ct_len;
    return LT_OK;
}
lt_ret_t se_tropic_get_pad_encryption_key(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                                          const uint8_t fill_id[SE_NV_FILL_ID_LEN],
                                          uint16_t slot_index,
                                          uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN])
{
    uint8_t info[SLOT_LABEL_LEN + SE_NV_FILL_ID_LEN + 2u];
    int ret;

    if ((ss == NULL) || (fill_id == NULL) || (key == NULL) || (slot_index >= SE_TROPIC_PAD_COUNT)) {
        return LT_PARAM_ERR;
    }

    (void)memcpy(info, k_slot_label, SLOT_LABEL_LEN);
    (void)memcpy(info + SLOT_LABEL_LEN, fill_id, SE_NV_FILL_ID_LEN);
    write_storage_slot_binding(slot_index, info + SLOT_LABEL_LEN + SE_NV_FILL_ID_LEN);

    ret = wc_HKDF(WC_SHA384, ss, SE_TROPIC_MLKEM_SS_LEN, NULL, 0, info, (word32)sizeof(info), key,
                  SE_TROPIC_RMEM_AES_KEY_LEN);
    wc_ForceZero(info, sizeof(info));
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}
lt_ret_t se_tropic_encrypt_and_write_to_rmem(lt_handle_t *h, uint16_t slot,
                                                 const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                                 const uint8_t *binding, uint16_t binding_len,
                                                 const uint8_t *data, uint16_t len)
{
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t blob[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t blob_len = sizeof(blob);
    uint16_t plain_max;
    lt_ret_t ret;

    if ((h == NULL) || (key == NULL) || (data == NULL) || (len == 0u) ||
        ((binding == NULL) && (binding_len != 0U))) {
        return LT_PARAM_ERR;
    }
    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    if ((plain_max == 0U) || (len > plain_max)) {
        return LT_PARAM_ERR;
    }
    if (slot > TR01_R_MEM_DATA_SLOT_MAX) {
        return LT_PARAM_ERR;
    }

    ret = lt_random_value_get(h, nonce, sizeof(nonce));
    if (ret != LT_OK) {
        return ret;
    }

    ret = se_tropic_encrypt_storage_blob(key, binding, binding_len, data, len, nonce, blob,
                                         &blob_len);
    wc_ForceZero(nonce, sizeof(nonce));
    if (ret != LT_OK) {
        wc_ForceZero(blob, sizeof(blob));
        return ret;
    }

    ret = lt_r_mem_data_erase(h, slot);
    if (ret != LT_OK) {
        wc_ForceZero(blob, sizeof(blob));
        return ret;
    }
    ret = lt_r_mem_data_write(h, slot, blob, blob_len);
    wc_ForceZero(blob, sizeof(blob));
    return ret;
}

lt_ret_t se_tropic_read_and_decrypt_from_rmem(lt_handle_t *h, uint16_t slot,
                                              const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                              const uint8_t *binding, uint16_t binding_len,
                                              uint8_t *out, uint16_t out_max,
                                              uint16_t *out_len)
{
    uint8_t blob[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t got = 0;
    lt_ret_t ret;

    if ((h == NULL) || (key == NULL) || (out == NULL) || (out_len == NULL) ||
        ((binding == NULL) && (binding_len != 0U))) {
        return LT_PARAM_ERR;
    }

    ret = lt_r_mem_data_read(h, slot, blob, sizeof(blob), &got);
    if (ret != LT_OK) {
        return ret;
    }

    ret = se_tropic_decrypt_storage_blob(key, binding, binding_len, blob, got, out, out_max,
                                           out_len);
    wc_ForceZero(blob, sizeof(blob));
    return ret;
}

lt_ret_t se_tropic_encrypt_and_write_mcu_sealed_to_rmem(lt_handle_t *h, uint16_t slot,
                                                      const uint8_t *data, uint16_t len)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[2];
    lt_ret_t ret;

    write_storage_slot_binding(slot, binding);
    ret = se_tropic_load_device_storage_key(key);
    if (ret == LT_OK) {
        ret = se_tropic_encrypt_and_write_to_rmem(h, slot, key, binding, sizeof(binding), data,
                                                    len);
    }
    wc_ForceZero(key, sizeof(key));
    return ret;
}

lt_ret_t se_tropic_read_and_decrypt_mcu_sealed_from_rmem(lt_handle_t *h, uint16_t slot, uint8_t *out,
                                                     uint16_t out_max, uint16_t *out_len)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[2];
    lt_ret_t ret;

    write_storage_slot_binding(slot, binding);
    ret = se_tropic_load_device_storage_key(key);
    if (ret == LT_OK) {
        ret = se_tropic_read_and_decrypt_from_rmem(h, slot, key, binding, sizeof(binding), out,
                                                   out_max, out_len);
    }
    wc_ForceZero(key, sizeof(key));
    return ret;
}
