/**
 * @file    se_tropic_rmem.c
 * @brief   R-MEM encryption, QKD slot map, and PIN-gated OTP consume
 */
#include "se_tropic_rmem.h"
#include "se_tropic_mlkem.h"
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

static uint8_t s_kem_ct[SE_TROPIC_KEM_CT_LEN];
static uint8_t s_pad[SE_TROPIC_RMEM_PLAIN_MAX];

typedef struct {
    uint8_t open;
    se_nv_otp_dir_t dir;
    uint8_t ss[SE_TROPIC_MLKEM_SS_LEN];
    uint16_t plain_max;
    uint32_t slots_needed;
    uint32_t remaining;
    uint8_t by_pads;
    uint8_t have_prev;
    uint16_t prev_logical;
} otp_xor_ctx_t;

static otp_xor_ctx_t s_otp_xor;

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
static uint16_t keystream_slot_at_offset(uint16_t base, uint16_t index)
{
    uint32_t slot = (uint32_t)base + (uint32_t)index;

    if (slot > SE_TROPIC_QKD_SLOT_LAST) {
        return (uint16_t)(SE_TROPIC_QKD_SLOT_LAST + 1u);
    }
    return (uint16_t)slot;
}

static lt_ret_t load_device_storage_key(uint8_t out[SE_TROPIC_RMEM_AES_KEY_LEN])
{
    return se_tropic_port_device_aead_key(out);
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
        se_tropic_log("RMEM GCM encrypt fail %d", wret);
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
        se_tropic_log("RMEM GCM decrypt fail %d", wret);
        wc_ForceZero(plain, ct_len);
        return LT_CRYPTO_ERR;
    }
    *plain_len = ct_len;
    return LT_OK;
}

static lt_ret_t decrypt_storage_blob_with_slot_binding(const uint8_t *key, uint16_t slot,
                                                    const uint8_t *blob, uint16_t blob_len,
                                                    uint8_t *plain, uint16_t plain_max,
                                                    uint16_t *plain_len)
{
    uint8_t binding[2];

    write_storage_slot_binding(slot, binding);
    return se_tropic_decrypt_storage_blob(key, binding, sizeof(binding), blob, blob_len, plain,
                                            plain_max, plain_len);
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

/** Decrypt a finished pad image under the per-slot key (OTP consume only). */
static lt_ret_t decrypt_qkd_pad_image(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                              const uint8_t fill_id[SE_NV_FILL_ID_LEN], uint16_t phys,
                              const uint8_t *image, uint16_t image_len, uint8_t *out,
                              uint16_t out_max, uint16_t *out_len)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint16_t slot_index = 0U;
    lt_ret_t ret;

    if ((ss == NULL) || (fill_id == NULL) || (image == NULL) || (out == NULL) || (out_len == NULL)) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_get_slot_index_from_phys(phys, &slot_index);
    if (ret == LT_OK) {
        ret = se_tropic_get_pad_encryption_key(ss, fill_id, slot_index, key);
    }
    if (ret == LT_OK) {
        ret = decrypt_storage_blob_with_slot_binding(key, slot_index, image, image_len, out, out_max,
                                                  out_len);
    }
    wc_ForceZero(key, sizeof(key));
    /* Wrong fill_id / restored old pad => decrypt fail; treat as tamper. */
    if (ret == LT_CRYPTO_ERR) {
        return SE_TROPIC_LT_TAMPERED;
    }
    return ret;
}

static void write_kem_ct_storage_binding(uint16_t slot, const uint8_t fill_id[SE_NV_FILL_ID_LEN],
                                      uint8_t binding[34])
{
    write_storage_slot_binding(slot, binding);
    (void)memcpy(binding + 2, fill_id, SE_NV_FILL_ID_LEN);
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
    ret = load_device_storage_key(key);
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
    ret = load_device_storage_key(key);
    if (ret == LT_OK) {
        ret = se_tropic_read_and_decrypt_from_rmem(h, slot, key, binding, sizeof(binding), out,
                                                   out_max, out_len);
    }
    wc_ForceZero(key, sizeof(key));
    return ret;
}

static int otp_dir_ok(se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_ENCRYPT) || (dir == SE_NV_OTP_DECRYPT);
}

static enum lt_mcounter_index_t otp_mcounter(se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_DECRYPT) ? SE_TROPIC_QKD_MCOUNTER_DECRYPT
                                      : SE_TROPIC_QKD_MCOUNTER_ENCRYPT;
}

/** Last physical pad in @p this_base's half (the other base is the far edge). */
static uint16_t otp_half_last(uint16_t this_base, uint16_t other_base)
{
    if (this_base < other_base) {
        return (uint16_t)(other_base - 1u);
    }
    return SE_TROPIC_QKD_SLOT_LAST;
}

static lt_ret_t otp_dir_range(se_nv_otp_dir_t dir, uint16_t *base, uint16_t *last)
{
    uint16_t base_encrypt = 0U;
    uint16_t base_decrypt = 0U;
    lt_ret_t ret;

    ret = se_nv_get_otp_bases(&base_encrypt, &base_decrypt);
    if (ret != LT_OK) {
        return ret;
    }
    if (dir == SE_NV_OTP_DECRYPT) {
        *base = base_decrypt;
        *last = otp_half_last(base_decrypt, base_encrypt);
    } else {
        *base = base_encrypt;
        *last = otp_half_last(base_encrypt, base_decrypt);
    }
    return LT_OK;
}

static int is_valid_dir_cursor(uint32_t raw, se_nv_otp_dir_t dir, uint16_t *slot_out)
{
    uint16_t base = 0U;
    uint16_t last = 0U;

    if ((raw == SE_TROPIC_QKD_CURSOR_END) || (raw > SE_TROPIC_QKD_SLOT_LAST) ||
        (se_tropic_slot_is_keystream((uint16_t)raw) == 0)) {
        return 0;
    }
    if (otp_dir_range(dir, &base, &last) != LT_OK) {
        return 0;
    }
    if (((uint16_t)raw < base) || ((uint16_t)raw > last)) {
        return 0;
    }
    if (slot_out != NULL) {
        *slot_out = (uint16_t)raw;
    }
    return 1;
}

static lt_ret_t qkd_cursor_set_exhausted(lt_handle_t *h, se_nv_otp_dir_t dir)
{
    /* Tropic uses full 32-bit END; MCU NV stores a uint16 non-keystream sentinel. */
    lt_ret_t ret = lt_mcounter_init(h, otp_mcounter(dir), SE_TROPIC_QKD_CURSOR_END);
    if (ret == LT_OK) {
        ret = se_nv_set_cursor(dir, (uint16_t)(SE_TROPIC_QKD_SLOT_LAST + 1u));
    }
    return ret;
}

/** Advance the keystream cursor by one slot after consume. */
static lt_ret_t qkd_cursor_advance_from_slot(lt_handle_t *h, se_nv_otp_dir_t dir, uint16_t current)
{
    uint16_t base = 0U;
    uint16_t last = 0U;
    uint16_t next;
    lt_ret_t ret;

    ret = otp_dir_range(dir, &base, &last);
    if (ret != LT_OK) {
        return ret;
    }
    if (current >= last) {
        return qkd_cursor_set_exhausted(h, dir);
    }
    next = (uint16_t)(current + 1u);
    /* Tropic first, then MCU NV (power-cut between may look like tamper). */
    ret = lt_mcounter_init(h, otp_mcounter(dir), (uint32_t)next);
    if (ret != LT_OK) {
        return ret;
    }
    return se_nv_set_cursor(dir, next);
}

lt_ret_t se_tropic_qkd_provision_begin(lt_handle_t *h)
{
    uint16_t slot;
    lt_ret_t ret;

    if (h == NULL) {
        return LT_PARAM_ERR;
    }

    /* Chip has no bulk erase; one erase per slot, once per new fill. */
    for (slot = SE_TROPIC_QKD_SLOT_BASE; slot <= SE_TROPIC_QKD_SLOT_LAST; slot++) {
        ret = lt_r_mem_data_erase(h, slot);
        if (ret != LT_OK) {
            se_tropic_log("QKD wipe fail slot=%u %s", (unsigned)slot, lt_ret_verbose(ret));
            return ret;
        }
    }

    se_tropic_log("QKD provision wipe slots %u..%u", (unsigned)SE_TROPIC_QKD_SLOT_BASE,
                  (unsigned)SE_TROPIC_QKD_SLOT_LAST);
    return LT_OK;
}

lt_ret_t se_tropic_qkd_arm_halves(lt_handle_t *h, uint8_t decrypt_half)
{
    uint16_t base_first = SE_TROPIC_PAD_FIRST;
    uint16_t base_second = (uint16_t)(SE_TROPIC_PAD_FIRST + SE_TROPIC_PAD_HALF);
    uint16_t base_encrypt;
    uint16_t base_decrypt;
    lt_ret_t ret;

    if ((h == NULL) || (decrypt_half > 1U)) {
        return LT_PARAM_ERR;
    }
    if (decrypt_half == 0U) {
        base_decrypt = base_first;
        base_encrypt = base_second;
    } else {
        base_decrypt = base_second;
        base_encrypt = base_first;
    }

    ret = se_nv_arm_otp_cursors(base_encrypt, base_decrypt);
    if (ret != LT_OK) {
        return ret;
    }
    ret = lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_ENCRYPT, (uint32_t)base_encrypt);
    if (ret != LT_OK) {
        return ret;
    }
    ret = lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_DECRYPT, (uint32_t)base_decrypt);
    if (ret != LT_OK) {
        return ret;
    }
    se_tropic_log("QKD halves decrypt=%u enc_base=%u dec_base=%u", (unsigned)decrypt_half,
                  (unsigned)base_encrypt, (unsigned)base_decrypt);
    return LT_OK;
}

lt_ret_t se_tropic_qkd_cursor_init(lt_handle_t *h, se_nv_otp_dir_t dir, uint16_t start_slot)
{
    if ((h == NULL) || (otp_dir_ok(dir) == 0) || (se_tropic_slot_is_keystream(start_slot) == 0)) {
        return LT_PARAM_ERR;
    }
    return lt_mcounter_init(h, otp_mcounter(dir), (uint32_t)start_slot);
}

lt_ret_t se_tropic_qkd_cursor_get(lt_handle_t *h, se_nv_otp_dir_t dir, uint32_t *next_slot)
{
    uint32_t tropic_raw = 0U;
    uint16_t mcu_cursor = 0U;
    lt_ret_t ret;

    if ((h == NULL) || (next_slot == NULL) || (otp_dir_ok(dir) == 0)) {
        return LT_PARAM_ERR;
    }

    ret = se_nv_get_cursor(dir, &mcu_cursor);
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return ret;
    }
    if (ret != LT_OK) {
        return LT_FAIL;
    }
    if (is_valid_dir_cursor((uint32_t)mcu_cursor, dir, NULL) == 0) {
        return LT_FAIL;
    }

    ret = lt_mcounter_get(h, otp_mcounter(dir), &tropic_raw);
    if (ret != LT_OK) {
        return ret;
    }
    if (tropic_raw != (uint32_t)mcu_cursor) {
        se_tropic_log("QKD cursor mismatch dir=%u MCU=%u Tropic=%lu", (unsigned)dir,
                      (unsigned)mcu_cursor, (unsigned long)tropic_raw);
        return SE_TROPIC_LT_TAMPERED;
    }
    *next_slot = (uint32_t)mcu_cursor;
    return LT_OK;
}

lt_ret_t se_tropic_qkd_cursor_advance(lt_handle_t *h, se_nv_otp_dir_t dir)
{
    uint32_t raw = 0U;
    uint16_t slot = 0U;
    lt_ret_t ret;

    if ((h == NULL) || (otp_dir_ok(dir) == 0)) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_qkd_cursor_get(h, dir, &raw);
    if (ret != LT_OK) {
        return ret;
    }
    slot = (uint16_t)raw;
    return qkd_cursor_advance_from_slot(h, dir, slot);
}

lt_ret_t se_tropic_kem_ct_write(lt_handle_t *h, const uint8_t ct[SE_TROPIC_KEM_CT_LEN])
{
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[34];
    uint16_t off = 0U;
    uint16_t plain_max;
    uint16_t i;
    lt_ret_t ret;

    if ((h == NULL) || (ct == NULL)) {
        return LT_PARAM_ERR;
    }

    if (se_nv_pending_fill_take(fill_id) == 0) {
        ret = lt_random_value_get(h, fill_id, sizeof(fill_id));
        if (ret != LT_OK) {
            return ret;
        }
    }

    ret = se_nv_commit_fill(fill_id);
    if (ret != LT_OK) {
        wc_ForceZero(fill_id, sizeof(fill_id));
        return ret;
    }

    ret = se_tropic_qkd_provision_begin(h);
    if (ret != LT_OK) {
        wc_ForceZero(fill_id, sizeof(fill_id));
        return ret;
    }

    ret = load_device_storage_key(key);
    if (ret != LT_OK) {
        wc_ForceZero(fill_id, sizeof(fill_id));
        return ret;
    }

    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    for (i = 0U; i < SE_TROPIC_KEM_CT_SLOTS; i++) {
        uint16_t take = (uint16_t)(SE_TROPIC_KEM_CT_LEN - off);
        uint16_t slot = (uint16_t)(SE_TROPIC_KEM_CT_BASE + i);

        if (take > plain_max) {
            take = plain_max;
        }
        write_kem_ct_storage_binding(slot, fill_id, binding);
        ret = se_tropic_encrypt_and_write_to_rmem(h, slot, key, binding, sizeof(binding),
                                                    ct + off, take);
        if (ret != LT_OK) {
            break;
        }
        off = (uint16_t)(off + take);
    }
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(fill_id, sizeof(fill_id));
    return ret;
}

lt_ret_t se_tropic_kem_ct_read(lt_handle_t *h, uint8_t ct[SE_TROPIC_KEM_CT_LEN])
{
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[34];
    uint16_t off = 0U;
    uint16_t i;
    lt_ret_t ret;

    if ((h == NULL) || (ct == NULL)) {
        return LT_PARAM_ERR;
    }

    ret = se_nv_get_fill_id(fill_id);
    if (ret != LT_OK) {
        return (ret == SE_TROPIC_LT_TAMPERED) ? ret : LT_FAIL;
    }
    ret = load_device_storage_key(key);
    if (ret != LT_OK) {
        wc_ForceZero(fill_id, sizeof(fill_id));
        return ret;
    }

    for (i = 0U; i < SE_TROPIC_KEM_CT_SLOTS; i++) {
        uint16_t got = 0U;
        uint16_t slot = (uint16_t)(SE_TROPIC_KEM_CT_BASE + i);

        write_kem_ct_storage_binding(slot, fill_id, binding);
        ret = se_tropic_read_and_decrypt_from_rmem(h, slot, key, binding, sizeof(binding),
                                                   ct + off, (uint16_t)(SE_TROPIC_KEM_CT_LEN - off),
                                                   &got);
        if (ret == LT_CRYPTO_ERR) {
            ret = SE_TROPIC_LT_TAMPERED;
            break;
        }
        if (ret != LT_OK) {
            break;
        }
        off = (uint16_t)(off + got);
    }
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(fill_id, sizeof(fill_id));
    if (ret != LT_OK) {
        return ret;
    }
    if (off != SE_TROPIC_KEM_CT_LEN) {
        return LT_FAIL;
    }
    return LT_OK;
}

static uint32_t rmem_slot_has_data(lt_handle_t *h, uint16_t slot)
{
    uint8_t probe[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t got = 0U;
    lt_ret_t ret;

    ret = lt_r_mem_data_read(h, slot, probe, sizeof(probe), &got);
    if (ret == LT_L3_R_MEM_DATA_READ_SLOT_EMPTY) {
        return 0U;
    }
    if (ret == LT_OK) {
        return (got > 0U) ? 1U : 0U;
    }
    /* Non-empty slot when the caller's buffer was too small. */
    return 1U;
}

lt_ret_t se_tropic_qkd_store(lt_handle_t *h, uint16_t slot, const uint8_t *image,
                             uint16_t image_len)
{
    lt_ret_t ret;
    uint16_t slot_max;
    uint16_t phys = 0U;

    if ((h == NULL) || (image == NULL) || (image_len == 0u)) {
        return LT_PARAM_ERR;
    }
    slot_max = se_tropic_get_rmem_slot_max_size(h);
    if ((slot_max == 0U) || (image_len > slot_max)) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_get_phys_from_slot_index(slot, &phys);
    if (ret != LT_OK) {
        return ret;
    }

    if (se_nv_have_fill() == 0) {
        return LT_FAIL;
    }

    if (rmem_slot_has_data(h, phys) != 0U) {
        return LT_FAIL;
    }

    return lt_r_mem_data_write(h, phys, image, image_len);
}

static lt_ret_t qkd_cursor_skip_one(lt_handle_t *h, se_nv_otp_dir_t dir)
{
    uint32_t raw = 0U;
    uint16_t slot;
    lt_ret_t ret;

    ret = se_tropic_qkd_cursor_get(h, dir, &raw);
    if (ret != LT_OK) {
        return ret;
    }
    slot = (uint16_t)raw;
    /* Hole or occupied: burn the pad. Erase failure must not rewind. */
    (void)lt_r_mem_data_erase(h, slot);
    return qkd_cursor_advance_from_slot(h, dir, slot);
}

lt_ret_t se_tropic_OTP_xor_consume(lt_handle_t *h, se_nv_otp_dir_t dir,
                               const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                               const uint8_t *msg, uint16_t len, uint8_t *out)
{
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint8_t image[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t image_len = 0U;
    uint16_t pad_len = 0U;
    uint16_t plain_max;
    uint32_t raw_slot = 0U;
    uint16_t slot = 0U;
    uint16_t i;
    lt_ret_t ret;

    if ((h == NULL) || (otp_dir_ok(dir) == 0) || (ss == NULL) || (msg == NULL) || (out == NULL) ||
        (len == 0u)) {
        return LT_PARAM_ERR;
    }

    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    if ((plain_max == 0U) || (len > plain_max)) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_qkd_cursor_get(h, dir, &raw_slot);
    if (ret != LT_OK) {
        return ret;
    }
    slot = (uint16_t)raw_slot;

    ret = se_nv_get_fill_id(fill_id);
    if (ret != LT_OK) {
        return (ret == SE_TROPIC_LT_TAMPERED) ? ret : LT_FAIL;
    }

    ret = lt_r_mem_data_read(h, slot, image, sizeof(image), &image_len);
    if (ret != LT_OK) {
        wc_ForceZero(fill_id, sizeof(fill_id));
        return ret;
    }

    ret = decrypt_qkd_pad_image(ss, fill_id, slot, image, image_len, s_pad, plain_max, &pad_len);
    wc_ForceZero(image, sizeof(image));
    wc_ForceZero(fill_id, sizeof(fill_id));
    if (ret != LT_OK) {
        wc_ForceZero(s_pad, sizeof(s_pad));
        return ret;
    }
    if (pad_len < len) {
        wc_ForceZero(s_pad, sizeof(s_pad));
        return LT_FAIL;
    }

    /* Advance before erase: lost pad on power-cut, never reuse. */
    ret = qkd_cursor_advance_from_slot(h, dir, slot);
    if (ret != LT_OK) {
        wc_ForceZero(s_pad, sizeof(s_pad));
        return ret;
    }

    ret = lt_r_mem_data_erase(h, slot);
    if (ret != LT_OK) {
        wc_ForceZero(s_pad, sizeof(s_pad));
        return ret;
    }

    for (i = 0U; i < len; i++) {
        out[i] = (uint8_t)(msg[i] ^ s_pad[i]);
    }
    wc_ForceZero(s_pad, sizeof(s_pad));
    return LT_OK;
}

void se_tropic_otp_xor_close(void)
{
    wc_ForceZero(s_otp_xor.ss, sizeof(s_otp_xor.ss));
    s_otp_xor.open = 0U;
    s_otp_xor.remaining = 0U;
    s_otp_xor.slots_needed = 0U;
    s_otp_xor.plain_max = 0U;
    s_otp_xor.by_pads = 0U;
    s_otp_xor.have_prev = 0U;
    s_otp_xor.prev_logical = 0U;
}

uint16_t se_tropic_otp_xor_pad_max(void)
{
    return s_otp_xor.open ? s_otp_xor.plain_max : 0U;
}

uint32_t se_tropic_otp_xor_bytes_left(void)
{
    return s_otp_xor.open ? s_otp_xor.remaining : 0U;
}

uint32_t se_tropic_otp_xor_pads_needed(void)
{
    return s_otp_xor.open ? s_otp_xor.slots_needed : 0U;
}

/** decrypt_half=0 layout: decrypt is the first pad half, encrypt the second. */
static uint32_t otp_unarmed_slots(se_nv_otp_dir_t dir)
{
    if (dir == SE_NV_OTP_DECRYPT) {
        return (uint32_t)SE_TROPIC_PAD_HALF;
    }
    return (uint32_t)SE_TROPIC_PAD_COUNT - (uint32_t)SE_TROPIC_PAD_HALF;
}

lt_ret_t se_tropic_otp_bytes_quota(lt_handle_t *h, se_nv_otp_dir_t dir,
                                   uint32_t *left_out, uint32_t *cap_out)
{
    uint32_t raw_slot = 0U;
    uint16_t half_base = 0U;
    uint16_t half_last = 0U;
    uint16_t pad_max;
    uint32_t slots;
    uint32_t cap;
    lt_ret_t ret;

    if ((h == NULL) || (otp_dir_ok(dir) == 0) || ((left_out == NULL) && (cap_out == NULL))) {
        return LT_PARAM_ERR;
    }
    if (left_out != NULL) {
        *left_out = 0U;
    }
    if (cap_out != NULL) {
        *cap_out = 0U;
    }

    pad_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    if (pad_max == 0U) {
        pad_max = SE_TROPIC_RMEM_PLAIN_MAX;
    }

    ret = otp_dir_range(dir, &half_base, &half_last);
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return ret;
    }
    if (ret != LT_OK) {
        cap = otp_unarmed_slots(dir) * (uint32_t)pad_max;
        if (cap_out != NULL) {
            *cap_out = cap;
        }
        return LT_OK;
    }

    slots = (uint32_t)half_last - (uint32_t)half_base + 1U;
    cap = slots * (uint32_t)pad_max;
    if (cap_out != NULL) {
        *cap_out = cap;
    }
    if (left_out == NULL) {
        return LT_OK;
    }

    ret = se_tropic_qkd_cursor_get(h, dir, &raw_slot);
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return ret;
    }
    if (ret != LT_OK) {
        return LT_OK;
    }
    if (((uint16_t)raw_slot < half_base) || ((uint16_t)raw_slot > half_last)) {
        return LT_OK;
    }

    slots = (uint32_t)half_last - (uint32_t)raw_slot + 1U;
    *left_out = slots * (uint32_t)pad_max;
    return LT_OK;
}

lt_ret_t se_tropic_otp_bytes_remaining(lt_handle_t *h, se_nv_otp_dir_t dir, uint32_t *bytes_out)
{
    return se_tropic_otp_bytes_quota(h, dir, bytes_out, NULL);
}

lt_ret_t se_tropic_otp_xor_open(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                    const uint8_t *add, uint8_t add_len, se_nv_otp_dir_t dir,
                                    uint32_t msg_len, uint32_t n_pads)
{
    uint32_t raw_slot = 0U;
    uint16_t half_base = 0U;
    uint16_t half_last = 0U;
    uint16_t first_slot;
    uint16_t last_slot;
    uint32_t slots32;
    lt_ret_t ret;

    se_tropic_otp_xor_close();

    if ((h == NULL) || (otp_dir_ok(dir) == 0) || (pin == NULL)) {
        return LT_PARAM_ERR;
    }

    s_otp_xor.plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    if (s_otp_xor.plain_max == 0U) {
        return LT_FAIL;
    }

    if (dir == SE_NV_OTP_ENCRYPT) {
        if (msg_len == 0U) {
            return LT_PARAM_ERR;
        }
        slots32 = (msg_len + (uint32_t)s_otp_xor.plain_max - 1U) / (uint32_t)s_otp_xor.plain_max;
        if (slots32 == 0U) {
            return LT_PARAM_ERR;
        }
        s_otp_xor.slots_needed = slots32;
        s_otp_xor.remaining = msg_len;
        s_otp_xor.by_pads = 0U;
    } else {
        if (n_pads == 0U) {
            return LT_PARAM_ERR;
        }
        s_otp_xor.slots_needed = n_pads;
        s_otp_xor.remaining = n_pads;
        s_otp_xor.by_pads = 1U;
    }

    ret = otp_dir_range(dir, &half_base, &half_last);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_qkd_cursor_get(h, dir, &raw_slot);
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return ret;
    }
    if (ret != LT_OK) {
        se_tropic_log("OTP cursor exhausted");
        return SE_TROPIC_LT_OTP_EXHAUSTED;
    }
    first_slot = (uint16_t)raw_slot;
    last_slot = keystream_slot_at_offset(first_slot, (uint16_t)(s_otp_xor.slots_needed - 1u));
    if ((first_slot < half_base) || (last_slot > half_last)) {
        se_tropic_log("OTP record exceeds half");
        return SE_TROPIC_LT_OTP_EXHAUSTED;
    }

    ret = se_tropic_mlkem_key_open(h, pin, pin_len, add, add_len);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_kem_ct_read(h, s_kem_ct);
    if (ret == LT_OK) {
        ret = se_tropic_mlkem_decapsulate(s_kem_ct, s_otp_xor.ss);
    }
    se_tropic_mlkem_key_close();
    wc_ForceZero(s_kem_ct, sizeof(s_kem_ct));
    if (ret != LT_OK) {
        se_tropic_otp_xor_close();
        return ret;
    }

    s_otp_xor.dir = dir;
    s_otp_xor.have_prev = 0U;
    s_otp_xor.open = 1U;
    return LT_OK;
}

lt_ret_t se_tropic_otp_xor_pad(lt_handle_t *h, const uint16_t *req_slot, const uint8_t *msg,
                                  uint16_t take, uint8_t *out, uint16_t *logical_slot,
                                  uint16_t *phys_slot)
{
    uint32_t raw_slot = 0U;
    uint16_t half_base = 0U;
    uint16_t half_last = 0U;
    uint16_t slot;
    uint16_t logical = 0U;
    lt_ret_t ret;

    if (logical_slot != NULL) {
        *logical_slot = 0U;
    }
    if (phys_slot != NULL) {
        *phys_slot = 0U;
    }
    if ((s_otp_xor.open == 0U) || (h == NULL) || (msg == NULL) || (out == NULL) || (take == 0U) ||
        (s_otp_xor.remaining == 0U) || (take > s_otp_xor.plain_max)) {
        return LT_PARAM_ERR;
    }
    if (s_otp_xor.by_pads != 0U) {
        if ((s_otp_xor.remaining > 1U) && (take != s_otp_xor.plain_max)) {
            return LT_PARAM_ERR;
        }
    } else {
        uint16_t expected = (s_otp_xor.remaining > (uint32_t)s_otp_xor.plain_max)
                                ? s_otp_xor.plain_max
                                : (uint16_t)s_otp_xor.remaining;

        if (take != expected) {
            return LT_PARAM_ERR;
        }
    }

    ret = otp_dir_range(s_otp_xor.dir, &half_base, &half_last);
    if (ret != LT_OK) {
        return ret;
    }

    if (s_otp_xor.dir == SE_NV_OTP_DECRYPT) {
        uint16_t target_phys = 0U;

        if (req_slot == NULL) {
            return LT_PARAM_ERR;
        }
        if ((s_otp_xor.have_prev != 0U) && (*req_slot != (uint16_t)(s_otp_xor.prev_logical + 1u))) {
            return LT_PARAM_ERR;
        }
        ret = se_tropic_get_phys_from_slot_index(*req_slot, &target_phys);
        if (ret != LT_OK) {
            return ret;
        }
        if ((target_phys < half_base) || (target_phys > half_last)) {
            se_tropic_log("OTP decrypt slot outside half");
            return LT_FAIL;
        }
        ret = se_tropic_qkd_cursor_get(h, s_otp_xor.dir, &raw_slot);
        if (ret != LT_OK) {
            return ret;
        }
        if (target_phys < (uint16_t)raw_slot) {
            se_tropic_log("OTP decrypt rewind refused");
            return LT_FAIL;
        }
        while ((uint16_t)raw_slot < target_phys) {
            ret = qkd_cursor_skip_one(h, s_otp_xor.dir);
            if (ret != LT_OK) {
                return ret;
            }
            ret = se_tropic_qkd_cursor_get(h, s_otp_xor.dir, &raw_slot);
            if (ret != LT_OK) {
                return ret;
            }
        }
    } else if (req_slot != NULL) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_qkd_cursor_get(h, s_otp_xor.dir, &raw_slot);
    if (ret != LT_OK) {
        return ret;
    }
    slot = (uint16_t)raw_slot;
    ret = se_tropic_get_slot_index_from_phys(slot, &logical);
    if (ret != LT_OK) {
        return ret;
    }

    ret = se_tropic_OTP_xor_consume(h, s_otp_xor.dir, s_otp_xor.ss, msg, take, out);
    if (ret != LT_OK) {
        wc_ForceZero(out, take);
        return ret;
    }

    if (s_otp_xor.by_pads != 0U) {
        s_otp_xor.remaining -= 1U;
    } else {
        s_otp_xor.remaining -= (uint32_t)take;
    }
    s_otp_xor.prev_logical = logical;
    s_otp_xor.have_prev = 1U;
    if (logical_slot != NULL) {
        *logical_slot = logical;
    }
    if (phys_slot != NULL) {
        *phys_slot = slot;
    }
    return LT_OK;
}

lt_ret_t se_tropic_otp_xor_message(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                    const uint8_t *add, uint8_t add_len, const uint8_t *msg,
                                    uint16_t len, uint8_t *out, se_nv_otp_dir_t dir,
                                    const uint16_t *req_slots, uint16_t req_slots_n,
                                    uint16_t *slot_used, uint16_t *logical_slots,
                                    uint16_t slots_cap, uint16_t *slots_n)
{
    uint16_t off = 0U;
    uint16_t i = 0U;
    uint32_t needed;
    uint16_t plain_max;
    lt_ret_t ret;

    if (slot_used != NULL) {
        *slot_used = 0U;
    }
    if (slots_n != NULL) {
        *slots_n = 0U;
    }
    if ((h == NULL) || (msg == NULL) || (out == NULL) || (len == 0u)) {
        return LT_PARAM_ERR;
    }
    if (dir == SE_NV_OTP_ENCRYPT) {
        if ((req_slots != NULL) || (req_slots_n != 0U)) {
            return LT_PARAM_ERR;
        }
    } else if ((req_slots == NULL) || (req_slots_n == 0U)) {
        return LT_PARAM_ERR;
    }

    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    if (plain_max == 0U) {
        return LT_FAIL;
    }
    if (dir == SE_NV_OTP_ENCRYPT) {
        ret = se_tropic_otp_xor_open(h, pin, pin_len, add, add_len, dir, (uint32_t)len, 0U);
    } else {
        ret = se_tropic_otp_xor_open(h, pin, pin_len, add, add_len, dir, 0U, (uint32_t)req_slots_n);
    }
    if (ret != LT_OK) {
        return ret;
    }

    needed = se_tropic_otp_xor_pads_needed();
    plain_max = se_tropic_otp_xor_pad_max();
    if ((logical_slots != NULL) && (needed > slots_cap)) {
        se_tropic_otp_xor_close();
        return LT_PARAM_ERR;
    }
    if (dir == SE_NV_OTP_DECRYPT) {
        if (req_slots_n != needed) {
            se_tropic_log("OTP decrypt slot count mismatch");
            se_tropic_otp_xor_close();
            return LT_PARAM_ERR;
        }
    }

    while (off < len) {
        uint16_t take = (uint16_t)(len - off);
        uint16_t logical = 0U;
        uint16_t phys = 0U;
        const uint16_t *req = NULL;

        if (take > plain_max) {
            take = plain_max;
        }
        if (dir == SE_NV_OTP_DECRYPT) {
            req = &req_slots[i];
        }
        ret = se_tropic_otp_xor_pad(h, req, msg + off, take, out + off, &logical, &phys);
        if (ret != LT_OK) {
            wc_ForceZero(out, len);
            break;
        }
        if ((i == 0U) && (slot_used != NULL)) {
            *slot_used = phys;
        }
        if (logical_slots != NULL) {
            logical_slots[i] = logical;
        }
        i = (uint16_t)(i + 1u);
        off = (uint16_t)(off + take);
    }

    if ((ret == LT_OK) && (slots_n != NULL)) {
        *slots_n = i;
    }
    se_tropic_otp_xor_close();
    return ret;
}
