/**
 * @file    se_tropic_cursor.c
 * @brief   QKD fill wipe, kem_ct, pad store, Tropic/MCU OTP cursors
 */
#include "se_tropic_rmem.h"
#include "se_tropic_rmem_internal.h"
#include "se_tropic_port.h"
#include "se_nv.h"
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

static uint8_t s_kem_ct[SE_TROPIC_KEM_CT_LEN];

static void write_kem_ct_storage_binding(uint16_t slot, const uint8_t fill_id[SE_NV_FILL_ID_LEN],
                                      uint8_t binding[34])
{
    write_storage_slot_binding(slot, binding);
    (void)memcpy(binding + 2, fill_id, SE_NV_FILL_ID_LEN);
}
static int is_valid_dir_cursor(uint32_t raw, se_nv_otp_dir_t dir, uint16_t *slot_out)
{
    uint16_t base = 0U;
    uint16_t last = 0U;

    if ((raw == SE_TROPIC_QKD_CURSOR_END) || (raw > SE_TROPIC_QKD_SLOT_LAST) ||
        (se_tropic_slot_is_keystream((uint16_t)raw) == 0)) {
        return 0;
    }
    if (se_tropic_otp_dir_range(dir, &base, &last) != LT_OK) {
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
    lt_ret_t ret = lt_mcounter_init(h, se_tropic_otp_mcounter(dir), SE_TROPIC_QKD_CURSOR_END);
    if (ret == LT_OK) {
        ret = se_nv_set_cursor(dir, (uint16_t)(SE_TROPIC_QKD_SLOT_LAST + 1u));
    }
    return ret;
}

/** Advance the keystream cursor by one slot after consume. */
lt_ret_t se_tropic_qkd_cursor_advance_from_slot(lt_handle_t *h, se_nv_otp_dir_t dir, uint16_t current)
{
    uint16_t base = 0U;
    uint16_t last = 0U;
    uint16_t next;
    lt_ret_t ret;

    ret = se_tropic_otp_dir_range(dir, &base, &last);
    if (ret != LT_OK) {
        return ret;
    }
    if (current >= last) {
        return qkd_cursor_set_exhausted(h, dir);
    }
    next = (uint16_t)(current + 1u);
    /* Tropic first, then MCU NV (power-cut between may look like tamper). */
    ret = lt_mcounter_init(h, se_tropic_otp_mcounter(dir), (uint32_t)next);
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
            se_tropic_log_fail("QKD wipe fail", ret);
            return ret;
        }
    }

    se_tropic_log("QKD provision wipe slots");
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
    se_tropic_log("QKD halves armed");
    return LT_OK;
}

lt_ret_t se_tropic_qkd_cursor_init(lt_handle_t *h, se_nv_otp_dir_t dir, uint16_t start_slot)
{
    if ((h == NULL) || (se_tropic_otp_dir_ok(dir) == 0) || (se_tropic_slot_is_keystream(start_slot) == 0)) {
        return LT_PARAM_ERR;
    }
    return lt_mcounter_init(h, se_tropic_otp_mcounter(dir), (uint32_t)start_slot);
}

lt_ret_t se_tropic_qkd_cursor_get(lt_handle_t *h, se_nv_otp_dir_t dir, uint32_t *next_slot)
{
    uint32_t tropic_raw = 0U;
    uint16_t mcu_cursor = 0U;
    lt_ret_t ret;

    if ((h == NULL) || (next_slot == NULL) || (se_tropic_otp_dir_ok(dir) == 0)) {
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

    ret = lt_mcounter_get(h, se_tropic_otp_mcounter(dir), &tropic_raw);
    if (ret != LT_OK) {
        return ret;
    }
    if (tropic_raw != (uint32_t)mcu_cursor) {
        se_tropic_log("failed");
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

    if ((h == NULL) || (se_tropic_otp_dir_ok(dir) == 0)) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_qkd_cursor_get(h, dir, &raw);
    if (ret != LT_OK) {
        return ret;
    }
    slot = (uint16_t)raw;
    return se_tropic_qkd_cursor_advance_from_slot(h, dir, slot);
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

    ret = se_tropic_load_device_storage_key(key);
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
    ret = se_tropic_load_device_storage_key(key);
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
lt_ret_t se_tropic_qkd_cursor_skip_one(lt_handle_t *h, se_nv_otp_dir_t dir)
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
    return se_tropic_qkd_cursor_advance_from_slot(h, dir, slot);
}
