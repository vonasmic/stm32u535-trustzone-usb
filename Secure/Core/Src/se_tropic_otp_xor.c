/**
 * @file    se_tropic_otp_xor.c
 * @brief   PIN-gated OTP pad consume (open / pad / close)
 */
#include "se_tropic_rmem.h"
#include "se_tropic_rmem_internal.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_pin.h"
#include "se_tropic_port.h"
#include "se_nv.h"
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

static uint8_t s_pad[SE_TROPIC_RMEM_PLAIN_MAX];
static uint8_t s_kem_ct[SE_TROPIC_KEM_CT_LEN];

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

    if ((h == NULL) || (se_tropic_otp_dir_ok(dir) == 0) || (ss == NULL) || (msg == NULL) || (out == NULL) ||
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
    ret = se_tropic_qkd_cursor_advance_from_slot(h, dir, slot);
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

    if ((h == NULL) || (se_tropic_otp_dir_ok(dir) == 0) || ((left_out == NULL) && (cap_out == NULL))) {
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

    ret = se_tropic_otp_dir_range(dir, &half_base, &half_last);
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

    if ((h == NULL) || (se_tropic_otp_dir_ok(dir) == 0) || (pin == NULL)) {
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

    ret = se_tropic_otp_dir_range(dir, &half_base, &half_last);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_qkd_cursor_get(h, dir, &raw_slot);
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return ret;
    }
    if (ret != LT_OK) {
        return SE_TROPIC_LT_OTP_EXHAUSTED;
    }
    first_slot = (uint16_t)raw_slot;
    last_slot = se_tropic_keystream_slot_at_offset(first_slot, (uint16_t)(s_otp_xor.slots_needed - 1u));
    if ((first_slot < half_base) || (last_slot > half_last)) {
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

    ret = se_tropic_otp_dir_range(s_otp_xor.dir, &half_base, &half_last);
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
            return LT_FAIL;
        }
        ret = se_tropic_qkd_cursor_get(h, s_otp_xor.dir, &raw_slot);
        if (ret != LT_OK) {
            return ret;
        }
        if (target_phys < (uint16_t)raw_slot) {
            return LT_FAIL;
        }
        while ((uint16_t)raw_slot < target_phys) {
            ret = se_tropic_qkd_cursor_skip_one(h, s_otp_xor.dir);
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
