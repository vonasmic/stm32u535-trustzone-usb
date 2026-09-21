/**
 * @file    se_tropic_rmem_internal.h
 * @brief   Shared R-MEM helpers for aead / cursor / otp_xor translation units
 */
#ifndef SE_TROPIC_RMEM_INTERNAL_H
#define SE_TROPIC_RMEM_INTERNAL_H

#include "se_tropic_rmem.h"
#include "se_tropic_port.h"

static inline int se_tropic_otp_dir_ok(se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_ENCRYPT) || (dir == SE_NV_OTP_DECRYPT);
}

static inline enum lt_mcounter_index_t se_tropic_otp_mcounter(se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_DECRYPT) ? SE_TROPIC_QKD_MCOUNTER_DECRYPT
                                      : SE_TROPIC_QKD_MCOUNTER_ENCRYPT;
}

static inline uint16_t se_tropic_otp_half_last(uint16_t this_base, uint16_t other_base)
{
    if (this_base < other_base) {
        return (uint16_t)(other_base - 1u);
    }
    return SE_TROPIC_QKD_SLOT_LAST;
}

static inline lt_ret_t se_tropic_otp_dir_range(se_nv_otp_dir_t dir, uint16_t *base, uint16_t *last)
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
        *last = se_tropic_otp_half_last(base_decrypt, base_encrypt);
    } else {
        *base = base_encrypt;
        *last = se_tropic_otp_half_last(base_encrypt, base_decrypt);
    }
    return LT_OK;
}

static inline lt_ret_t se_tropic_load_device_storage_key(uint8_t out[SE_TROPIC_RMEM_AES_KEY_LEN])
{
    return se_tropic_port_device_aead_key(out);
}

uint16_t se_tropic_keystream_slot_at_offset(uint16_t base, uint16_t index);
lt_ret_t se_tropic_qkd_cursor_advance_from_slot(lt_handle_t *h, se_nv_otp_dir_t dir,
                                               uint16_t current);
lt_ret_t se_tropic_qkd_cursor_skip_one(lt_handle_t *h, se_nv_otp_dir_t dir);

#endif /* SE_TROPIC_RMEM_INTERNAL_H */
