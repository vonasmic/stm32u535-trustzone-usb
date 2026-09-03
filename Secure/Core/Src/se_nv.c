/**
 * @file    se_nv.c
 * @brief   Sealed MCU NV for fill_id, dual OTP cursors, TIME floor, and pairing key
 */
#include "se_nv.h"
#include "se_le.h"
#include "se_tropic_port.h"
#include "se_tropic_rmem.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>

#define SE_NV_PLAIN_CORE_LEN \
    (SE_NV_FILL_ID_LEN + 8u + 4u + 4u) /* fill_id || 4*u16 cursors || time || flags */
#define SE_NV_PLAIN_LEN \
    (SE_NV_PLAIN_CORE_LEN + 1u + SE_NV_PAIRING_KEY_LEN + SE_NV_PAIRING_KEY_LEN)
#define SE_NV_BLOB_LEN (SE_TROPIC_RMEM_OVERHEAD + SE_NV_PLAIN_LEN)
#define SE_NV_BLOB_MAX SE_NV_BLOB_LEN

static const uint8_t k_nv_aad[] = "SE_nv_v3";

static uint8_t s_pending_fill[SE_NV_FILL_ID_LEN];
static uint8_t s_pending_valid;

static int otp_dir_ok(se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_ENCRYPT) || (dir == SE_NV_OTP_DECRYPT);
}

static uint16_t *cursor_field(se_nv_state_t *st, se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_DECRYPT) ? &st->cursor_decrypt : &st->cursor_encrypt;
}

static void pack_core(const se_nv_state_t *in, uint8_t *plain)
{
    (void)memcpy(plain, in->fill_id, SE_NV_FILL_ID_LEN);
    se_put_u16le(plain + SE_NV_FILL_ID_LEN, in->cursor_encrypt);
    se_put_u16le(plain + SE_NV_FILL_ID_LEN + 2u, in->cursor_decrypt);
    se_put_u16le(plain + SE_NV_FILL_ID_LEN + 4u, in->base_encrypt);
    se_put_u16le(plain + SE_NV_FILL_ID_LEN + 6u, in->base_decrypt);
    se_put_u32le(plain + SE_NV_FILL_ID_LEN + 8u, in->time_floor);
    se_put_u32le(plain + SE_NV_FILL_ID_LEN + 12u, in->flags);
}

static void unpack_core(const uint8_t *plain, se_nv_state_t *out)
{
    (void)memcpy(out->fill_id, plain, SE_NV_FILL_ID_LEN);
    out->cursor_encrypt = se_u16le(plain + SE_NV_FILL_ID_LEN);
    out->cursor_decrypt = se_u16le(plain + SE_NV_FILL_ID_LEN + 2u);
    out->base_encrypt = se_u16le(plain + SE_NV_FILL_ID_LEN + 4u);
    out->base_decrypt = se_u16le(plain + SE_NV_FILL_ID_LEN + 6u);
    out->time_floor = se_u32le(plain + SE_NV_FILL_ID_LEN + 8u);
    out->flags = se_u32le(plain + SE_NV_FILL_ID_LEN + 12u);
}

static void pack_plain(const se_nv_state_t *in, uint8_t plain[SE_NV_PLAIN_LEN])
{
    pack_core(in, plain);
    plain[SE_NV_PLAIN_CORE_LEN] = in->pairing_slot;
    (void)memcpy(plain + SE_NV_PLAIN_CORE_LEN + 1u, in->pairing_priv, SE_NV_PAIRING_KEY_LEN);
    (void)memcpy(plain + SE_NV_PLAIN_CORE_LEN + 1u + SE_NV_PAIRING_KEY_LEN, in->pairing_pub,
                 SE_NV_PAIRING_KEY_LEN);
}

static void unpack_plain(const uint8_t plain[SE_NV_PLAIN_LEN], se_nv_state_t *out)
{
    unpack_core(plain, out);
    out->pairing_slot = plain[SE_NV_PLAIN_CORE_LEN];
    (void)memcpy(out->pairing_priv, plain + SE_NV_PLAIN_CORE_LEN + 1u, SE_NV_PAIRING_KEY_LEN);
    (void)memcpy(out->pairing_pub, plain + SE_NV_PLAIN_CORE_LEN + 1u + SE_NV_PAIRING_KEY_LEN,
                 SE_NV_PAIRING_KEY_LEN);
}

static int page_is_erased(const uint8_t *blob, uint16_t len)
{
    uint16_t i;

    for (i = 0U; i < len; i++) {
        if (blob[i] != 0xffu) {
            return 0;
        }
    }
    return 1;
}

static void nv_state_wipe_secrets(se_nv_state_t *st)
{
    if (st != NULL) {
        wc_ForceZero(st->pairing_priv, sizeof(st->pairing_priv));
    }
}

lt_ret_t se_nv_load(se_nv_state_t *out)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t blob[SE_NV_BLOB_MAX];
    uint8_t plain[SE_NV_PLAIN_LEN];
    uint16_t plain_len = 0U;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memset(out, 0, sizeof(*out));

    ret = se_tropic_port_nv_raw_read(blob, sizeof(blob));
    if (ret != LT_OK) {
        return ret;
    }
    if (page_is_erased(blob, sizeof(blob)) != 0) {
        return LT_OK;
    }

    ret = se_tropic_port_device_aead_key(key);
    if (ret != LT_OK) {
        return ret;
    }

    ret = se_tropic_decrypt_storage_blob(key, k_nv_aad, (uint16_t)(sizeof(k_nv_aad) - 1u), blob,
                                         SE_NV_BLOB_LEN, plain, sizeof(plain), &plain_len);
    wc_ForceZero(key, sizeof(key));
    if (ret != LT_OK) {
        wc_ForceZero(plain, sizeof(plain));
        return SE_TROPIC_LT_TAMPERED;
    }
    if (plain_len != SE_NV_PLAIN_LEN) {
        wc_ForceZero(plain, sizeof(plain));
        return SE_TROPIC_LT_TAMPERED;
    }
    unpack_plain(plain, out);
    wc_ForceZero(plain, sizeof(plain));
    return LT_OK;
}

lt_ret_t se_nv_store(const se_nv_state_t *in)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t plain[SE_NV_PLAIN_LEN];
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t blob[SE_NV_BLOB_MAX];
    uint16_t blob_len = sizeof(blob);
    lt_ret_t ret;

    if (in == NULL) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_port_device_aead_key(key);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_port_nv_random(nonce, sizeof(nonce));
    if (ret != LT_OK) {
        wc_ForceZero(key, sizeof(key));
        return ret;
    }

    pack_plain(in, plain);
    ret = se_tropic_encrypt_storage_blob(key, k_nv_aad, (uint16_t)(sizeof(k_nv_aad) - 1u), plain,
                                         SE_NV_PLAIN_LEN, nonce, blob, &blob_len);
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(plain, sizeof(plain));
    wc_ForceZero(nonce, sizeof(nonce));
    if (ret != LT_OK) {
        wc_ForceZero(blob, sizeof(blob));
        return ret;
    }

    ret = se_tropic_port_nv_raw_write(blob, blob_len);
    wc_ForceZero(blob, sizeof(blob));
    return ret;
}

int se_nv_have_fill(void)
{
    se_nv_state_t st;
    lt_ret_t ret = se_nv_load(&st);
    int have;

    if (ret != LT_OK) {
        return 0;
    }
    have = ((st.flags & SE_NV_FLAG_FILL) != 0U) ? 1 : 0;
    nv_state_wipe_secrets(&st);
    return have;
}

lt_ret_t se_nv_get_fill_id(uint8_t out[SE_NV_FILL_ID_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if ((st.flags & SE_NV_FLAG_FILL) == 0U) {
        nv_state_wipe_secrets(&st);
        return LT_FAIL;
    }
    (void)memcpy(out, st.fill_id, SE_NV_FILL_ID_LEN);
    nv_state_wipe_secrets(&st);
    return LT_OK;
}

lt_ret_t se_nv_get_cursor(se_nv_otp_dir_t dir, uint16_t *cursor)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((cursor == NULL) || (otp_dir_ok(dir) == 0)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if (((st.flags & SE_NV_FLAG_FILL) == 0U) || ((st.flags & SE_NV_FLAG_OTP) == 0U)) {
        nv_state_wipe_secrets(&st);
        return LT_FAIL;
    }
    *cursor = *cursor_field(&st, dir);
    nv_state_wipe_secrets(&st);
    return LT_OK;
}

lt_ret_t se_nv_commit_fill(const uint8_t fill_id[SE_NV_FILL_ID_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;

    if (fill_id == NULL) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memcpy(st.fill_id, fill_id, SE_NV_FILL_ID_LEN);
    st.cursor_encrypt = 0U;
    st.cursor_decrypt = 0U;
    st.base_encrypt = 0U;
    st.base_decrypt = 0U;
    st.flags |= SE_NV_FLAG_FILL;
    st.flags &= ~SE_NV_FLAG_OTP;
    se_nv_pending_fill_clear();
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_arm_otp_cursors(uint16_t base_encrypt, uint16_t base_decrypt)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if (base_encrypt == base_decrypt) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if ((st.flags & SE_NV_FLAG_FILL) == 0U) {
        nv_state_wipe_secrets(&st);
        return LT_FAIL;
    }
    st.base_encrypt = base_encrypt;
    st.base_decrypt = base_decrypt;
    st.cursor_encrypt = base_encrypt;
    st.cursor_decrypt = base_decrypt;
    st.flags |= SE_NV_FLAG_OTP;
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_get_otp_bases(uint16_t *base_encrypt, uint16_t *base_decrypt)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((base_encrypt == NULL) || (base_decrypt == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if (((st.flags & SE_NV_FLAG_FILL) == 0U) || ((st.flags & SE_NV_FLAG_OTP) == 0U)) {
        nv_state_wipe_secrets(&st);
        return LT_FAIL;
    }
    *base_encrypt = st.base_encrypt;
    *base_decrypt = st.base_decrypt;
    nv_state_wipe_secrets(&st);
    return LT_OK;
}

lt_ret_t se_nv_set_cursor(se_nv_otp_dir_t dir, uint16_t cursor)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if (otp_dir_ok(dir) == 0) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if (((st.flags & SE_NV_FLAG_FILL) == 0U) || ((st.flags & SE_NV_FLAG_OTP) == 0U)) {
        nv_state_wipe_secrets(&st);
        return LT_FAIL;
    }
    *cursor_field(&st, dir) = cursor;
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_set_time_floor(uint32_t unix_utc)
{
    se_nv_state_t st;
    lt_ret_t ret;

    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    st.time_floor = unix_utc;
    st.flags |= SE_NV_FLAG_TIME;
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_get_time_floor(uint32_t *unix_utc, int *present)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((unix_utc == NULL) || (present == NULL)) {
        return LT_PARAM_ERR;
    }
    *present = 0;
    *unix_utc = 0U;
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if ((st.flags & SE_NV_FLAG_TIME) == 0U) {
        nv_state_wipe_secrets(&st);
        return LT_OK;
    }
    *unix_utc = st.time_floor;
    *present = 1;
    nv_state_wipe_secrets(&st);
    return LT_OK;
}

lt_ret_t se_nv_set_pairing(uint8_t slot, const uint8_t priv[SE_NV_PAIRING_KEY_LEN],
                           const uint8_t pub[SE_NV_PAIRING_KEY_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((priv == NULL) || (pub == NULL) || (slot < (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_1) ||
        (slot > (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_3)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    st.pairing_slot = slot;
    (void)memcpy(st.pairing_priv, priv, SE_NV_PAIRING_KEY_LEN);
    (void)memcpy(st.pairing_pub, pub, SE_NV_PAIRING_KEY_LEN);
    st.flags |= SE_NV_FLAG_PAIRING;
    ret = se_nv_store(&st);
    wc_ForceZero(st.pairing_priv, sizeof(st.pairing_priv));
    return ret;
}

lt_ret_t se_nv_get_pairing(uint8_t *slot, uint8_t priv[SE_NV_PAIRING_KEY_LEN],
                           uint8_t pub[SE_NV_PAIRING_KEY_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((slot == NULL) || (priv == NULL) || (pub == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if ((st.flags & SE_NV_FLAG_PAIRING) == 0U) {
        wc_ForceZero(st.pairing_priv, sizeof(st.pairing_priv));
        return LT_FAIL;
    }
    if ((st.pairing_slot < (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_1) ||
        (st.pairing_slot > (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_3)) {
        wc_ForceZero(st.pairing_priv, sizeof(st.pairing_priv));
        return SE_TROPIC_LT_TAMPERED;
    }
    *slot = st.pairing_slot;
    (void)memcpy(priv, st.pairing_priv, SE_NV_PAIRING_KEY_LEN);
    (void)memcpy(pub, st.pairing_pub, SE_NV_PAIRING_KEY_LEN);
    wc_ForceZero(st.pairing_priv, sizeof(st.pairing_priv));
    return LT_OK;
}

void se_nv_pending_fill_set(const uint8_t fill_id[SE_NV_FILL_ID_LEN])
{
    if (fill_id == NULL) {
        return;
    }
    (void)memcpy(s_pending_fill, fill_id, SE_NV_FILL_ID_LEN);
    s_pending_valid = 1U;
}

int se_nv_pending_fill_take(uint8_t fill_id[SE_NV_FILL_ID_LEN])
{
    if ((fill_id == NULL) || (s_pending_valid == 0U)) {
        return 0;
    }
    (void)memcpy(fill_id, s_pending_fill, SE_NV_FILL_ID_LEN);
    se_nv_pending_fill_clear();
    return 1;
}

void se_nv_pending_fill_clear(void)
{
    wc_ForceZero(s_pending_fill, sizeof(s_pending_fill));
    s_pending_valid = 0U;
}
