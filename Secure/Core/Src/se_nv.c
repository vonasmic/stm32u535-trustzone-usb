/**
 * @file    se_nv.c
 * @brief   Sealed MCU NV for fill_id, dual OTP cursors, TIME floor, pairing, peers
 *
 * Blob/plain working buffers live in BSS: v4 plaintext is ~506 B, too large for
 * the Secure 1 KB stack together with se_nv_state_t.
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
#define SE_NV_PLAIN_V3_LEN \
    (SE_NV_PLAIN_CORE_LEN + 1u + SE_NV_PAIRING_KEY_LEN + SE_NV_PAIRING_KEY_LEN)
#define SE_NV_PEER_SLOT_LEN (1u + SE_NV_PEER_NAME_MAX + SE_NV_PEER_HASH_LEN)
#define SE_NV_PLAIN_LEN (SE_NV_PLAIN_V3_LEN + 1u + (SE_NV_PEER_MAX * SE_NV_PEER_SLOT_LEN))
#define SE_NV_BLOB_LEN (SE_TROPIC_RMEM_OVERHEAD + SE_NV_PLAIN_LEN)
#define SE_NV_BLOB_V3_LEN (SE_TROPIC_RMEM_OVERHEAD + SE_NV_PLAIN_V3_LEN)
#define SE_NV_BLOB_MAX SE_NV_BLOB_LEN

static const uint8_t k_nv_aad_v4[] = "SE_nv_v4";
static const uint8_t k_nv_aad_v3[] = "SE_nv_v3";

static uint8_t s_pending_fill[SE_NV_FILL_ID_LEN];
static uint8_t s_pending_valid;
static uint8_t s_nv_blob[SE_NV_BLOB_MAX];
static uint8_t s_nv_plain[SE_NV_PLAIN_LEN];

static int otp_dir_ok(se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_ENCRYPT) || (dir == SE_NV_OTP_DECRYPT);
}

static uint16_t *cursor_field(se_nv_state_t *st, se_nv_otp_dir_t dir)
{
    return (dir == SE_NV_OTP_DECRYPT) ? &st->cursor_decrypt : &st->cursor_encrypt;
}

static int peer_name_char_ok(uint8_t c)
{
    return ((c >= (uint8_t)'A') && (c <= (uint8_t)'Z')) ||
           ((c >= (uint8_t)'a') && (c <= (uint8_t)'z')) ||
           ((c >= (uint8_t)'0') && (c <= (uint8_t)'9')) || (c == (uint8_t)'_') ||
           (c == (uint8_t)'.') || (c == (uint8_t)'-');
}

static int peer_name_ok(const uint8_t *name, uint8_t name_len)
{
    uint8_t i;

    if ((name == NULL) || (name_len < 1u) || (name_len > SE_NV_PEER_NAME_MAX)) {
        return 0;
    }
    for (i = 0U; i < name_len; i++) {
        if (peer_name_char_ok(name[i]) == 0) {
            return 0;
        }
    }
    return 1;
}

static int peer_names_equal(const uint8_t *a, uint8_t a_len, const uint8_t *b, uint8_t b_len)
{
    if (a_len != b_len) {
        return 0;
    }
    return (memcmp(a, b, a_len) == 0) ? 1 : 0;
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

static void pack_pairing(const se_nv_state_t *in, uint8_t *plain)
{
    plain[SE_NV_PLAIN_CORE_LEN] = in->pairing_slot;
    (void)memcpy(plain + SE_NV_PLAIN_CORE_LEN + 1u, in->pairing_priv, SE_NV_PAIRING_KEY_LEN);
    (void)memcpy(plain + SE_NV_PLAIN_CORE_LEN + 1u + SE_NV_PAIRING_KEY_LEN, in->pairing_pub,
                 SE_NV_PAIRING_KEY_LEN);
}

static void unpack_pairing(const uint8_t *plain, se_nv_state_t *out)
{
    out->pairing_slot = plain[SE_NV_PLAIN_CORE_LEN];
    (void)memcpy(out->pairing_priv, plain + SE_NV_PLAIN_CORE_LEN + 1u, SE_NV_PAIRING_KEY_LEN);
    (void)memcpy(out->pairing_pub, plain + SE_NV_PLAIN_CORE_LEN + 1u + SE_NV_PAIRING_KEY_LEN,
                 SE_NV_PAIRING_KEY_LEN);
}

static void pack_plain(const se_nv_state_t *in, uint8_t plain[SE_NV_PLAIN_LEN])
{
    uint8_t *p;
    uint8_t i;

    pack_core(in, plain);
    pack_pairing(in, plain);
    p = plain + SE_NV_PLAIN_V3_LEN;
    *p++ = in->peer_count;
    for (i = 0U; i < SE_NV_PEER_MAX; i++) {
        p[0] = in->peers[i].name_len;
        (void)memcpy(p + 1u, in->peers[i].name, SE_NV_PEER_NAME_MAX);
        (void)memcpy(p + 1u + SE_NV_PEER_NAME_MAX, in->peers[i].hash, SE_NV_PEER_HASH_LEN);
        p += SE_NV_PEER_SLOT_LEN;
    }
}

static lt_ret_t unpack_peers(const uint8_t *plain, se_nv_state_t *out)
{
    const uint8_t *p = plain + SE_NV_PLAIN_V3_LEN;
    uint8_t i;
    uint8_t nlen;

    out->peer_count = *p++;
    if (out->peer_count > SE_NV_PEER_MAX) {
        return SE_TROPIC_LT_TAMPERED;
    }
    for (i = 0U; i < SE_NV_PEER_MAX; i++) {
        nlen = p[0];
        if (nlen > SE_NV_PEER_NAME_MAX) {
            return SE_TROPIC_LT_TAMPERED;
        }
        if (i < out->peer_count) {
            if (peer_name_ok(p + 1u, nlen) == 0) {
                return SE_TROPIC_LT_TAMPERED;
            }
        } else if (nlen != 0U) {
            return SE_TROPIC_LT_TAMPERED;
        }
        out->peers[i].name_len = nlen;
        (void)memcpy(out->peers[i].name, p + 1u, SE_NV_PEER_NAME_MAX);
        (void)memcpy(out->peers[i].hash, p + 1u + SE_NV_PEER_NAME_MAX, SE_NV_PEER_HASH_LEN);
        p += SE_NV_PEER_SLOT_LEN;
    }
    return LT_OK;
}

static void unpack_plain_v3(const uint8_t *plain, se_nv_state_t *out)
{
    unpack_core(plain, out);
    unpack_pairing(plain, out);
    out->peer_count = 0U;
    (void)memset(out->peers, 0, sizeof(out->peers));
}

static lt_ret_t unpack_plain_v4(const uint8_t *plain, se_nv_state_t *out)
{
    unpack_core(plain, out);
    unpack_pairing(plain, out);
    return unpack_peers(plain, out);
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

static void nv_work_wipe(void)
{
    wc_ForceZero(s_nv_plain, sizeof(s_nv_plain));
    wc_ForceZero(s_nv_blob, sizeof(s_nv_blob));
}

lt_ret_t se_nv_load(se_nv_state_t *out)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint16_t plain_len = 0U;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memset(out, 0, sizeof(*out));

    ret = se_tropic_port_nv_raw_read(s_nv_blob, sizeof(s_nv_blob));
    if (ret != LT_OK) {
        nv_work_wipe();
        return ret;
    }
    if (page_is_erased(s_nv_blob, sizeof(s_nv_blob)) != 0) {
        nv_work_wipe();
        return LT_OK;
    }

    ret = se_tropic_port_device_aead_key(key);
    if (ret != LT_OK) {
        nv_work_wipe();
        return ret;
    }

    plain_len = 0U;
    ret = se_tropic_decrypt_storage_blob(key, k_nv_aad_v4, (uint16_t)(sizeof(k_nv_aad_v4) - 1u),
                                         s_nv_blob, SE_NV_BLOB_LEN, s_nv_plain, sizeof(s_nv_plain),
                                         &plain_len);
    if ((ret == LT_OK) && (plain_len == SE_NV_PLAIN_LEN)) {
        ret = unpack_plain_v4(s_nv_plain, out);
        wc_ForceZero(key, sizeof(key));
        nv_work_wipe();
        if (ret != LT_OK) {
            (void)memset(out, 0, sizeof(*out));
            return SE_TROPIC_LT_TAMPERED;
        }
        return LT_OK;
    }

    plain_len = 0U;
    ret = se_tropic_decrypt_storage_blob(key, k_nv_aad_v3, (uint16_t)(sizeof(k_nv_aad_v3) - 1u),
                                         s_nv_blob, SE_NV_BLOB_V3_LEN, s_nv_plain,
                                         SE_NV_PLAIN_V3_LEN, &plain_len);
    wc_ForceZero(key, sizeof(key));
    if ((ret == LT_OK) && (plain_len == SE_NV_PLAIN_V3_LEN)) {
        unpack_plain_v3(s_nv_plain, out);
        nv_work_wipe();
        return LT_OK;
    }
    nv_work_wipe();
    (void)memset(out, 0, sizeof(*out));
    return SE_TROPIC_LT_TAMPERED;
}

lt_ret_t se_nv_store(const se_nv_state_t *in)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    uint16_t blob_len = sizeof(s_nv_blob);
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

    pack_plain(in, s_nv_plain);
    ret = se_tropic_encrypt_storage_blob(key, k_nv_aad_v4, (uint16_t)(sizeof(k_nv_aad_v4) - 1u),
                                         s_nv_plain, SE_NV_PLAIN_LEN, nonce, s_nv_blob, &blob_len);
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(s_nv_plain, sizeof(s_nv_plain));
    wc_ForceZero(nonce, sizeof(nonce));
    if (ret != LT_OK) {
        wc_ForceZero(s_nv_blob, sizeof(s_nv_blob));
        return ret;
    }

    ret = se_tropic_port_nv_raw_write(s_nv_blob, blob_len);
    wc_ForceZero(s_nv_blob, sizeof(s_nv_blob));
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

lt_ret_t se_nv_peer_add(const uint8_t *name, uint8_t name_len,
                        const uint8_t hash32[SE_NV_PEER_HASH_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t i;

    if ((hash32 == NULL) || (peer_name_ok(name, name_len) == 0)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    for (i = 0U; i < st.peer_count; i++) {
        if (peer_names_equal(st.peers[i].name, st.peers[i].name_len, name, name_len) != 0) {
            nv_state_wipe_secrets(&st);
            return SE_NV_PEER_EXISTS;
        }
    }
    if (st.peer_count >= SE_NV_PEER_MAX) {
        nv_state_wipe_secrets(&st);
        return SE_NV_PEER_FULL;
    }
    i = st.peer_count;
    st.peers[i].name_len = name_len;
    (void)memset(st.peers[i].name, 0, SE_NV_PEER_NAME_MAX);
    (void)memcpy(st.peers[i].name, name, name_len);
    (void)memcpy(st.peers[i].hash, hash32, SE_NV_PEER_HASH_LEN);
    st.peer_count = (uint8_t)(st.peer_count + 1u);
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_peer_remove(const uint8_t *name, uint8_t name_len)
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t i;
    uint8_t found = SE_NV_PEER_MAX;

    if (peer_name_ok(name, name_len) == 0) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    for (i = 0U; i < st.peer_count; i++) {
        if (peer_names_equal(st.peers[i].name, st.peers[i].name_len, name, name_len) != 0) {
            found = i;
            break;
        }
    }
    if (found >= SE_NV_PEER_MAX) {
        nv_state_wipe_secrets(&st);
        return SE_NV_PEER_NOT_FOUND;
    }
    for (i = found; i + 1u < st.peer_count; i++) {
        st.peers[i] = st.peers[i + 1u];
    }
    st.peer_count = (uint8_t)(st.peer_count - 1u);
    (void)memset(&st.peers[st.peer_count], 0, sizeof(st.peers[0]));
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_peer_count(uint8_t *count)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if (count == NULL) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    *count = st.peer_count;
    nv_state_wipe_secrets(&st);
    return LT_OK;
}

lt_ret_t se_nv_peer_get(uint8_t index, uint8_t *name, uint8_t *name_len,
                        uint8_t hash32[SE_NV_PEER_HASH_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t nlen;
    uint8_t cap;

    if ((name == NULL) || (name_len == NULL) || (hash32 == NULL)) {
        return LT_PARAM_ERR;
    }
    cap = *name_len;
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if (index >= st.peer_count) {
        nv_state_wipe_secrets(&st);
        return SE_NV_PEER_NOT_FOUND;
    }
    nlen = st.peers[index].name_len;
    if (cap < nlen) {
        nv_state_wipe_secrets(&st);
        return LT_PARAM_ERR;
    }
    (void)memcpy(name, st.peers[index].name, nlen);
    (void)memcpy(hash32, st.peers[index].hash, SE_NV_PEER_HASH_LEN);
    *name_len = nlen;
    nv_state_wipe_secrets(&st);
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
