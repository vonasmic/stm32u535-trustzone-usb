/**
 * @file    se_nv.c
 * @brief   Sealed MCU NV for fill_id, dual OTP cursors, TIME floor, pairing, peers
 *
 * Blob/plain working buffers live in BSS: v5 plaintext is ~634 B, too large for
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
#define SE_NV_EXTRA_LEN \
    (2u + SE_NV_OWNER_SPKI_MAX + SE_NV_PW_HASH_LEN + 2u + SE_NV_WRAP_MAX + 2u + SE_NV_MLKEM_MAX)
#define SE_NV_PLAIN_V6_LEN (SE_NV_PLAIN_LEN + SE_NV_EXTRA_LEN)
#define SE_NV_BLOB_V6_LEN (SE_TROPIC_RMEM_OVERHEAD + SE_NV_PLAIN_V6_LEN)
/* v4 held SHA-256 peer hashes; kept only to recognise and migrate an older page. */
#define SE_NV_PEER_SLOT_V4_LEN (1u + SE_NV_PEER_NAME_MAX + 32u)
#define SE_NV_PLAIN_V4_LEN (SE_NV_PLAIN_V3_LEN + 1u + (SE_NV_PEER_MAX * SE_NV_PEER_SLOT_V4_LEN))
#define SE_NV_BLOB_V4_LEN (SE_TROPIC_RMEM_OVERHEAD + SE_NV_PLAIN_V4_LEN)
#define SE_NV_BLOB_V3_LEN (SE_TROPIC_RMEM_OVERHEAD + SE_NV_PLAIN_V3_LEN)
#define SE_NV_BLOB_MAX SE_NV_BLOB_V6_LEN

static const uint8_t k_nv_aad_v6[] = "SE_nv_v6";
static const uint8_t k_nv_aad_v5[] = "SE_nv_v5";
static const uint8_t k_nv_aad_v4[] = "SE_nv_v4";
static const uint8_t k_nv_aad_v3[] = "SE_nv_v3";

typedef struct {
    uint16_t owner_len;
    uint8_t owner[SE_NV_OWNER_SPKI_MAX];
    uint8_t pw_hash[SE_NV_PW_HASH_LEN];
    uint16_t wrap_len;
    uint8_t wrap[SE_NV_WRAP_MAX];
    uint16_t mlkem_len;
    uint8_t mlkem[SE_NV_MLKEM_MAX];
} se_nv_extra_t;

static uint8_t s_pending_fill[SE_NV_FILL_ID_LEN];
static uint8_t s_pending_valid;
static uint8_t s_nv_page[SE_NV_PAGE_SIZE];
static uint8_t s_nv_blob[SE_NV_BLOB_MAX];
static uint8_t s_nv_plain[SE_NV_PLAIN_V6_LEN];
static se_nv_extra_t s_extra;

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

static void extra_clear(void)
{
    wc_ForceZero(&s_extra, sizeof(s_extra));
}

static void pack_extra(uint8_t *plain)
{
    uint8_t *p = plain + SE_NV_PLAIN_LEN;

    se_put_u16le(p, s_extra.owner_len);
    p += 2u;
    (void)memcpy(p, s_extra.owner, SE_NV_OWNER_SPKI_MAX);
    p += SE_NV_OWNER_SPKI_MAX;
    (void)memcpy(p, s_extra.pw_hash, SE_NV_PW_HASH_LEN);
    p += SE_NV_PW_HASH_LEN;
    se_put_u16le(p, s_extra.wrap_len);
    p += 2u;
    (void)memcpy(p, s_extra.wrap, SE_NV_WRAP_MAX);
    p += SE_NV_WRAP_MAX;
    se_put_u16le(p, s_extra.mlkem_len);
    p += 2u;
    (void)memcpy(p, s_extra.mlkem, SE_NV_MLKEM_MAX);
}

static lt_ret_t unpack_extra(const uint8_t *plain)
{
    const uint8_t *p = plain + SE_NV_PLAIN_LEN;

    extra_clear();
    s_extra.owner_len = se_u16le(p);
    p += 2u;
    if (s_extra.owner_len > SE_NV_OWNER_SPKI_MAX) {
        extra_clear();
        return SE_TROPIC_LT_TAMPERED;
    }
    (void)memcpy(s_extra.owner, p, SE_NV_OWNER_SPKI_MAX);
    p += SE_NV_OWNER_SPKI_MAX;
    (void)memcpy(s_extra.pw_hash, p, SE_NV_PW_HASH_LEN);
    p += SE_NV_PW_HASH_LEN;
    s_extra.wrap_len = se_u16le(p);
    p += 2u;
    if (s_extra.wrap_len > SE_NV_WRAP_MAX) {
        extra_clear();
        return SE_TROPIC_LT_TAMPERED;
    }
    (void)memcpy(s_extra.wrap, p, SE_NV_WRAP_MAX);
    p += SE_NV_WRAP_MAX;
    s_extra.mlkem_len = se_u16le(p);
    p += 2u;
    if (s_extra.mlkem_len > SE_NV_MLKEM_MAX) {
        extra_clear();
        return SE_TROPIC_LT_TAMPERED;
    }
    (void)memcpy(s_extra.mlkem, p, SE_NV_MLKEM_MAX);
    return LT_OK;
}

static void pack_plain(const se_nv_state_t *in, uint8_t *plain)
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

/** v3 has no peer table and v4's is SHA-256 wide: both migrate with peers dropped. */
static void unpack_plain_without_peers(const uint8_t *plain, se_nv_state_t *out)
{
    unpack_core(plain, out);
    unpack_pairing(plain, out);
    out->peer_count = 0U;
    (void)memset(out->peers, 0, sizeof(out->peers));
}

static lt_ret_t unpack_plain_v5(const uint8_t *plain, se_nv_state_t *out)
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
    wc_ForceZero(s_nv_page, sizeof(s_nv_page));
}

static lt_ret_t decrypt_at(const uint8_t *key, const uint8_t *blob, uint16_t blob_len,
                           const uint8_t *aad, uint16_t aad_len, uint16_t expect_plain,
                           se_nv_state_t *out, int with_v6_extra)
{
    uint16_t plain_len = 0U;
    lt_ret_t ret;

    ret = se_tropic_decrypt_storage_blob(key, aad, aad_len, blob, blob_len, s_nv_plain,
                                         (uint16_t)sizeof(s_nv_plain), &plain_len);
    if ((ret != LT_OK) || (plain_len != expect_plain)) {
        return LT_FAIL;
    }
    if (with_v6_extra != 0) {
        ret = unpack_plain_v5(s_nv_plain, out);
        if (ret == LT_OK) {
            ret = unpack_extra(s_nv_plain);
        }
    } else if (expect_plain == SE_NV_PLAIN_LEN) {
        extra_clear();
        ret = unpack_plain_v5(s_nv_plain, out);
    } else {
        extra_clear();
        unpack_plain_without_peers(s_nv_plain, out);
        ret = LT_OK;
    }
    return ret;
}

lt_ret_t se_nv_load(se_nv_state_t *out)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    const uint8_t *blob;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memset(out, 0, sizeof(*out));
    extra_clear();

    ret = se_tropic_port_nv_page_read(s_nv_page);
    if (ret != LT_OK) {
        nv_work_wipe();
        return ret;
    }
    blob = s_nv_page + SE_NV_BLOB_OFF;
    if (page_is_erased(blob, SE_NV_BLOB_V6_LEN) != 0) {
        /* Virgin page or generate-once dwk with no sealed payload. */
        nv_work_wipe();
        return LT_OK;
    }

    ret = se_tropic_port_device_aead_key(key);
    if (ret != LT_OK) {
        nv_work_wipe();
        extra_clear();
        return ret;
    }

    ret = decrypt_at(key, blob, SE_NV_BLOB_V6_LEN, k_nv_aad_v6,
                     (uint16_t)(sizeof(k_nv_aad_v6) - 1u), SE_NV_PLAIN_V6_LEN, out, 1);
    if (ret == LT_OK) {
        wc_ForceZero(key, sizeof(key));
        nv_work_wipe();
        return LT_OK;
    }
    if (ret == SE_TROPIC_LT_TAMPERED) {
        wc_ForceZero(key, sizeof(key));
        nv_work_wipe();
        extra_clear();
        (void)memset(out, 0, sizeof(*out));
        return SE_TROPIC_LT_TAMPERED;
    }
    /* Pre-v6 records sit at offset 0 (no dwk header). */
    blob = s_nv_page;
    if (decrypt_at(key, blob, SE_NV_BLOB_LEN, k_nv_aad_v5,
                   (uint16_t)(sizeof(k_nv_aad_v5) - 1u), SE_NV_PLAIN_LEN, out, 0) == LT_OK) {
        wc_ForceZero(key, sizeof(key));
        nv_work_wipe();
        return LT_OK;
    }
    if (decrypt_at(key, blob, SE_NV_BLOB_V4_LEN, k_nv_aad_v4,
                   (uint16_t)(sizeof(k_nv_aad_v4) - 1u), SE_NV_PLAIN_V4_LEN, out, 0) == LT_OK) {
        wc_ForceZero(key, sizeof(key));
        nv_work_wipe();
        return LT_OK;
    }
    if (decrypt_at(key, blob, SE_NV_BLOB_V3_LEN, k_nv_aad_v3,
                   (uint16_t)(sizeof(k_nv_aad_v3) - 1u), SE_NV_PLAIN_V3_LEN, out, 0) == LT_OK) {
        wc_ForceZero(key, sizeof(key));
        nv_work_wipe();
        return LT_OK;
    }
    wc_ForceZero(key, sizeof(key));
    nv_work_wipe();
    extra_clear();
    (void)memset(out, 0, sizeof(*out));
    return SE_TROPIC_LT_TAMPERED;
}

lt_ret_t se_nv_store(const se_nv_state_t *in)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t dwk[SE_NV_DWK_LEN];
    uint16_t blob_len = SE_NV_BLOB_V6_LEN;
    lt_ret_t ret;

    if (in == NULL) {
        return LT_PARAM_ERR;
    }

    ret = se_tropic_port_dwk(dwk);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_port_device_aead_key(key);
    if (ret != LT_OK) {
        wc_ForceZero(dwk, sizeof(dwk));
        return ret;
    }
    ret = se_tropic_port_nv_random(nonce, sizeof(nonce));
    if (ret != LT_OK) {
        wc_ForceZero(key, sizeof(key));
        wc_ForceZero(dwk, sizeof(dwk));
        return ret;
    }

    (void)memset(s_nv_plain, 0, sizeof(s_nv_plain));
    pack_plain(in, s_nv_plain);
    pack_extra(s_nv_plain);
    ret = se_tropic_encrypt_storage_blob(key, k_nv_aad_v6, (uint16_t)(sizeof(k_nv_aad_v6) - 1u),
                                         s_nv_plain, SE_NV_PLAIN_V6_LEN, nonce, s_nv_blob,
                                         &blob_len);
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(s_nv_plain, sizeof(s_nv_plain));
    wc_ForceZero(nonce, sizeof(nonce));
    if (ret != LT_OK) {
        wc_ForceZero(s_nv_blob, sizeof(s_nv_blob));
        wc_ForceZero(dwk, sizeof(dwk));
        return ret;
    }

    (void)memset(s_nv_page, 0xff, sizeof(s_nv_page));
    (void)memcpy(s_nv_page, dwk, SE_NV_DWK_LEN);
    (void)memcpy(s_nv_page + SE_NV_BLOB_OFF, s_nv_blob, blob_len);
    wc_ForceZero(dwk, sizeof(dwk));
    wc_ForceZero(s_nv_blob, sizeof(s_nv_blob));
    ret = se_tropic_port_nv_page_write(s_nv_page);
    wc_ForceZero(s_nv_page, sizeof(s_nv_page));
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

lt_ret_t se_nv_clear_pairing(void)
{
    se_nv_state_t st;
    lt_ret_t ret;

    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    st.flags &= (uint32_t)~SE_NV_FLAG_PAIRING;
    st.pairing_slot = 0U;
    wc_ForceZero(st.pairing_priv, sizeof(st.pairing_priv));
    wc_ForceZero(st.pairing_pub, sizeof(st.pairing_pub));
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_peer_add(const uint8_t *name, uint8_t name_len,
                        const uint8_t hash48[SE_NV_PEER_HASH_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t i;

    if ((hash48 == NULL) || (peer_name_ok(name, name_len) == 0)) {
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
    (void)memcpy(st.peers[i].hash, hash48, SE_NV_PEER_HASH_LEN);
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
                        uint8_t hash48[SE_NV_PEER_HASH_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t nlen;
    uint8_t cap;

    if ((name == NULL) || (name_len == NULL) || (hash48 == NULL)) {
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
    (void)memcpy(hash48, st.peers[index].hash, SE_NV_PEER_HASH_LEN);
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

int se_nv_has_owner(void)
{
    se_nv_state_t st;
    lt_ret_t ret = se_nv_load(&st);
    int has;

    if (ret != LT_OK) {
        return 0;
    }
    has = (s_extra.owner_len > 0U) ? 1 : 0;
    nv_state_wipe_secrets(&st);
    return has;
}

int se_nv_has_wrap(void)
{
    se_nv_state_t st;
    lt_ret_t ret = se_nv_load(&st);
    int has;

    if (ret != LT_OK) {
        return 0;
    }
    has = (s_extra.wrap_len > 0U) ? 1 : 0;
    nv_state_wipe_secrets(&st);
    return has;
}

int se_nv_has_mlkem(void)
{
    se_nv_state_t st;
    lt_ret_t ret = se_nv_load(&st);
    int has;

    if (ret != LT_OK) {
        return 0;
    }
    has = (s_extra.mlkem_len == SE_NV_MLKEM_MAX) ? 1 : 0;
    nv_state_wipe_secrets(&st);
    return has;
}

lt_ret_t se_nv_get_owner_spki(uint8_t *out, uint16_t *len)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    nv_state_wipe_secrets(&st);
    if (s_extra.owner_len == 0U) {
        *len = 0U;
        return LT_FAIL;
    }
    (void)memcpy(out, s_extra.owner, s_extra.owner_len);
    *len = s_extra.owner_len;
    return LT_OK;
}

lt_ret_t se_nv_set_owner(const uint8_t *spki, uint16_t spki_len,
                         const uint8_t pw_hash[SE_NV_PW_HASH_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((spki == NULL) || (pw_hash == NULL) || (spki_len == 0U) ||
        (spki_len > SE_NV_OWNER_SPKI_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memset(s_extra.owner, 0, sizeof(s_extra.owner));
    (void)memcpy(s_extra.owner, spki, spki_len);
    s_extra.owner_len = spki_len;
    (void)memcpy(s_extra.pw_hash, pw_hash, SE_NV_PW_HASH_LEN);
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_get_pw_hash(uint8_t out[SE_NV_PW_HASH_LEN])
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
    nv_state_wipe_secrets(&st);
    if (s_extra.owner_len == 0U) {
        return LT_FAIL;
    }
    (void)memcpy(out, s_extra.pw_hash, SE_NV_PW_HASH_LEN);
    return LT_OK;
}

lt_ret_t se_nv_get_wrap(uint8_t *out, uint16_t *len, uint16_t cap)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    nv_state_wipe_secrets(&st);
    if (s_extra.wrap_len == 0U) {
        *len = 0U;
        return LT_FAIL;
    }
    if (cap < s_extra.wrap_len) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(out, s_extra.wrap, s_extra.wrap_len);
    *len = s_extra.wrap_len;
    return LT_OK;
}

lt_ret_t se_nv_set_wrap(const uint8_t *wrap, uint16_t len)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((wrap == NULL) || (len == 0U) || (len > SE_NV_WRAP_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memset(s_extra.wrap, 0, sizeof(s_extra.wrap));
    (void)memcpy(s_extra.wrap, wrap, len);
    s_extra.wrap_len = len;
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_get_mlkem_pk(uint8_t *out, uint16_t *len)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    *len = 0U;
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    nv_state_wipe_secrets(&st);
    if (s_extra.mlkem_len == 0U) {
        return LT_FAIL;
    }
    (void)memcpy(out, s_extra.mlkem, s_extra.mlkem_len);
    *len = s_extra.mlkem_len;
    return LT_OK;
}

lt_ret_t se_nv_set_mlkem_pk(const uint8_t *pk, uint16_t len)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if ((pk == NULL) || (len != SE_NV_MLKEM_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memcpy(s_extra.mlkem, pk, SE_NV_MLKEM_MAX);
    s_extra.mlkem_len = len;
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}

lt_ret_t se_nv_clear_except_pairing(void)
{
    se_nv_state_t st;
    uint8_t slot;
    uint8_t priv[SE_NV_PAIRING_KEY_LEN];
    uint8_t pub[SE_NV_PAIRING_KEY_LEN];
    uint32_t flags;
    lt_ret_t ret;

    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    flags = st.flags & SE_NV_FLAG_PAIRING;
    slot = st.pairing_slot;
    (void)memcpy(priv, st.pairing_priv, sizeof(priv));
    (void)memcpy(pub, st.pairing_pub, sizeof(pub));
    (void)memset(&st, 0, sizeof(st));
    extra_clear();
    if (flags != 0U) {
        st.flags = SE_NV_FLAG_PAIRING;
        st.pairing_slot = slot;
        (void)memcpy(st.pairing_priv, priv, sizeof(priv));
        (void)memcpy(st.pairing_pub, pub, sizeof(pub));
    }
    wc_ForceZero(priv, sizeof(priv));
    ret = se_nv_store(&st);
    nv_state_wipe_secrets(&st);
    return ret;
}
