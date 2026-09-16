/**
 * @file    se_nv.c
 * @brief   Plaintext MCU NV at fixed offsets; slice reads, RMW writes
 *
 * Bytes [0,32) are generate-once secure_dwk (Tropic AEAD / PIN / pw hash).
 * The record starts at offset 32. Pairing priv and the device SK are only
 * copied when those APIs run. The 8 KB work buffer is write-only.
 */
#include "se_nv.h"
#include "se_le.h"
#include "se_tropic_port.h"
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

#define SE_NV_MAGIC   0x53454E56u /* SENV */
#define SE_NV_VERSION 7u

#define SE_NV_PEER_SLOT_LEN (1u + SE_NV_PEER_NAME_MAX + SE_NV_PEER_HASH_LEN)

#define SE_NV_OFF_MAGIC     32u
#define SE_NV_OFF_VER       36u
#define SE_NV_OFF_FLAGS     38u
#define SE_NV_OFF_TIME      42u
#define SE_NV_OFF_FILL      46u
#define SE_NV_OFF_CUR_E     78u
#define SE_NV_OFF_CUR_D     80u
#define SE_NV_OFF_BASE_E    82u
#define SE_NV_OFF_BASE_D    84u
#define SE_NV_OFF_P_SLOT    86u
#define SE_NV_OFF_P_PUB     87u
#define SE_NV_OFF_NPEER     119u
#define SE_NV_OFF_PEERS     120u
#define SE_NV_OFF_OWNER_LEN 640u
#define SE_NV_OFF_OWNER     642u
#define SE_NV_OFF_MLKEM_LEN 1954u
#define SE_NV_OFF_MLKEM     1956u
#define SE_NV_OFF_PW        3140u
#define SE_NV_OFF_P_PRIV    3188u
#define SE_NV_OFF_SK_LEN    3220u
#define SE_NV_OFF_SK        3222u
#define SE_NV_REC_END       6294u
#define SE_NV_OPS_LEN       (SE_NV_OFF_OWNER_LEN - SE_NV_OFF_FLAGS)

#if SE_NV_REC_END > SE_NV_PAGE_SIZE
#error "NV record does not fit in the flash page"
#endif

static uint8_t s_pending_fill[SE_NV_FILL_ID_LEN];
static uint8_t s_pending_valid;
static uint8_t s_nv_page[SE_NV_PAGE_SIZE];
static uint8_t s_ops[SE_NV_OPS_LEN];

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

static int slice_blank(const uint8_t *p, uint16_t len)
{
    uint16_t i;

    for (i = 0U; i < len; i++) {
        if (p[i] != 0xffu) {
            return 0;
        }
    }
    return 1;
}

static void nv_work_wipe(void)
{
    wc_ForceZero(s_nv_page, sizeof(s_nv_page));
    wc_ForceZero(s_ops, sizeof(s_ops));
}

/** 0 = empty, 1 = present, TAMPERED = bad version/length. */
static lt_ret_t nv_rec_present(int *present)
{
    uint8_t hdr[6];
    uint16_t ver;
    lt_ret_t ret;

    if (present == NULL) {
        return LT_PARAM_ERR;
    }
    *present = 0;
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_MAGIC, hdr, (uint16_t)sizeof(hdr));
    if (ret != LT_OK) {
        return ret;
    }
    if (slice_blank(hdr, (uint16_t)sizeof(hdr)) != 0) {
        return LT_OK;
    }
    if (se_u32le(hdr) != SE_NV_MAGIC) {
        return LT_OK;
    }
    ver = se_u16le(hdr + 4);
    if (ver != SE_NV_VERSION) {
        return SE_TROPIC_LT_TAMPERED;
    }
    *present = 1;
    return LT_OK;
}

static lt_ret_t nv_read_u16(uint16_t off, uint16_t *out)
{
    uint8_t b[2];
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_port_nv_slice_read(off, b, 2U);
    if (ret != LT_OK) {
        return ret;
    }
    *out = se_u16le(b);
    return LT_OK;
}

static lt_ret_t nv_read_u32(uint16_t off, uint32_t *out)
{
    uint8_t b[4];
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_port_nv_slice_read(off, b, 4U);
    if (ret != LT_OK) {
        return ret;
    }
    *out = se_u32le(b);
    return LT_OK;
}

static void pack_ops(const se_nv_state_t *in, uint8_t *page)
{
    uint8_t *p;
    uint8_t i;

    se_put_u32le(page + SE_NV_OFF_FLAGS, in->flags);
    se_put_u32le(page + SE_NV_OFF_TIME, in->time_floor);
    (void)memcpy(page + SE_NV_OFF_FILL, in->fill_id, SE_NV_FILL_ID_LEN);
    se_put_u16le(page + SE_NV_OFF_CUR_E, in->cursor_encrypt);
    se_put_u16le(page + SE_NV_OFF_CUR_D, in->cursor_decrypt);
    se_put_u16le(page + SE_NV_OFF_BASE_E, in->base_encrypt);
    se_put_u16le(page + SE_NV_OFF_BASE_D, in->base_decrypt);
    page[SE_NV_OFF_P_SLOT] = in->pairing_slot;
    (void)memcpy(page + SE_NV_OFF_P_PUB, in->pairing_pub, SE_NV_PAIRING_KEY_LEN);
    page[SE_NV_OFF_NPEER] = in->peer_count;
    p = page + SE_NV_OFF_PEERS;
    for (i = 0U; i < SE_NV_PEER_MAX; i++) {
        p[0] = in->peers[i].name_len;
        (void)memcpy(p + 1u, in->peers[i].name, SE_NV_PEER_NAME_MAX);
        (void)memcpy(p + 1u + SE_NV_PEER_NAME_MAX, in->peers[i].hash, SE_NV_PEER_HASH_LEN);
        p += SE_NV_PEER_SLOT_LEN;
    }
}

static lt_ret_t unpack_ops(const uint8_t *ops, se_nv_state_t *out)
{
    const uint8_t *p;
    uint8_t i;
    uint8_t nlen;

    (void)memset(out, 0, sizeof(*out));
    out->flags = se_u32le(ops + (SE_NV_OFF_FLAGS - SE_NV_OFF_FLAGS));
    out->time_floor = se_u32le(ops + (SE_NV_OFF_TIME - SE_NV_OFF_FLAGS));
    (void)memcpy(out->fill_id, ops + (SE_NV_OFF_FILL - SE_NV_OFF_FLAGS), SE_NV_FILL_ID_LEN);
    out->cursor_encrypt = se_u16le(ops + (SE_NV_OFF_CUR_E - SE_NV_OFF_FLAGS));
    out->cursor_decrypt = se_u16le(ops + (SE_NV_OFF_CUR_D - SE_NV_OFF_FLAGS));
    out->base_encrypt = se_u16le(ops + (SE_NV_OFF_BASE_E - SE_NV_OFF_FLAGS));
    out->base_decrypt = se_u16le(ops + (SE_NV_OFF_BASE_D - SE_NV_OFF_FLAGS));
    out->pairing_slot = ops[SE_NV_OFF_P_SLOT - SE_NV_OFF_FLAGS];
    (void)memcpy(out->pairing_pub, ops + (SE_NV_OFF_P_PUB - SE_NV_OFF_FLAGS),
                 SE_NV_PAIRING_KEY_LEN);
    out->peer_count = ops[SE_NV_OFF_NPEER - SE_NV_OFF_FLAGS];
    if (out->peer_count > SE_NV_PEER_MAX) {
        return SE_TROPIC_LT_TAMPERED;
    }
    p = ops + (SE_NV_OFF_PEERS - SE_NV_OFF_FLAGS);
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

static void rec_init(uint8_t *page)
{
    (void)memset(page + SE_NV_OFF_MAGIC, 0, SE_NV_REC_END - SE_NV_OFF_MAGIC);
    se_put_u32le(page + SE_NV_OFF_MAGIC, SE_NV_MAGIC);
    se_put_u16le(page + SE_NV_OFF_VER, SE_NV_VERSION);
}

static lt_ret_t nv_begin_write(void)
{
    uint8_t dwk[SE_NV_DWK_LEN];
    lt_ret_t ret;

    ret = se_tropic_port_dwk(dwk);
    wc_ForceZero(dwk, sizeof(dwk));
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_port_nv_page_read(s_nv_page);
    if (ret != LT_OK) {
        nv_work_wipe();
        return ret;
    }
    if ((slice_blank(s_nv_page + SE_NV_OFF_MAGIC, 6U) != 0) ||
        (se_u32le(s_nv_page + SE_NV_OFF_MAGIC) != SE_NV_MAGIC)) {
        rec_init(s_nv_page);
        return LT_OK;
    }
    if (se_u16le(s_nv_page + SE_NV_OFF_VER) != SE_NV_VERSION) {
        nv_work_wipe();
        return SE_TROPIC_LT_TAMPERED;
    }
    return LT_OK;
}

static lt_ret_t nv_commit_write(void)
{
    lt_ret_t ret;

    ret = se_tropic_port_nv_page_write(s_nv_page);
    nv_work_wipe();
    return ret;
}

lt_ret_t se_nv_load(se_nv_state_t *out)
{
    int present = 0;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memset(out, 0, sizeof(*out));
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_OK;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_FLAGS, s_ops, SE_NV_OPS_LEN);
    if (ret != LT_OK) {
        wc_ForceZero(s_ops, sizeof(s_ops));
        return ret;
    }
    ret = unpack_ops(s_ops, out);
    wc_ForceZero(s_ops, sizeof(s_ops));
    return ret;
}

lt_ret_t se_nv_store(const se_nv_state_t *in)
{
    lt_ret_t ret;

    if (in == NULL) {
        return LT_PARAM_ERR;
    }
    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    pack_ops(in, s_nv_page);
    return nv_commit_write();
}

int se_nv_have_fill(void)
{
    uint32_t flags = 0U;
    int present = 0;
    lt_ret_t ret;

    ret = nv_rec_present(&present);
    if ((ret != LT_OK) || (present == 0)) {
        return 0;
    }
    ret = nv_read_u32(SE_NV_OFF_FLAGS, &flags);
    if (ret != LT_OK) {
        return 0;
    }
    return ((flags & SE_NV_FLAG_FILL) != 0U) ? 1 : 0;
}

lt_ret_t se_nv_get_fill_id(uint8_t out[SE_NV_FILL_ID_LEN])
{
    uint32_t flags = 0U;
    int present = 0;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u32(SE_NV_OFF_FLAGS, &flags);
    if (ret != LT_OK) {
        return ret;
    }
    if ((flags & SE_NV_FLAG_FILL) == 0U) {
        return LT_FAIL;
    }
    return se_tropic_port_nv_slice_read(SE_NV_OFF_FILL, out, SE_NV_FILL_ID_LEN);
}

lt_ret_t se_nv_get_cursor(se_nv_otp_dir_t dir, uint16_t *cursor)
{
    uint32_t flags = 0U;
    uint16_t off;
    int present = 0;
    lt_ret_t ret;

    if ((cursor == NULL) || (otp_dir_ok(dir) == 0)) {
        return LT_PARAM_ERR;
    }
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u32(SE_NV_OFF_FLAGS, &flags);
    if (ret != LT_OK) {
        return ret;
    }
    if (((flags & SE_NV_FLAG_FILL) == 0U) || ((flags & SE_NV_FLAG_OTP) == 0U)) {
        return LT_FAIL;
    }
    off = (dir == SE_NV_OTP_DECRYPT) ? SE_NV_OFF_CUR_D : SE_NV_OFF_CUR_E;
    return nv_read_u16(off, cursor);
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
    return se_nv_store(&st);
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
        return LT_FAIL;
    }
    st.base_encrypt = base_encrypt;
    st.base_decrypt = base_decrypt;
    st.cursor_encrypt = base_encrypt;
    st.cursor_decrypt = base_decrypt;
    st.flags |= SE_NV_FLAG_OTP;
    return se_nv_store(&st);
}

lt_ret_t se_nv_get_otp_bases(uint16_t *base_encrypt, uint16_t *base_decrypt)
{
    uint32_t flags = 0U;
    int present = 0;
    lt_ret_t ret;

    if ((base_encrypt == NULL) || (base_decrypt == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u32(SE_NV_OFF_FLAGS, &flags);
    if (ret != LT_OK) {
        return ret;
    }
    if (((flags & SE_NV_FLAG_FILL) == 0U) || ((flags & SE_NV_FLAG_OTP) == 0U)) {
        return LT_FAIL;
    }
    ret = nv_read_u16(SE_NV_OFF_BASE_E, base_encrypt);
    if (ret != LT_OK) {
        return ret;
    }
    return nv_read_u16(SE_NV_OFF_BASE_D, base_decrypt);
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
        return LT_FAIL;
    }
    *cursor_field(&st, dir) = cursor;
    return se_nv_store(&st);
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
    return se_nv_store(&st);
}

lt_ret_t se_nv_get_time_floor(uint32_t *unix_utc, int *present)
{
    uint32_t flags = 0U;
    int rec = 0;
    lt_ret_t ret;

    if ((unix_utc == NULL) || (present == NULL)) {
        return LT_PARAM_ERR;
    }
    *present = 0;
    *unix_utc = 0U;
    ret = nv_rec_present(&rec);
    if (ret != LT_OK) {
        return ret;
    }
    if (rec == 0) {
        return LT_OK;
    }
    ret = nv_read_u32(SE_NV_OFF_FLAGS, &flags);
    if (ret != LT_OK) {
        return ret;
    }
    if ((flags & SE_NV_FLAG_TIME) == 0U) {
        return LT_OK;
    }
    *present = 1;
    return nv_read_u32(SE_NV_OFF_TIME, unix_utc);
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
    (void)memcpy(st.pairing_pub, pub, SE_NV_PAIRING_KEY_LEN);
    st.flags |= SE_NV_FLAG_PAIRING;
    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    pack_ops(&st, s_nv_page);
    (void)memcpy(s_nv_page + SE_NV_OFF_P_PRIV, priv, SE_NV_PAIRING_KEY_LEN);
    return nv_commit_write();
}

lt_ret_t se_nv_get_pairing(uint8_t *slot, uint8_t priv[SE_NV_PAIRING_KEY_LEN],
                           uint8_t pub[SE_NV_PAIRING_KEY_LEN])
{
    uint32_t flags = 0U;
    uint8_t sl = 0U;
    int present = 0;
    lt_ret_t ret;

    if ((slot == NULL) || (priv == NULL) || (pub == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u32(SE_NV_OFF_FLAGS, &flags);
    if (ret != LT_OK) {
        return ret;
    }
    if ((flags & SE_NV_FLAG_PAIRING) == 0U) {
        return LT_FAIL;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_P_SLOT, &sl, 1U);
    if (ret != LT_OK) {
        return ret;
    }
    if ((sl < (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_1) ||
        (sl > (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_3)) {
        return SE_TROPIC_LT_TAMPERED;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_P_PUB, pub, SE_NV_PAIRING_KEY_LEN);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_P_PRIV, priv, SE_NV_PAIRING_KEY_LEN);
    if (ret != LT_OK) {
        wc_ForceZero(pub, SE_NV_PAIRING_KEY_LEN);
        return ret;
    }
    *slot = sl;
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
    (void)memset(st.pairing_pub, 0, sizeof(st.pairing_pub));
    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    pack_ops(&st, s_nv_page);
    wc_ForceZero(s_nv_page + SE_NV_OFF_P_PRIV, SE_NV_PAIRING_KEY_LEN);
    return nv_commit_write();
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
            return SE_NV_PEER_EXISTS;
        }
    }
    if (st.peer_count >= SE_NV_PEER_MAX) {
        return SE_NV_PEER_FULL;
    }
    i = st.peer_count;
    st.peers[i].name_len = name_len;
    (void)memset(st.peers[i].name, 0, SE_NV_PEER_NAME_MAX);
    (void)memcpy(st.peers[i].name, name, name_len);
    (void)memcpy(st.peers[i].hash, hash48, SE_NV_PEER_HASH_LEN);
    st.peer_count = (uint8_t)(st.peer_count + 1u);
    return se_nv_store(&st);
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
        return SE_NV_PEER_NOT_FOUND;
    }
    for (i = found; i + 1u < st.peer_count; i++) {
        st.peers[i] = st.peers[i + 1u];
    }
    st.peer_count = (uint8_t)(st.peer_count - 1u);
    (void)memset(&st.peers[st.peer_count], 0, sizeof(st.peers[0]));
    return se_nv_store(&st);
}

lt_ret_t se_nv_peer_count(uint8_t *count)
{
    uint8_t n = 0U;
    int present = 0;
    lt_ret_t ret;

    if (count == NULL) {
        return LT_PARAM_ERR;
    }
    *count = 0U;
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_OK;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_NPEER, &n, 1U);
    if (ret != LT_OK) {
        return ret;
    }
    if (n > SE_NV_PEER_MAX) {
        return SE_TROPIC_LT_TAMPERED;
    }
    *count = n;
    return LT_OK;
}

lt_ret_t se_nv_peer_get(uint8_t index, uint8_t *name, uint8_t *name_len,
                        uint8_t hash48[SE_NV_PEER_HASH_LEN])
{
    uint8_t slot[SE_NV_PEER_SLOT_LEN];
    uint8_t n = 0U;
    uint8_t nlen;
    uint8_t cap;
    int present = 0;
    lt_ret_t ret;

    if ((name == NULL) || (name_len == NULL) || (hash48 == NULL)) {
        return LT_PARAM_ERR;
    }
    cap = *name_len;
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return SE_NV_PEER_NOT_FOUND;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_NPEER, &n, 1U);
    if (ret != LT_OK) {
        return ret;
    }
    if (n > SE_NV_PEER_MAX) {
        return SE_TROPIC_LT_TAMPERED;
    }
    if (index >= n) {
        return SE_NV_PEER_NOT_FOUND;
    }
    ret = se_tropic_port_nv_slice_read(
        (uint16_t)(SE_NV_OFF_PEERS + ((uint16_t)index * SE_NV_PEER_SLOT_LEN)), slot,
        SE_NV_PEER_SLOT_LEN);
    if (ret != LT_OK) {
        return ret;
    }
    nlen = slot[0];
    if ((nlen == 0U) || (nlen > SE_NV_PEER_NAME_MAX) || (peer_name_ok(slot + 1u, nlen) == 0)) {
        return SE_TROPIC_LT_TAMPERED;
    }
    if (cap < nlen) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(name, slot + 1u, nlen);
    (void)memcpy(hash48, slot + 1u + SE_NV_PEER_NAME_MAX, SE_NV_PEER_HASH_LEN);
    *name_len = nlen;
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
    uint16_t len = 0U;
    int present = 0;
    lt_ret_t ret;

    ret = nv_rec_present(&present);
    if ((ret != LT_OK) || (present == 0)) {
        return 0;
    }
    ret = nv_read_u16(SE_NV_OFF_OWNER_LEN, &len);
    if (ret != LT_OK) {
        return 0;
    }
    return (len > 0U) && (len <= SE_NV_OWNER_SPKI_MAX);
}

int se_nv_has_device_sk(void)
{
    uint16_t len = 0U;
    int present = 0;
    lt_ret_t ret;

    ret = nv_rec_present(&present);
    if ((ret != LT_OK) || (present == 0)) {
        return 0;
    }
    ret = nv_read_u16(SE_NV_OFF_SK_LEN, &len);
    if (ret != LT_OK) {
        return 0;
    }
    return (len > 0U) && (len <= SE_NV_SK_MAX);
}

int se_nv_has_mlkem(void)
{
    uint16_t len = 0U;
    int present = 0;
    lt_ret_t ret;

    ret = nv_rec_present(&present);
    if ((ret != LT_OK) || (present == 0)) {
        return 0;
    }
    ret = nv_read_u16(SE_NV_OFF_MLKEM_LEN, &len);
    if (ret != LT_OK) {
        return 0;
    }
    return (len == SE_NV_MLKEM_MAX) ? 1 : 0;
}

lt_ret_t se_nv_get_owner_spki(uint8_t *out, uint16_t *len)
{
    uint16_t n = 0U;
    int present = 0;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    *len = 0U;
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u16(SE_NV_OFF_OWNER_LEN, &n);
    if (ret != LT_OK) {
        return ret;
    }
    if ((n == 0U) || (n > SE_NV_OWNER_SPKI_MAX)) {
        return (n > SE_NV_OWNER_SPKI_MAX) ? SE_TROPIC_LT_TAMPERED : LT_FAIL;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_OWNER, out, n);
    if (ret != LT_OK) {
        return ret;
    }
    *len = n;
    return LT_OK;
}

lt_ret_t se_nv_set_owner(const uint8_t *spki, uint16_t spki_len,
                         const uint8_t pw_hash[SE_NV_PW_HASH_LEN])
{
    lt_ret_t ret;

    if ((spki == NULL) || (pw_hash == NULL) || (spki_len == 0U) ||
        (spki_len > SE_NV_OWNER_SPKI_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    (void)memset(s_nv_page + SE_NV_OFF_OWNER, 0, SE_NV_OWNER_SPKI_MAX);
    se_put_u16le(s_nv_page + SE_NV_OFF_OWNER_LEN, spki_len);
    (void)memcpy(s_nv_page + SE_NV_OFF_OWNER, spki, spki_len);
    (void)memcpy(s_nv_page + SE_NV_OFF_PW, pw_hash, SE_NV_PW_HASH_LEN);
    return nv_commit_write();
}

lt_ret_t se_nv_get_pw_hash(uint8_t out[SE_NV_PW_HASH_LEN])
{
    uint16_t n = 0U;
    int present = 0;
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u16(SE_NV_OFF_OWNER_LEN, &n);
    if (ret != LT_OK) {
        return ret;
    }
    if (n == 0U) {
        return LT_FAIL;
    }
    return se_tropic_port_nv_slice_read(SE_NV_OFF_PW, out, SE_NV_PW_HASH_LEN);
}

lt_ret_t se_nv_get_device_sk(uint8_t *out, uint16_t *len, uint16_t cap)
{
    uint16_t n = 0U;
    int present = 0;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    *len = 0U;
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u16(SE_NV_OFF_SK_LEN, &n);
    if (ret != LT_OK) {
        return ret;
    }
    if ((n == 0U) || (n > SE_NV_SK_MAX)) {
        return (n > SE_NV_SK_MAX) ? SE_TROPIC_LT_TAMPERED : LT_FAIL;
    }
    if (cap < n) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_SK, out, n);
    if (ret != LT_OK) {
        return ret;
    }
    *len = n;
    return LT_OK;
}

lt_ret_t se_nv_set_device_sk(const uint8_t *der, uint16_t len)
{
    lt_ret_t ret;

    if ((der == NULL) || (len == 0U) || (len > SE_NV_SK_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    (void)memset(s_nv_page + SE_NV_OFF_SK, 0, SE_NV_SK_MAX);
    se_put_u16le(s_nv_page + SE_NV_OFF_SK_LEN, len);
    (void)memcpy(s_nv_page + SE_NV_OFF_SK, der, len);
    return nv_commit_write();
}

lt_ret_t se_nv_get_mlkem_pk(uint8_t *out, uint16_t *len)
{
    uint16_t n = 0U;
    int present = 0;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    *len = 0U;
    ret = nv_rec_present(&present);
    if (ret != LT_OK) {
        return ret;
    }
    if (present == 0) {
        return LT_FAIL;
    }
    ret = nv_read_u16(SE_NV_OFF_MLKEM_LEN, &n);
    if (ret != LT_OK) {
        return ret;
    }
    if ((n == 0U) || (n > SE_NV_MLKEM_MAX)) {
        return (n > SE_NV_MLKEM_MAX) ? SE_TROPIC_LT_TAMPERED : LT_FAIL;
    }
    ret = se_tropic_port_nv_slice_read(SE_NV_OFF_MLKEM, out, n);
    if (ret != LT_OK) {
        return ret;
    }
    *len = n;
    return LT_OK;
}

lt_ret_t se_nv_set_mlkem_pk(const uint8_t *pk, uint16_t len)
{
    lt_ret_t ret;

    if ((pk == NULL) || (len != SE_NV_MLKEM_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    se_put_u16le(s_nv_page + SE_NV_OFF_MLKEM_LEN, len);
    (void)memcpy(s_nv_page + SE_NV_OFF_MLKEM, pk, SE_NV_MLKEM_MAX);
    return nv_commit_write();
}

lt_ret_t se_nv_clear_except_pairing(void)
{
    uint8_t slot;
    uint8_t pub[SE_NV_PAIRING_KEY_LEN];
    uint8_t priv[SE_NV_PAIRING_KEY_LEN];
    uint32_t flags;
    int keep;
    lt_ret_t ret;

    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    flags = se_u32le(s_nv_page + SE_NV_OFF_FLAGS);
    keep = ((flags & SE_NV_FLAG_PAIRING) != 0U) ? 1 : 0;
    slot = s_nv_page[SE_NV_OFF_P_SLOT];
    (void)memcpy(pub, s_nv_page + SE_NV_OFF_P_PUB, sizeof(pub));
    (void)memcpy(priv, s_nv_page + SE_NV_OFF_P_PRIV, sizeof(priv));
    rec_init(s_nv_page);
    if (keep != 0) {
        s_nv_page[SE_NV_OFF_P_SLOT] = slot;
        (void)memcpy(s_nv_page + SE_NV_OFF_P_PUB, pub, sizeof(pub));
        (void)memcpy(s_nv_page + SE_NV_OFF_P_PRIV, priv, sizeof(priv));
        se_put_u32le(s_nv_page + SE_NV_OFF_FLAGS, SE_NV_FLAG_PAIRING);
    }
    wc_ForceZero(priv, sizeof(priv));
    return nv_commit_write();
}
