/**
 * @file    se_nv.c
 * @brief   Plaintext MCU NV at fixed offsets; slice reads, RMW writes
 *
 * Bytes [0,32) are generate-once secure_dwk (Tropic AEAD / PIN / pw hash).
 * The record starts at offset 32. Pairing priv and the device SK are only
 * copied when those APIs run. The 8 KB work buffer is write-only.
 */
#include "se_nv.h"
#include "se_nv_internal.h"
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
#define SE_NV_REC_END       (SE_NV_OFF_SK + SE_NV_SK_MAX)
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
            if (se_nv_peer_name_ok(p + 1u, nlen) == 0) {
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

/** Begin, run @p fn against {@code s_nv_page}, commit. Wipes the page on @p fn failure. */
static lt_ret_t nv_mutate(lt_ret_t (*fn)(void *), void *ctx)
{
    lt_ret_t ret;

    ret = nv_begin_write();
    if (ret != LT_OK) {
        return ret;
    }
    ret = fn(ctx);
    if (ret != LT_OK) {
        nv_work_wipe();
        return ret;
    }
    return nv_commit_write();
}

static lt_ret_t nv_pack_ops_cb(void *ctx)
{
    pack_ops((const se_nv_state_t *)ctx, s_nv_page);
    return LT_OK;
}

typedef struct {
    const se_nv_state_t *st;
    const uint8_t *priv;
} nv_pairing_ctx_t;

static lt_ret_t nv_pack_pairing_cb(void *ctx)
{
    const nv_pairing_ctx_t *c = ctx;

    pack_ops(c->st, s_nv_page);
    if (c->priv != NULL) {
        (void)memcpy(s_nv_page + SE_NV_OFF_P_PRIV, c->priv, SE_NV_PAIRING_KEY_LEN);
    } else {
        wc_ForceZero(s_nv_page + SE_NV_OFF_P_PRIV, SE_NV_PAIRING_KEY_LEN);
    }
    return LT_OK;
}

typedef struct {
    const uint8_t *spki;
    uint16_t spki_len;
    const uint8_t *pw_hash;
} nv_owner_ctx_t;

static lt_ret_t nv_set_owner_cb(void *ctx)
{
    const nv_owner_ctx_t *c = ctx;

    (void)memset(s_nv_page + SE_NV_OFF_OWNER, 0, SE_NV_OWNER_SPKI_MAX);
    se_put_u16le(s_nv_page + SE_NV_OFF_OWNER_LEN, c->spki_len);
    (void)memcpy(s_nv_page + SE_NV_OFF_OWNER, c->spki, c->spki_len);
    (void)memcpy(s_nv_page + SE_NV_OFF_PW, c->pw_hash, SE_NV_PW_HASH_LEN);
    return LT_OK;
}

typedef struct {
    const uint8_t *der;
    uint16_t len;
} nv_blob_ctx_t;

static lt_ret_t nv_set_sk_cb(void *ctx)
{
    const nv_blob_ctx_t *c = ctx;

    (void)memset(s_nv_page + SE_NV_OFF_SK, 0, SE_NV_SK_MAX);
    se_put_u16le(s_nv_page + SE_NV_OFF_SK_LEN, c->len);
    (void)memcpy(s_nv_page + SE_NV_OFF_SK, c->der, c->len);
    return LT_OK;
}

static lt_ret_t nv_set_mlkem_cb(void *ctx)
{
    const nv_blob_ctx_t *c = ctx;

    se_put_u16le(s_nv_page + SE_NV_OFF_MLKEM_LEN, c->len);
    (void)memcpy(s_nv_page + SE_NV_OFF_MLKEM, c->der, SE_NV_MLKEM_MAX);
    return LT_OK;
}

static lt_ret_t nv_clear_except_pairing_cb(void *ctx)
{
    uint8_t slot;
    uint8_t pub[SE_NV_PAIRING_KEY_LEN];
    uint8_t priv[SE_NV_PAIRING_KEY_LEN];
    uint32_t flags;
    int keep;

    (void)ctx;
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
    return LT_OK;
}

static int nv_has_u16(uint16_t off, uint16_t min, uint16_t max)
{
    uint16_t len = 0U;
    int present = 0;

    if ((nv_rec_present(&present) != LT_OK) || (present == 0)) {
        return 0;
    }
    if (nv_read_u16(off, &len) != LT_OK) {
        return 0;
    }
    return ((len >= min) && (len <= max)) ? 1 : 0;
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
    if (in == NULL) {
        return LT_PARAM_ERR;
    }
    return nv_mutate(nv_pack_ops_cb, (void *)in);
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
    {
        nv_pairing_ctx_t ctx = { &st, priv };

        return nv_mutate(nv_pack_pairing_cb, &ctx);
    }
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
    {
        nv_pairing_ctx_t ctx = { &st, NULL };

        return nv_mutate(nv_pack_pairing_cb, &ctx);
    }
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
    return nv_has_u16(SE_NV_OFF_OWNER_LEN, 1U, SE_NV_OWNER_SPKI_MAX);
}

int se_nv_has_device_sk(void)
{
    return nv_has_u16(SE_NV_OFF_SK_LEN, 1U, SE_NV_SK_MAX);
}

int se_nv_has_mlkem(void)
{
    return nv_has_u16(SE_NV_OFF_MLKEM_LEN, SE_NV_MLKEM_MAX, SE_NV_MLKEM_MAX);
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
    nv_owner_ctx_t ctx;

    if ((spki == NULL) || (pw_hash == NULL) || (spki_len == 0U) ||
        (spki_len > SE_NV_OWNER_SPKI_MAX)) {
        return LT_PARAM_ERR;
    }
    ctx.spki = spki;
    ctx.spki_len = spki_len;
    ctx.pw_hash = pw_hash;
    return nv_mutate(nv_set_owner_cb, &ctx);
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
    nv_blob_ctx_t ctx;

    if ((der == NULL) || (len == 0U) || (len > SE_NV_SK_MAX)) {
        return LT_PARAM_ERR;
    }
    ctx.der = der;
    ctx.len = len;
    return nv_mutate(nv_set_sk_cb, &ctx);
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
    nv_blob_ctx_t ctx;

    if ((pk == NULL) || (len != SE_NV_MLKEM_MAX)) {
        return LT_PARAM_ERR;
    }
    ctx.der = pk;
    ctx.len = len;
    return nv_mutate(nv_set_mlkem_cb, &ctx);
}

lt_ret_t se_nv_clear_except_pairing(void)
{
    return nv_mutate(nv_clear_except_pairing_cb, NULL);
}
