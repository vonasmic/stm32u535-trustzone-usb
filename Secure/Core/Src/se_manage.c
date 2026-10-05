/**
 * @file    se_manage.c
 * @brief   Identity-changing commands for owner-pinned TLS
 */
#include "se_manage.h"
#include "se_device_id.h"
#include "se_le.h"
#include "se_nv.h"
#include "se_owner.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "wolfssl/wolfcrypt/memory.h"
#include <string.h>

static uint8_t s_buf[SE_MANAGE_BUF_MAX];

uint8_t *se_manage_buf(void)
{
    return s_buf;
}

uint32_t se_manage_buf_cap(void)
{
    return SE_MANAGE_BUF_MAX;
}

void se_manage_buf_wipe(void)
{
    wc_ForceZero(s_buf, sizeof(s_buf));
}

int se_manage_frame_ready(uint32_t got, uint32_t (*need)(const uint8_t *buf, uint32_t got))
{
    uint32_t needn;

    if (need == NULL) {
        return -1;
    }
    needn = need(s_buf, got);
    if (needn == 0xffffffffu) {
        return -1;
    }
    if ((needn == 0U) || (got < needn)) {
        return SE_FRAME_NEED_MORE;
    }
    if (got != needn) {
        return -1;
    }
    return SE_FRAME_COMPLETE;
}

int se_manage_accum(uint32_t *got, const uint8_t *chunk, uint32_t n,
                    uint32_t (*need)(const uint8_t *buf, uint32_t got))
{
    if ((got == NULL) || ((n > 0U) && (chunk == NULL))) {
        return -1;
    }
    if ((*got + n) > sizeof(s_buf)) {
        return -1;
    }
    if (n > 0U) {
        (void)memcpy(s_buf + *got, chunk, (size_t)n);
        *got += n;
    }
    return se_manage_frame_ready(*got, need);
}

static void set_msg(char *msg, uint16_t cap, const char *s)
{
    size_t n;

    if ((msg == NULL) || (cap == 0U)) {
        return;
    }
    if (s == NULL) {
        msg[0] = '\0';
        return;
    }
    n = strlen(s);
    if (n >= (size_t)cap) {
        n = (size_t)cap - 1U;
    }
    (void)memcpy(msg, s, n);
    msg[n] = '\0';
}

static int pin_ok(const uint8_t *pin, uint8_t pin_len)
{
    return se_tropic_pin_ascii_ok(pin, pin_len);
}

static void hex_encode(const uint8_t *in, uint32_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    uint32_t i;

    for (i = 0U; i < n; i++) {
        out[i * 2U] = digits[(in[i] >> 4) & 0x0FU];
        out[i * 2U + 1U] = digits[in[i] & 0x0FU];
    }
}

/** {@code PAIRING ok <slot> <64 hex priv> <64 hex pub>} (142 ASCII bytes). */
static void pairing_ok_msg(char *msg, uint16_t cap, uint8_t slot, const uint8_t priv[32],
                           const uint8_t pub[32])
{
    static const char prefix[] = "PAIRING ok ";
    size_t n;

    if ((msg == NULL) || (cap < 143U) || (priv == NULL) || (pub == NULL) || (slot < 1U) ||
        (slot > 3U)) {
        set_msg(msg, cap, "PAIRING ok");
        return;
    }
    n = sizeof(prefix) - 1U;
    (void)memcpy(msg, prefix, n);
    msg[n++] = (char)('0' + slot);
    msg[n++] = ' ';
    hex_encode(priv, 32U, msg + n);
    n += 64U;
    msg[n++] = ' ';
    hex_encode(pub, 32U, msg + n);
    n += 64U;
    msg[n] = '\0';
}

static uint32_t tropic_map(uint32_t st, char *msg, uint16_t cap, const char *ok,
                           const char *fail)
{
    if (st == SE_TROPIC_OK) {
        set_msg(msg, cap, ok);
        return SE_MANAGE_OK;
    }
    if (st == SE_TROPIC_SLOT_OCC) {
        set_msg(msg, cap, "slot occupied");
        return SE_MANAGE_SLOT_OCC;
    }
    if (st == SE_TROPIC_NOT_READY) {
        set_msg(msg, cap, "not ready");
        return SE_MANAGE_NOT_READY;
    }
    if (st == SE_TROPIC_TAMPERED) {
        set_msg(msg, cap, "DEVICE_TAMPERED");
        return SE_MANAGE_TAMPERED;
    }
    if (st == SE_TROPIC_PIN_FAIL) {
        set_msg(msg, cap, "PIN fail");
        return SE_MANAGE_PIN_FAIL;
    }
    set_msg(msg, cap, (fail != NULL && fail[0] != '\0') ? fail : "command failed");
    return SE_MANAGE_ERR;
}

uint32_t se_manage_store_device_cert(const uint8_t *cert, uint16_t cert_len)
{
    if ((cert == NULL) || (cert_len == 0U) || (cert_len > SE_CREDS_DER_MAX)) {
        return SE_MANAGE_PARSE;
    }
    if (se_nv_has_device_sk() == 0) {
        return SE_MANAGE_NOT_READY;
    }
    if (se_device_id_cert_matches(cert, cert_len) == 0) {
        return SE_MANAGE_ERR;
    }
    if (se_creds_set_device_cert(cert, cert_len) != LT_OK) {
        return SE_MANAGE_ERR;
    }
    return SE_MANAGE_OK;
}

static uint32_t peer_map(lt_ret_t ret, char *msg, uint16_t cap, const char *ok)
{
    if (ret == LT_OK) {
        set_msg(msg, cap, ok);
        return SE_MANAGE_OK;
    }
    if (ret == SE_NV_PEER_EXISTS) {
        set_msg(msg, cap, "PEER nickname exists");
        return SE_MANAGE_PEER_EXISTS;
    }
    if (ret == SE_NV_PEER_NOT_FOUND) {
        set_msg(msg, cap, "PEER not found");
        return SE_MANAGE_PEER_NOT_FOUND;
    }
    if (ret == SE_NV_PEER_FULL) {
        set_msg(msg, cap, "PEER list full");
        return SE_MANAGE_PEER_FULL;
    }
    if (ret == SE_TROPIC_LT_TAMPERED) {
        set_msg(msg, cap, "DEVICE_TAMPERED");
        return SE_MANAGE_TAMPERED;
    }
    set_msg(msg, cap, "PEER command failed");
    return SE_MANAGE_ERR;
}

static uint32_t do_peer_add(const uint8_t *body, uint16_t body_len, char *msg, uint16_t msg_cap)
{
    uint8_t nlen;

    if ((body == NULL) || (body_len < (1U + SE_NV_PEER_HASH_LEN))) {
        set_msg(msg, msg_cap, "bad PEER ADD");
        return SE_MANAGE_PARSE;
    }
    nlen = body[0];
    if ((nlen < 1U) || (nlen > SE_NV_PEER_NAME_MAX) ||
        (body_len != (1U + (uint16_t)nlen + SE_NV_PEER_HASH_LEN))) {
        set_msg(msg, msg_cap, "bad PEER ADD");
        return SE_MANAGE_PARSE;
    }
    return peer_map(se_nv_peer_add(body + 1U, nlen, body + 1U + nlen), msg, msg_cap,
                    "PEER ADD ok");
}

static uint32_t do_peer_remove(const uint8_t *body, uint16_t body_len, char *msg,
                               uint16_t msg_cap)
{
    uint8_t nlen;

    if ((body == NULL) || (body_len < 2U)) {
        set_msg(msg, msg_cap, "bad PEER REMOVE");
        return SE_MANAGE_PARSE;
    }
    nlen = body[0];
    if ((nlen < 1U) || (nlen > SE_NV_PEER_NAME_MAX) ||
        (body_len != (1U + (uint16_t)nlen))) {
        set_msg(msg, msg_cap, "bad PEER REMOVE");
        return SE_MANAGE_PARSE;
    }
    return peer_map(se_nv_peer_remove(body + 1U, nlen), msg, msg_cap, "PEER REMOVE ok");
}

static uint32_t do_creds_sae(const uint8_t *body, uint16_t body_len, char *msg,
                             uint16_t msg_cap)
{
    if ((body == NULL) || (body_len == 0U) || (body_len > SE_CREDS_DER_MAX)) {
        set_msg(msg, msg_cap, "bad CREDS SAE");
        return SE_MANAGE_PARSE;
    }
    if (se_creds_set_sae_ca(body, body_len) != LT_OK) {
        set_msg(msg, msg_cap, "CREDS SAE failed");
        return SE_MANAGE_ERR;
    }
    set_msg(msg, msg_cap, "CREDS SAE ok");
    return SE_MANAGE_OK;
}

static uint32_t do_insert_signed_csr(const uint8_t *body, uint16_t body_len, char *msg,
                                     uint16_t msg_cap)
{
    uint16_t cert_len;
    uint32_t st;

    if ((body == NULL) || (body_len < 2U)) {
        set_msg(msg, msg_cap, "bad INSERT SIGNED CSR");
        return SE_MANAGE_PARSE;
    }
    cert_len = se_u16le(body);
    if ((cert_len == 0U) || (cert_len > SE_CREDS_DER_MAX) ||
        (body_len != (2U + (uint32_t)cert_len))) {
        set_msg(msg, msg_cap, "bad INSERT SIGNED CSR");
        return SE_MANAGE_PARSE;
    }
    st = se_manage_store_device_cert(body + 2U, cert_len);
    if (st == SE_MANAGE_NOT_READY) {
        set_msg(msg, msg_cap, "no device key");
        return st;
    }
    if (st != SE_MANAGE_OK) {
        set_msg(msg, msg_cap, "INSERT SIGNED CSR failed");
        return st;
    }
    set_msg(msg, msg_cap, "INSERT SIGNED CSR ok");
    return SE_MANAGE_OK;
}

static uint32_t do_pairing(const uint8_t *body, uint16_t body_len, char *msg, uint16_t msg_cap)
{
    uint32_t st;

    if ((body == NULL) || (body_len != 1U) || (body[0] < 1U) || (body[0] > 3U)) {
        set_msg(msg, msg_cap, "bad PAIRING");
        return SE_MANAGE_PARSE;
    }
    st = se_create_pairing_key_to_tropic(body[0]);
    if (st != SE_TROPIC_OK) {
        return tropic_map(st, msg, msg_cap, "PAIRING ok", "PAIRING failed");
    }
    {
        uint8_t slot = 0U;
        uint8_t priv[32];
        uint8_t pub[32];

        if (se_tropic_pairing_export(&slot, priv, pub) != SE_TROPIC_OK) {
            wc_ForceZero(priv, sizeof(priv));
            set_msg(msg, msg_cap, "PAIRING ok");
            return SE_MANAGE_OK;
        }
        pairing_ok_msg(msg, msg_cap, slot, priv, pub);
        wc_ForceZero(priv, sizeof(priv));
        wc_ForceZero(pub, sizeof(pub));
    }
    return SE_MANAGE_OK;
}

static uint32_t do_pairing_load(const uint8_t *body, uint16_t body_len, char *msg,
                                uint16_t msg_cap)
{
    uint8_t have_slot = 0U;
    uint8_t have_priv[32];
    uint8_t have_pub[32];
    lt_ret_t nv;

    if ((body == NULL) || (body_len != 65U) || (body[0] < 1U) || (body[0] > 3U)) {
        set_msg(msg, msg_cap, "bad PAIRING LOAD");
        return SE_MANAGE_PARSE;
    }
    nv = se_nv_get_pairing(&have_slot, have_priv, have_pub);
    wc_ForceZero(have_priv, sizeof(have_priv));
    wc_ForceZero(have_pub, sizeof(have_pub));
    if (nv == LT_OK) {
        set_msg(msg, msg_cap, "pairing present");
        return SE_MANAGE_ERR;
    }
    if (nv != LT_FAIL) {
        set_msg(msg, msg_cap, "PAIRING LOAD failed");
        return SE_MANAGE_ERR;
    }
    return tropic_map(se_tropic_pairing_load(body[0], body + 1U, body + 33U), msg, msg_cap,
                      "PAIRING LOAD ok", "PAIRING LOAD failed");
}

static uint32_t do_owner_replace(const uint8_t *body, uint16_t body_len, char *msg,
                                 uint16_t msg_cap)
{
    uint8_t old_len;
    uint8_t new_len;
    uint16_t spki_len;
    uint32_t off;
    lt_ret_t ret;

    if ((body == NULL) || (body_len < 4U)) {
        set_msg(msg, msg_cap, "bad OWNER REPLACE");
        return SE_MANAGE_PARSE;
    }
    old_len = body[0];
    if ((old_len < SE_OWNER_PW_MIN) || (old_len > SE_OWNER_PW_MAX) ||
        (body_len < (1U + (uint16_t)old_len + 1U))) {
        set_msg(msg, msg_cap, "bad OWNER REPLACE");
        return SE_MANAGE_PARSE;
    }
    off = 1U + (uint32_t)old_len;
    new_len = body[off];
    if ((new_len < SE_OWNER_PW_MIN) || (new_len > SE_OWNER_PW_MAX) ||
        (body_len < (uint16_t)(off + 1U + new_len + 2U))) {
        set_msg(msg, msg_cap, "bad OWNER REPLACE");
        return SE_MANAGE_PARSE;
    }
    off += 1U + (uint32_t)new_len;
    spki_len = se_u16le(body + off);
    if ((spki_len == 0U) || (spki_len > SE_NV_OWNER_SPKI_MAX) ||
        (body_len != (uint16_t)(off + 2U + spki_len))) {
        set_msg(msg, msg_cap, "bad OWNER REPLACE");
        return SE_MANAGE_PARSE;
    }
    ret = se_owner_replace(body + 1U, old_len, body + 1U + old_len + 1U, new_len,
                           body + off + 2U, spki_len);
    if (ret == LT_OK) {
        set_msg(msg, msg_cap, "OWNER REPLACE ok");
        return SE_MANAGE_OK;
    }
    if (ret == LT_PARAM_ERR) {
        set_msg(msg, msg_cap, "bad OWNER REPLACE");
        return SE_MANAGE_PARSE;
    }
    if (ret == LT_FAIL) {
        set_msg(msg, msg_cap, "OWNER REPLACE failed");
        return SE_MANAGE_PW_FAIL;
    }
    set_msg(msg, msg_cap, "OWNER REPLACE failed");
    return SE_MANAGE_ERR;
}

uint32_t se_manage_req_need(const uint8_t *buf, uint32_t got)
{
    uint8_t pin_len;
    uint16_t body_len;

    if ((buf == NULL) || (got < 2U)) {
        return 0U;
    }
    pin_len = buf[1];
    if (pin_len > SE_TROPIC_PIN_SIZE_MAX) {
        return 0xffffffffu;
    }
    if (got < (2U + (uint32_t)pin_len + 2U)) {
        return 0U;
    }
    body_len = se_u16le(buf + 2U + pin_len);
    if (body_len > SE_MANAGE_BODY_MAX) {
        return 0xffffffffu;
    }
    return 2U + (uint32_t)pin_len + 2U + (uint32_t)body_len;
}

uint32_t se_manage_owner_set_need(const uint8_t *buf, uint32_t got)
{
    uint8_t pw_len;
    uint16_t n;
    uint32_t off;

    if ((buf == NULL) || (got < 1U)) {
        return 0U;
    }
    pw_len = buf[0];
    if ((pw_len < SE_OWNER_PW_MIN) || (pw_len > SE_OWNER_PW_MAX)) {
        return 0xffffffffu;
    }
    if (got < (1U + (uint32_t)pw_len + 2U)) {
        return 0U;
    }
    n = se_u16le(buf + 1U + pw_len);
    if ((n == 0U) || (n > SE_NV_OWNER_SPKI_MAX)) {
        return 0xffffffffu;
    }
    off = 1U + (uint32_t)pw_len + 2U + (uint32_t)n;
    if (got < (off + 2U)) {
        return 0U;
    }
    n = se_u16le(buf + off);
    if (n > SE_CREDS_DER_MAX) {
        return 0xffffffffu;
    }
    return off + 2U + (uint32_t)n;
}

uint32_t se_manage_owner_set_parse(const uint8_t *buf, uint32_t len,
                                   const uint8_t **pw, uint8_t *pw_len,
                                   const uint8_t **spki, uint16_t *spki_len,
                                   const uint8_t **ca, uint16_t *ca_len)
{
    uint8_t pw_n;
    uint16_t spki_n;
    uint16_t ca_n;
    uint32_t off;

    if ((se_manage_owner_set_need(buf, len) != len) || (pw == NULL) || (pw_len == NULL) ||
        (spki == NULL) || (spki_len == NULL) || (ca == NULL) || (ca_len == NULL)) {
        return SE_MANAGE_PARSE;
    }
    pw_n = buf[0];
    spki_n = se_u16le(buf + 1U + pw_n);
    off = 1U + (uint32_t)pw_n + 2U + (uint32_t)spki_n;
    ca_n = se_u16le(buf + off);
    *pw_len = pw_n;
    *pw = buf + 1U;
    *spki_len = spki_n;
    *spki = buf + 1U + pw_n + 2U;
    *ca_len = ca_n;
    *ca = (ca_n == 0U) ? NULL : (buf + off + 2U);
    return SE_MANAGE_OK;
}

uint16_t se_manage_rsp_encode(uint8_t *out, uint16_t cap, uint8_t status, const char *msg)
{
    size_t n = 0U;

    if ((out == NULL) || (cap < 3U)) {
        return 0U;
    }
    if (msg != NULL) {
        n = strlen(msg);
        if (n > (size_t)SE_MANAGE_MSG_MAX) {
            n = (size_t)SE_MANAGE_MSG_MAX;
        }
    }
    if (cap < (uint16_t)(3U + n)) {
        return 0U;
    }
    out[0] = status;
    se_put_u16le(out + 1U, (uint16_t)n);
    if (n > 0U) {
        (void)memcpy(out + 3U, msg, n);
    }
    return (uint16_t)(3U + n);
}

uint32_t se_manage_apply_buf(const uint8_t *buf, uint32_t len, char *msg, uint16_t msg_cap)
{
    uint8_t pin_len;
    uint16_t body_len;
    const uint8_t *pin;
    const uint8_t *body;

    if ((buf == NULL) || (se_manage_req_need(buf, len) != len)) {
        return SE_MANAGE_PARSE;
    }
    pin_len = buf[1];
    pin = (pin_len == 0U) ? NULL : (buf + 2U);
    body_len = se_u16le(buf + 2U + pin_len);
    body = (body_len == 0U) ? NULL : (buf + 2U + pin_len + 2U);
    return se_manage_apply(buf[0], pin, pin_len, body, body_len, msg, msg_cap);
}

uint32_t se_manage_apply(uint8_t cmd, const uint8_t *pin, uint8_t pin_len,
                         const uint8_t *body, uint16_t body_len, char *msg,
                         uint16_t msg_cap)
{
    uint32_t st;

    if ((cmd == SE_MANAGE_KEM_INIT) && (pin_len != 0U) && (pin_ok(pin, pin_len) == 0)) {
        set_msg(msg, msg_cap, "bad PIN");
        return SE_MANAGE_PARSE;
    }

    switch (cmd) {
    case SE_MANAGE_KEM_INIT:
        if (pin_ok(pin, pin_len) == 0) {
            set_msg(msg, msg_cap, "PIN required");
            return SE_MANAGE_PARSE;
        }
        if ((body != NULL) && (body_len != 0U)) {
            set_msg(msg, msg_cap, "bad KEM INIT");
            return SE_MANAGE_PARSE;
        }
        st = se_tropic_kem_init_probe();
        if (st != SE_TROPIC_OK) {
            return tropic_map(st, msg, msg_cap, "", "KEM INIT failed");
        }
        return tropic_map(se_tropic_kem_init_confirm(pin, pin_len, NULL, 0U), msg, msg_cap,
                          "KEM INIT ok", "KEM INIT failed");
    case SE_MANAGE_KEYGEN:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad KEYGEN");
            return SE_MANAGE_PARSE;
        }
        if ((body != NULL) && (body_len != 0U)) {
            set_msg(msg, msg_cap, "bad KEYGEN");
            return SE_MANAGE_PARSE;
        }
        return tropic_map(se_tropic_keygen(), msg, msg_cap, "KEYGEN ok", "KEYGEN failed");
    case SE_MANAGE_PEER_ADD:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad PEER ADD");
            return SE_MANAGE_PARSE;
        }
        return do_peer_add(body, body_len, msg, msg_cap);
    case SE_MANAGE_PEER_REMOVE:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad PEER REMOVE");
            return SE_MANAGE_PARSE;
        }
        return do_peer_remove(body, body_len, msg, msg_cap);
    case SE_MANAGE_CREDS_SAE:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad CREDS SAE");
            return SE_MANAGE_PARSE;
        }
        return do_creds_sae(body, body_len, msg, msg_cap);
    case SE_MANAGE_INSERT_SIGNED_CSR:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad INSERT SIGNED CSR");
            return SE_MANAGE_PARSE;
        }
        return do_insert_signed_csr(body, body_len, msg, msg_cap);
    case SE_MANAGE_OWNER_REPLACE:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad OWNER REPLACE");
            return SE_MANAGE_PARSE;
        }
        return do_owner_replace(body, body_len, msg, msg_cap);
    case SE_MANAGE_PAIRING:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad PAIRING");
            return SE_MANAGE_PARSE;
        }
        return do_pairing(body, body_len, msg, msg_cap);
    case SE_MANAGE_PAIRING_LOAD:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad PAIRING LOAD");
            return SE_MANAGE_PARSE;
        }
        return do_pairing_load(body, body_len, msg, msg_cap);
    default:
        set_msg(msg, msg_cap, "bad command");
        return SE_MANAGE_BAD_CMD;
    }
}
