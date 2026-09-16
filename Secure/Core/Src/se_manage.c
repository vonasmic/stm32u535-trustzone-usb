/**
 * @file    se_manage.c
 * @brief   PIN-gated / identity-changing commands for owner-pinned TLS
 */
#include "se_manage.h"
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
    return ((pin != NULL) && (pin_len >= SE_TROPIC_PIN_SIZE_MIN) &&
            (pin_len <= SE_TROPIC_PIN_SIZE_MAX))
               ? 1
               : 0;
}

static uint32_t tropic_map(uint32_t st, char *msg, uint16_t cap, const char *ok)
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
    set_msg(msg, cap, "command failed");
    return SE_MANAGE_ERR;
}

uint32_t se_manage_store_device(const uint8_t *cert, uint16_t cert_len,
                                const uint8_t *key, uint16_t key_len)
{
    if ((cert == NULL) || (key == NULL) || (cert_len == 0U) || (key_len == 0U) ||
        (cert_len > SE_CREDS_DER_MAX) || (key_len > SE_MANAGE_KEY_DER_MAX) ||
        (key_len > SE_NV_SK_MAX)) {
        return SE_MANAGE_PARSE;
    }
    if (se_creds_set_device_cert(cert, cert_len) != LT_OK) {
        return SE_MANAGE_ERR;
    }
    if (se_nv_set_device_sk(key, key_len) != LT_OK) {
        return SE_MANAGE_ERR;
    }
    return SE_MANAGE_OK;
}

static uint32_t peer_pin_gate(const uint8_t *pin, uint8_t pin_len)
{
    uint8_t final_key[SE_TROPIC_PIN_HMAC_LEN];
    lt_handle_t *h;
    lt_ret_t ret;

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_MANAGE_ERR;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return SE_MANAGE_ERR;
    }
    ret = se_tropic_pin_check(h, pin, pin_len, NULL, 0U, final_key);
    wc_ForceZero(final_key, sizeof(final_key));
    if (ret != LT_OK) {
        return SE_MANAGE_PIN_FAIL;
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

static uint32_t do_peer_add(const uint8_t *pin, uint8_t pin_len, const uint8_t *body,
                            uint16_t body_len, char *msg, uint16_t msg_cap)
{
    uint8_t nlen;
    uint32_t st;

    if (pin_ok(pin, pin_len) == 0) {
        set_msg(msg, msg_cap, "PIN required");
        return SE_MANAGE_PARSE;
    }
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
    st = peer_pin_gate(pin, pin_len);
    if (st != SE_MANAGE_OK) {
        set_msg(msg, msg_cap, "PIN fail");
        return st;
    }
    return peer_map(se_nv_peer_add(body + 1U, nlen, body + 1U + nlen), msg, msg_cap,
                    "PEER ADD ok");
}

static uint32_t do_peer_remove(const uint8_t *pin, uint8_t pin_len, const uint8_t *body,
                               uint16_t body_len, char *msg, uint16_t msg_cap)
{
    uint8_t nlen;
    uint32_t st;

    if (pin_ok(pin, pin_len) == 0) {
        set_msg(msg, msg_cap, "PIN required");
        return SE_MANAGE_PARSE;
    }
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
    st = peer_pin_gate(pin, pin_len);
    if (st != SE_MANAGE_OK) {
        set_msg(msg, msg_cap, "PIN fail");
        return st;
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

static uint32_t do_creds_device(const uint8_t *body, uint16_t body_len, char *msg,
                                uint16_t msg_cap)
{
    uint16_t cert_len;
    uint16_t key_len;
    uint32_t st;

    if ((body == NULL) || (body_len < 4U)) {
        set_msg(msg, msg_cap, "bad CREDS DEVICE");
        return SE_MANAGE_PARSE;
    }
    cert_len = se_u16le(body);
    if ((cert_len == 0U) || (cert_len > SE_CREDS_DER_MAX) ||
        (body_len < (4U + (uint32_t)cert_len))) {
        set_msg(msg, msg_cap, "bad CREDS DEVICE");
        return SE_MANAGE_PARSE;
    }
    key_len = se_u16le(body + 2U + cert_len);
    if ((key_len == 0U) || (key_len > SE_MANAGE_KEY_DER_MAX) ||
        (body_len != (4U + cert_len + key_len))) {
        set_msg(msg, msg_cap, "bad CREDS DEVICE");
        return SE_MANAGE_PARSE;
    }
    st = se_manage_store_device(body + 2U, cert_len, body + 4U + cert_len, key_len);
    if (st != SE_MANAGE_OK) {
        set_msg(msg, msg_cap, "CREDS DEVICE failed");
        return st;
    }
    set_msg(msg, msg_cap, "CREDS DEVICE ok");
    return SE_MANAGE_OK;
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

    if ((cmd != SE_MANAGE_CREDS_SAE) && (cmd != SE_MANAGE_CREDS_DEVICE) &&
        (cmd != SE_MANAGE_OWNER_REPLACE) && (pin_len != 0U) &&
        (pin_ok(pin, pin_len) == 0)) {
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
            return tropic_map(st, msg, msg_cap, "");
        }
        return tropic_map(se_tropic_kem_init_confirm(pin, pin_len, NULL, 0U), msg, msg_cap,
                          "KEM INIT ok");
    case SE_MANAGE_KEYGEN:
        if (pin_ok(pin, pin_len) == 0) {
            set_msg(msg, msg_cap, "PIN required");
            return SE_MANAGE_PARSE;
        }
        if ((body != NULL) && (body_len != 0U)) {
            set_msg(msg, msg_cap, "bad KEYGEN");
            return SE_MANAGE_PARSE;
        }
        return tropic_map(se_tropic_keygen(pin, pin_len), msg, msg_cap, "KEYGEN ok");
    case SE_MANAGE_PEER_ADD:
        return do_peer_add(pin, pin_len, body, body_len, msg, msg_cap);
    case SE_MANAGE_PEER_REMOVE:
        return do_peer_remove(pin, pin_len, body, body_len, msg, msg_cap);
    case SE_MANAGE_CREDS_SAE:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad CREDS SAE");
            return SE_MANAGE_PARSE;
        }
        return do_creds_sae(body, body_len, msg, msg_cap);
    case SE_MANAGE_CREDS_DEVICE:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad CREDS DEVICE");
            return SE_MANAGE_PARSE;
        }
        return do_creds_device(body, body_len, msg, msg_cap);
    case SE_MANAGE_OWNER_REPLACE:
        if (pin_len != 0U) {
            set_msg(msg, msg_cap, "bad OWNER REPLACE");
            return SE_MANAGE_PARSE;
        }
        return do_owner_replace(body, body_len, msg, msg_cap);
    default:
        set_msg(msg, msg_cap, "bad command");
        return SE_MANAGE_BAD_CMD;
    }
}
