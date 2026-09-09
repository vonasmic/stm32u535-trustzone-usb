/**
 * @file    se_auth.c
 * @brief   First-wins USB OWNER SET: unsigned pw + SPKI + optional device creds
 */
#include "se_auth.h"
#include "se_creds.h"
#include "se_le.h"
#include "se_manage.h"
#include "se_nv.h"
#include "se_owner.h"
#include "se_tropic.h"
#include "se_tropic_port.h"
#include "se_usb_tls.h"
#include "wolfssl/wolfcrypt/memory.h"
#include <string.h>

static uint8_t s_armed;
static uint32_t s_got;

int se_auth_active(void)
{
    return (s_armed != 0U) ? 1 : 0;
}

void se_auth_abort(void)
{
    s_armed = 0U;
    s_got = 0U;
    se_manage_buf_wipe();
    se_usb_tls_clear_rx();
}

uint32_t se_auth_begin_owner(void)
{
    if (s_armed != 0U) {
        return SE_AUTH_ERR;
    }
    if (se_nv_has_owner() != 0) {
        se_tropic_log("OWNER SET refused: already enrolled");
        return SE_AUTH_ERR;
    }
    se_usb_tls_clear_rx();
    se_manage_buf_wipe();
    s_got = 0U;
    s_armed = 1U;
    return SE_AUTH_OK;
}

/**
 * OWNER SET blob:
 *   u8 pw_len | pw | u16le spki_len | spki
 *   u16le cert_len | cert | u16le key_len | key | u16le ca_len | ca
 * cert/key/ca lengths may be 0. cert and key must both be present or both omitted.
 * @return needed size, 0 if more bytes required, 0xffffffff on parse fail
 */
static uint32_t frame_need(const uint8_t *f, uint32_t got)
{
    uint8_t pw_len;
    uint16_t n;
    uint32_t off;

    if (got < 1U) {
        return 0U;
    }
    pw_len = f[0];
    if ((pw_len < SE_OWNER_PW_MIN) || (pw_len > SE_OWNER_PW_MAX)) {
        return 0xffffffffu;
    }
    if (got < (1U + (uint32_t)pw_len + 2U)) {
        return 0U;
    }
    n = se_u16le(f + 1U + pw_len);
    if ((n == 0U) || (n > SE_NV_OWNER_SPKI_MAX)) {
        return 0xffffffffu;
    }
    off = 1U + (uint32_t)pw_len + 2U + (uint32_t)n;
    if (got < (off + 2U)) {
        return 0U;
    }
    n = se_u16le(f + off);
    if (n > SE_CREDS_DER_MAX) {
        return 0xffffffffu;
    }
    off += 2U + (uint32_t)n;
    if (got < (off + 2U)) {
        return 0U;
    }
    n = se_u16le(f + off);
    if (n > SE_MANAGE_KEY_DER_MAX) {
        return 0xffffffffu;
    }
    off += 2U + (uint32_t)n;
    if (got < (off + 2U)) {
        return 0U;
    }
    n = se_u16le(f + off);
    if (n > SE_CREDS_DER_MAX) {
        return 0xffffffffu;
    }
    return off + 2U + (uint32_t)n;
}

static void run_owner_set(const uint8_t *f)
{
    uint8_t pw_len;
    uint16_t spki_len;
    uint16_t cert_len;
    uint16_t key_len;
    uint16_t ca_len;
    uint32_t off;
    const uint8_t *spki;
    const uint8_t *cert;
    const uint8_t *key;
    const uint8_t *ca;

    pw_len = f[0];
    spki_len = se_u16le(f + 1U + pw_len);
    spki = f + 1U + pw_len + 2U;
    off = 1U + (uint32_t)pw_len + 2U + (uint32_t)spki_len;
    cert_len = se_u16le(f + off);
    cert = f + off + 2U;
    off += 2U + (uint32_t)cert_len;
    key_len = se_u16le(f + off);
    key = f + off + 2U;
    off += 2U + (uint32_t)key_len;
    ca_len = se_u16le(f + off);
    ca = f + off + 2U;

    if (((cert_len == 0U) && (key_len != 0U)) || ((cert_len != 0U) && (key_len == 0U))) {
        se_tropic_log("OWNER SET failed");
        return;
    }
    if (se_owner_set(f + 1U, pw_len, spki, spki_len) != LT_OK) {
        se_tropic_log("OWNER SET failed");
        return;
    }
    if ((cert_len != 0U) &&
        (se_manage_store_device(cert, cert_len, key, key_len) != SE_MANAGE_OK)) {
        se_tropic_log("OWNER SET ok; device creds failed");
        return;
    }
    if ((ca_len != 0U) && (se_creds_set_sae_ca(ca, ca_len) != LT_OK)) {
        se_tropic_log("OWNER SET ok; SAE CA failed");
        return;
    }
    se_tropic_log("OWNER SET ok");
}

void se_auth_service(void)
{
    uint8_t *frame = se_manage_buf();
    uint32_t cap = se_manage_buf_cap();
    uint32_t need;
    int n;

    if (s_armed == 0U) {
        return;
    }
    if (se_usb_tls_rx_overflow() != 0U) {
        se_tropic_log("auth: RX overflow");
        se_auth_abort();
        return;
    }
    while (s_got < cap) {
        n = se_usb_tls_rx_take(frame + s_got, cap - s_got);
        if (n <= 0) {
            break;
        }
        s_got += (uint32_t)n;
    }
    need = frame_need(frame, s_got);
    if (need == 0xffffffffu) {
        se_tropic_log("auth: bad frame");
        se_auth_abort();
        return;
    }
    if ((need == 0U) || (s_got < need)) {
        if (s_got >= cap) {
            se_tropic_log("auth: bad frame");
            se_auth_abort();
        }
        return;
    }
    run_owner_set(frame);
    se_auth_abort();
}
