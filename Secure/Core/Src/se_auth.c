/**
 * @file    se_auth.c
 * @brief   First-wins USB OWNER SET ingest (unsigned blob on CDC)
 *
 * Wire need/parse lives in se_manage.c (Java: fel.cvut.se.SeManage).
 */
#include "se_auth.h"
#include "se_creds.h"
#include "se_device_id.h"
#include "se_manage.h"
#include "se_nv.h"
#include "se_owner.h"
#include "se_usb_tls.h"

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
        return SE_AUTH_ERR;
    }
    se_usb_tls_clear_rx();
    se_manage_buf_wipe();
    s_got = 0U;
    s_armed = 1U;
    return SE_AUTH_OK;
}

static void run_owner_set(const uint8_t *f, uint32_t len)
{
    const uint8_t *pw;
    const uint8_t *spki;
    const uint8_t *ca;
    uint8_t pw_len;
    uint16_t spki_len;
    uint16_t ca_len;

    if (se_manage_owner_set_parse(f, len, &pw, &pw_len, &spki, &spki_len, &ca, &ca_len) !=
        SE_MANAGE_OK) {
        (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    if (se_owner_set(pw, pw_len, spki, spki_len) != LT_OK) {
        (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    if (se_device_id_ensure() != LT_OK) {
        (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    if ((ca_len != 0U) && (se_creds_set_sae_ca(ca, ca_len) != LT_OK)) {
        (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    (void)se_usb_dump(SE_USB_DUMP_OK, NULL, 0U);
}

void se_auth_service(void)
{
    uint8_t *frame = se_manage_buf();
    uint32_t cap = se_manage_buf_cap();
    int n;
    int st;

    if (s_armed == 0U) {
        return;
    }
    if (se_usb_tls_rx_overflow() != 0U) {
        (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
        se_auth_abort();
        return;
    }
    while (s_got < cap) {
        n = se_usb_tls_rx_take(frame + s_got, cap - s_got);
        if (n <= 0) {
            break;
        }
        s_got += (uint32_t)n;
        st = se_manage_frame_ready(s_got, se_manage_owner_set_need);
        if (st < 0) {
            (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
            se_auth_abort();
            return;
        }
        if (st == SE_FRAME_COMPLETE) {
            run_owner_set(frame, s_got);
            se_auth_abort();
            return;
        }
    }
    if (s_got >= cap) {
        (void)se_usb_dump(SE_USB_DUMP_ERR, NULL, 0U);
        se_auth_abort();
    }
}
