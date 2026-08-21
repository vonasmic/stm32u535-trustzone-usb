/**
 * @file    se_tls_nsc_callable.c
 * @brief   NSC veneers: USB pipe, wall clock, TLS service for NonSecure
 */
#include "se_tls_nsc.h"
#include "se_usb_tls.h"
#include "se_tls_json_client.h"
#include "se_time.h"
#include "main.h"
#include <arm_cmse.h>
#include <string.h>

static int ns_ok_ptr(const void *p, uint32_t len)
{
    if (len == 0U) {
        return 1;
    }
    if (p == NULL) {
        return 0;
    }
    return cmse_check_address_range((void *)p, (size_t)len, CMSE_NONSECURE) != NULL;
}

static int ns_ok_out_ptr(const void *p, uint32_t len)
{
    if (p == NULL) {
        return 0;
    }
    return cmse_check_address_range((void *)p, (size_t)len, CMSE_NONSECURE) != NULL;
}

uint32_t CSME_NSE_API SECURE_UsbRx_nsc_call(const uint8_t *buf, uint32_t len)
{
    if (len > SECURE_USB_PKT_MAX) {
        se_tls_json_abort();
        return SECURE_USB_ERR;
    }
    if (len > 0U && !ns_ok_ptr(buf, len)) {
        return SECURE_USB_ERR;
    }
    if (len > 0U && se_usb_tls_rx_push(buf, len) < 0) {
        se_tls_json_abort();
        return SECURE_USB_ERR;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_UsbTx_nsc_call(uint8_t *buf, uint32_t max, uint32_t *out_len)
{
    uint32_t got = 0U;
    int st;

    if (max > SECURE_USB_PKT_MAX) {
        max = SECURE_USB_PKT_MAX;
    }
    if (buf == NULL || max == 0U) {
        return SECURE_USB_ERR;
    }
    if (!ns_ok_out_ptr(buf, max)) {
        return SECURE_USB_ERR;
    }
    if (out_len != NULL && !ns_ok_out_ptr(out_len, sizeof(uint32_t))) {
        return SECURE_USB_ERR;
    }

    st = se_usb_tls_tx_pop(buf, max, &got);
    if (st < 0) {
        return SECURE_USB_LINK_DOWN;
    }
    if (st > 0) {
        if (out_len != NULL) {
            *out_len = 0U;
        }
        return SECURE_USB_BUSY;
    }
    if (out_len != NULL) {
        *out_len = got;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_UsbEvent_nsc_call(uint32_t event)
{
    switch (event) {
    case SECURE_USB_EVT_ACTIVATE:
        se_usb_tls_set_active(1U);
        break;
    case SECURE_USB_EVT_DEACTIVATE:
        se_tls_json_reset_quiet();
        se_usb_tls_set_active(0U);
        break;
    case SECURE_USB_EVT_DTR_ON:
        se_usb_tls_set_dtr(1U);
        break;
    case SECURE_USB_EVT_DTR_OFF:
        se_usb_tls_set_dtr(0U);
        break;
    default:
        return SECURE_USB_ERR;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_UsbService_nsc_call(void)
{
    se_usb_tls_service_once();
    if (se_time_is_synced() == 0) {
        return SECURE_USB_IDLE;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_SetUnixTime_nsc_call(uint32_t unix_utc)
{
    if (se_time_set_unix(unix_utc) != 0) {
        return SECURE_USB_ERR;
    }
    se_usb_debug_printf("time synced unix=%lu", (unsigned long)unix_utc);
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_GetUnixTime_nsc_call(void)
{
    return se_time_unix_now();
}

uint32_t CSME_NSE_API SECURE_UsbLog_nsc_call(const uint8_t *msg, uint32_t len)
{
    char tmp[160];

    if (len == 0U || len >= sizeof(tmp)) {
        return SECURE_USB_ERR;
    }
    if (!ns_ok_ptr(msg, len)) {
        return SECURE_USB_ERR;
    }
    (void)memcpy(tmp, msg, len);
    tmp[len] = '\0';
    se_usb_debug_printf("%s", tmp);
    return SECURE_USB_OK;
}
