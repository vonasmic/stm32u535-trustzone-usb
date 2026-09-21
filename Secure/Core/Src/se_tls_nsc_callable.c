/**
 * @file    se_tls_nsc_callable.c
 * @brief   NSC veneers: USB pipe, wall clock, TLS service for NonSecure
 *
 * Every NonSecure-supplied pointer is validated with cmse_check_address_range
 * (SAU/IDAU non-secure + MPU access) before use. Callers must use the
 * returned sanitized pointer, never the raw NS argument.
 */
#include "se_tls_nsc.h"
#include "se_usb_tls.h"
#include "se_tls_client.h"
#include "se_time.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_session.h"
#include "se_nv.h"
#include "se_auth.h"
#include "se_device_id.h"
#if defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
#include <arm_cmse.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * NS input buffer: must be entirely NonSecure and readable.
 * @return sanitized pointer, or NULL on failure. len==0 always succeeds (NULL ok).
 */
static void *ns_sanitize_in(const void *p, uint32_t len)
{
    uintptr_t base;

    if (len == 0U) {
        return (void *)p; /* empty: no access; keep original (may be NULL) */
    }
    if (p == NULL) {
        return NULL;
    }
    base = (uintptr_t)p;
    if (base + (uintptr_t)len < base) {
        return NULL; /* length overflow */
    }
#if defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
    return cmse_check_address_range((void *)p, (size_t)len,
                                    CMSE_NONSECURE | CMSE_MPU_READ);
#else
    (void)base;
    return (void *)p;
#endif
}

/** NS output buffer: must be entirely NonSecure and writable. */
static void *ns_sanitize_out(void *p, uint32_t len)
{
    uintptr_t base;

    if (p == NULL || len == 0U) {
        return NULL;
    }
    base = (uintptr_t)p;
    if (base + (uintptr_t)len < base) {
        return NULL;
    }
#if defined(__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
    return cmse_check_address_range(p, (size_t)len,
                                    CMSE_NONSECURE | CMSE_MPU_READWRITE);
#else
    (void)base;
    return p;
#endif
}

/** Collapsed USB Tropic status: ok, empty occupancy, or err. */
static uint32_t tropic_nsc_ok_err(uint32_t st)
{
    return (st == SE_TROPIC_OK) ? SECURE_TROPIC_OK : SECURE_TROPIC_ERR;
}

static uint32_t tropic_nsc_dump(uint32_t st)
{
    if (st == SE_TROPIC_OK) {
        return SECURE_TROPIC_OK;
    }
    if (st == SE_TROPIC_NOT_READY) {
        return SECURE_USB_DUMP_EMPTY;
    }
    return SECURE_TROPIC_ERR;
}

uint32_t CSME_NSE_API SECURE_UsbRx_nsc_call(const uint8_t *buf, uint32_t len)
{
    if (len > SECURE_USB_PKT_MAX) {
        se_tls_abort();
        return SECURE_USB_ERR;
    }
    if (len > 0U) {
        const uint8_t *ns_buf = (const uint8_t *)ns_sanitize_in(buf, len);

        if (ns_buf == NULL) {
            return SECURE_USB_ERR;
        }
        if (se_usb_tls_rx_push(ns_buf, len) < 0) {
            se_tls_abort();
            return SECURE_USB_ERR;
        }
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_UsbTx_nsc_call(uint8_t *buf, uint32_t max, uint32_t *out_len)
{
    uint8_t *ns_buf;
    uint32_t *ns_out_len = NULL;
    uint32_t got = 0U;
    int st;

    if (max > SECURE_USB_PKT_MAX) {
        max = SECURE_USB_PKT_MAX;
    }
    if (max == 0U) {
        return SECURE_USB_ERR;
    }
    ns_buf = (uint8_t *)ns_sanitize_out(buf, max);
    if (ns_buf == NULL) {
        return SECURE_USB_ERR;
    }
    if (out_len != NULL) {
        ns_out_len = (uint32_t *)ns_sanitize_out(out_len, (uint32_t)sizeof(uint32_t));
        if (ns_out_len == NULL) {
            return SECURE_USB_ERR;
        }
    }

    st = se_usb_tls_tx_pop(ns_buf, max, &got);
    if (st < 0) {
        return SECURE_USB_LINK_DOWN;
    }
    if (st > 0) {
        if (ns_out_len != NULL) {
            *ns_out_len = 0U;
        }
        return SECURE_USB_BUSY;
    }
    if (ns_out_len != NULL) {
        *ns_out_len = got;
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
        se_auth_abort();
        se_tls_reset_quiet();
        se_usb_tls_set_active(0U);
        break;
    case SECURE_USB_EVT_DTR_ON:
        se_usb_tls_set_dtr(1U);
        break;
    case SECURE_USB_EVT_DTR_OFF:
        se_auth_abort();
        se_usb_tls_set_dtr(0U);
        break;
    default:
        return SECURE_USB_ERR;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_UsbService_nsc_call(void)
{
    if (se_auth_active() != 0) {
        se_auth_service();
        return (se_auth_active() != 0) ? SECURE_USB_OK : SECURE_USB_IDLE;
    }
    se_usb_tls_service_once();
    if (se_tls_session_active() == 0) {
        return SECURE_USB_IDLE;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_OwnerBegin_nsc_call(void)
{
    if (se_tls_session_active() != 0) {
        return SECURE_USB_ERR;
    }
    return (se_auth_begin_owner() == SE_AUTH_OK) ? SECURE_USB_OK : SECURE_USB_ERR;
}

uint32_t CSME_NSE_API SECURE_TlsStart_nsc_call(uint32_t mode, uint32_t unix_utc)
{
    int rc;

    if (se_auth_active() != 0) {
        return SECURE_USB_ERR;
    }
    if ((mode != SECURE_TLS_MODE_PROVISION) && (mode != SECURE_TLS_MODE_ENCRYPT) &&
        (mode != SECURE_TLS_MODE_DECRYPT) && (mode != SECURE_TLS_MODE_MANAGE)) {
        return SECURE_USB_ERR;
    }

    rc = se_time_set_unix(unix_utc);
    if (rc < 0) {
        return SECURE_USB_ERR;
    }

    return (se_tls_arm(mode) == 0) ? SECURE_USB_OK : SECURE_USB_ERR;
}

uint32_t CSME_NSE_API SECURE_SetUnixTime_nsc_call(uint32_t unix_utc)
{
    int rc = se_time_set_unix(unix_utc);

    if (rc < 0) {
        return SECURE_USB_ERR;
    }
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_GetUnixTime_nsc_call(void)
{
    return se_time_unix_now();
}

uint32_t CSME_NSE_API SECURE_UsbLog_nsc_call(const uint8_t *msg, uint32_t len)
{
    const uint8_t *ns_msg;
    char tmp[160];

    if (len == 0U || len >= sizeof(tmp)) {
        return SECURE_USB_ERR;
    }
    ns_msg = (const uint8_t *)ns_sanitize_in(msg, len);
    if (ns_msg == NULL) {
        return SECURE_USB_ERR;
    }
    (void)memcpy(tmp, ns_msg, len);
    tmp[len] = '\0';
    se_usb_debug_puts(tmp);
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_UsbDump_nsc_call(uint8_t status, const uint8_t *body, uint32_t len)
{
    const uint8_t *ns_body = NULL;

    if (len > SE_USB_DUMP_BODY_MAX) {
        return SECURE_USB_ERR;
    }
    if (len > 0U) {
        ns_body = (const uint8_t *)ns_sanitize_in(body, len);
        if (ns_body == NULL) {
            return SECURE_USB_ERR;
        }
    }
    return (se_usb_dump(status, ns_body, (uint16_t)len) == 0) ? SECURE_USB_OK : SECURE_USB_ERR;
}

uint32_t CSME_NSE_API SECURE_TropicPing_nsc_call(void)
{
    return tropic_nsc_ok_err(se_tropic_ping());
}

uint32_t CSME_NSE_API SECURE_TropicInfo_nsc_call(void)
{
    return tropic_nsc_ok_err(se_tropic_info());
}

uint32_t CSME_NSE_API SECURE_TropicPub_nsc_call(uint8_t *out_xy64)
{
    uint8_t *ns_out;

    ns_out = (uint8_t *)ns_sanitize_out(out_xy64, 64U);
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    return tropic_nsc_dump(se_tropic_pub_read(ns_out));
}

uint32_t CSME_NSE_API SECURE_TropicClientHash_nsc_call(uint8_t *out48)
{
    uint8_t *ns_out;

    ns_out = (uint8_t *)ns_sanitize_out(out48, SE_TROPIC_CLIENT_HASH_LEN);
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    return tropic_nsc_ok_err(se_tropic_client_hash_read(ns_out));
}

uint32_t CSME_NSE_API SECURE_ClientCsr_nsc_call(uint8_t *out, uint32_t *len_inout)
{
    uint8_t *ns_out;
    uint32_t *ns_len;
    uint16_t n = 0U;
    uint32_t cap;
    lt_ret_t ret;

    ns_len = (uint32_t *)ns_sanitize_out(len_inout, (uint32_t)sizeof(uint32_t));
    if (ns_len == NULL) {
        return SECURE_TROPIC_ERR;
    }
    cap = *ns_len;
    if ((cap < 1U) || (cap > SE_USB_DUMP_BODY_MAX)) {
        return SECURE_TROPIC_ERR;
    }
    ns_out = (uint8_t *)ns_sanitize_out(out, cap);
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    if (se_device_id_ensure() != LT_OK) {
        return SECURE_TROPIC_ERR;
    }
    n = (uint16_t)cap;
    ret = se_device_id_export_pub(ns_out, &n, (uint16_t)cap);
    if (ret != LT_OK) {
        return SECURE_TROPIC_ERR;
    }
    *ns_len = (uint32_t)n;
    return SECURE_TROPIC_OK;
}

uint32_t CSME_NSE_API SECURE_TropicKemPub_nsc_call(uint8_t *out, uint32_t *len_inout)
{
    uint8_t *ns_out;
    uint32_t *ns_len;
    uint16_t n = 0U;
    uint32_t cap;

    ns_len = (uint32_t *)ns_sanitize_out(len_inout, (uint32_t)sizeof(uint32_t));
    if (ns_len == NULL) {
        return SECURE_TROPIC_ERR;
    }
    cap = *ns_len;
    if ((cap < 1U) || (cap > SE_TROPIC_MLKEM_PK_LEN)) {
        return SECURE_TROPIC_ERR;
    }
    ns_out = (uint8_t *)ns_sanitize_out(out, cap);
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    n = 0U;
    {
        uint32_t st = tropic_nsc_dump(se_tropic_mlkem_pub_read(ns_out, (uint16_t)cap, &n));

        if (st != SECURE_TROPIC_OK) {
            return st;
        }
        *ns_len = (uint32_t)n;
        return SECURE_TROPIC_OK;
    }
}

uint32_t CSME_NSE_API SECURE_TropicOtpLeft_nsc_call(uint32_t out_quotas[4])
{
    uint32_t *ns_out;

    ns_out = (uint32_t *)ns_sanitize_out(out_quotas, (uint32_t)(4U * sizeof(uint32_t)));
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    return tropic_nsc_ok_err(se_tropic_otp_left(ns_out));
}

static uint32_t peer_lt_to_nsc(lt_ret_t ret)
{
    if (ret == LT_OK) {
        return SECURE_PEER_OK;
    }
    if (ret == SE_NV_PEER_NOT_FOUND) {
        return SECURE_PEER_NOT_FOUND;
    }
    return SECURE_PEER_ERR;
}

uint32_t CSME_NSE_API SECURE_PeerCount_nsc_call(void)
{
    uint8_t n = 0U;
    lt_ret_t ret = se_nv_peer_count(&n);

    if (ret != LT_OK) {
        return 0x80u;
    }
    return (uint32_t)n;
}

uint32_t CSME_NSE_API SECURE_PeerGet_nsc_call(uint32_t index, uint8_t *name_out,
                                              uint32_t *name_len_inout, uint8_t *hash48_out)
{
    uint8_t *ns_name;
    uint32_t *ns_nlen;
    uint8_t *ns_hash;
    uint8_t nlen;
    uint32_t cap;

    if (index > 255U) {
        return SECURE_PEER_ERR;
    }
    ns_nlen = (uint32_t *)ns_sanitize_out(name_len_inout, (uint32_t)sizeof(uint32_t));
    if (ns_nlen == NULL) {
        return SECURE_PEER_ERR;
    }
    cap = *ns_nlen;
    if ((cap < 1U) || (cap > SECURE_PEER_NAME_MAX)) {
        return SECURE_PEER_ERR;
    }
    ns_name = (uint8_t *)ns_sanitize_out(name_out, cap);
    ns_hash = (uint8_t *)ns_sanitize_out(hash48_out, SECURE_PEER_HASH_LEN);
    if ((ns_name == NULL) || (ns_hash == NULL)) {
        return SECURE_PEER_ERR;
    }
    nlen = (uint8_t)cap;
    {
        lt_ret_t ret = se_nv_peer_get((uint8_t)index, ns_name, &nlen, ns_hash);

        if (ret == LT_OK) {
            *ns_nlen = (uint32_t)nlen;
        }
        return peer_lt_to_nsc(ret);
    }
}
