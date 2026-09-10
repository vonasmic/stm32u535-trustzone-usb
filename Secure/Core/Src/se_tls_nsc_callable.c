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
#include "se_tropic_pin.h"
#include "se_nv.h"
#include "se_tropic_session.h"
#include "se_auth.h"
#include "wolfssl/wolfcrypt/memory.h"
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
    if (rc > 0) {
        se_usb_debug_printf("TIME behind floor, using unix=%lu",
                            (unsigned long)se_time_unix_now());
    } else {
        se_usb_debug_printf("time synced unix=%lu", (unsigned long)unix_utc);
    }

    return (se_tls_arm(mode) == 0) ? SECURE_USB_OK : SECURE_USB_ERR;
}

uint32_t CSME_NSE_API SECURE_SetUnixTime_nsc_call(uint32_t unix_utc)
{
    int rc = se_time_set_unix(unix_utc);

    if (rc < 0) {
        return SECURE_USB_ERR;
    }
    if (rc > 0) {
        se_usb_debug_printf("TIME behind floor, using unix=%lu",
                            (unsigned long)se_time_unix_now());
    } else {
        se_usb_debug_printf("time synced unix=%lu", (unsigned long)unix_utc);
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
    se_usb_debug_printf("%s", tmp);
    return SECURE_USB_OK;
}

uint32_t CSME_NSE_API SECURE_TropicPing_nsc_call(void)
{
    return se_tropic_ping();
}

uint32_t CSME_NSE_API SECURE_TropicInfo_nsc_call(void)
{
    return se_tropic_info();
}

uint32_t CSME_NSE_API SECURE_TropicPub_nsc_call(uint8_t *out_xy64)
{
    uint8_t *ns_out;

    ns_out = (uint8_t *)ns_sanitize_out(out_xy64, 64U);
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    return se_tropic_pub_read(ns_out);
}

uint32_t CSME_NSE_API SECURE_TropicClientHash_nsc_call(void)
{
    return se_tropic_client_hash_dump();
}

uint32_t CSME_NSE_API SECURE_TropicKeygen_nsc_call(const uint8_t *pin, uint32_t pin_len)
{
    const uint8_t *ns_pin;
    uint8_t local[SE_TROPIC_PIN_SIZE_MAX];
    uint32_t st;

    if (pin_len == 0U) {
        return se_tropic_keygen(NULL, 0U);
    }
    if (pin_len < SE_TROPIC_PIN_SIZE_MIN || pin_len > SE_TROPIC_PIN_SIZE_MAX) {
        return SECURE_TROPIC_ERR;
    }
    ns_pin = (const uint8_t *)ns_sanitize_in(pin, pin_len);
    if (ns_pin == NULL) {
        return SECURE_TROPIC_ERR;
    }
    (void)memcpy(local, ns_pin, pin_len);
    st = se_tropic_keygen(local, (uint8_t)pin_len);
    wc_ForceZero(local, sizeof(local));
    return st;
}

uint32_t CSME_NSE_API SECURE_TropicSign_nsc_call(const uint8_t *hash32, uint8_t *rs64_out)
{
    const uint8_t *ns_hash;
    uint8_t *ns_rs;

    ns_hash = (const uint8_t *)ns_sanitize_in(hash32, 32U);
    ns_rs = (uint8_t *)ns_sanitize_out(rs64_out, 64U);
    if (ns_hash == NULL || ns_rs == NULL) {
        return SECURE_TROPIC_ERR;
    }
    return se_tropic_sign_hash(ns_hash, ns_rs);
}

uint32_t CSME_NSE_API SECURE_TropicKemInit_nsc_call(const uint8_t *pin, uint32_t pin_len,
                                                    uint32_t confirm)
{
    const uint8_t *ns_pin;

    if (pin_len < SE_TROPIC_PIN_SIZE_MIN || pin_len > SE_TROPIC_PIN_SIZE_MAX) {
        return SECURE_TROPIC_ERR;
    }
    ns_pin = (const uint8_t *)ns_sanitize_in(pin, pin_len);
    if (ns_pin == NULL) {
        return SECURE_TROPIC_ERR;
    }
    if (confirm != 0U) {
        return se_tropic_kem_init_confirm(ns_pin, (uint8_t)pin_len, NULL, 0U);
    }
    return se_tropic_kem_init_probe();
}

uint32_t CSME_NSE_API SECURE_TropicKemPub_nsc_call(void)
{
    return se_tropic_kem_pub_dump();
}

uint32_t CSME_NSE_API SECURE_TropicOtpLeft_nsc_call(void)
{
    return se_tropic_otp_left_dump();
}

uint32_t CSME_NSE_API SECURE_TropicPairing_nsc_call(uint32_t slot, uint8_t *out64)
{
    uint8_t *ns_out;
    uint32_t st;

    if (slot > 255U) {
        return SECURE_TROPIC_ERR;
    }
    ns_out = (uint8_t *)ns_sanitize_out(out64, 64U);
    if (ns_out == NULL) {
        return SECURE_TROPIC_ERR;
    }
    st = se_create_pairing_key_to_tropic((uint8_t)slot);
    if (st != SECURE_TROPIC_OK) {
        (void)memset(ns_out, 0, 64U);
        return st;
    }
    st = se_tropic_pairing_export(NULL, ns_out, ns_out + 32U);
    if (st != SECURE_TROPIC_OK) {
        (void)memset(ns_out, 0, 64U);
    }
    return st;
}

uint32_t CSME_NSE_API SECURE_TropicPairingLoad_nsc_call(uint32_t slot, const uint8_t *in64)
{
    const uint8_t *ns_in;
    uint8_t local[64];
    uint32_t st;

    if (slot > 255U) {
        return SECURE_TROPIC_ERR;
    }
    ns_in = (const uint8_t *)ns_sanitize_in(in64, 64U);
    if (ns_in == NULL) {
        return SECURE_TROPIC_ERR;
    }
    (void)memcpy(local, ns_in, sizeof(local));
    st = se_tropic_pairing_load((uint8_t)slot, local, local + 32U);
    wc_ForceZero(local, sizeof(local));
    return st;
}

static uint32_t peer_lt_to_nsc(lt_ret_t ret)
{
    if (ret == LT_OK) {
        return SECURE_PEER_OK;
    }
    if (ret == SE_NV_PEER_EXISTS) {
        return SECURE_PEER_EXISTS;
    }
    if (ret == SE_NV_PEER_NOT_FOUND) {
        return SECURE_PEER_NOT_FOUND;
    }
    if (ret == SE_NV_PEER_FULL) {
        return SECURE_PEER_FULL;
    }
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return SECURE_TROPIC_TAMPERED;
    }
    return SECURE_PEER_ERR;
}

static uint32_t peer_require_pin(const uint8_t *pin, uint32_t pin_len)
{
    uint8_t final_key[TR01_MAC_AND_DESTROY_DATA_SIZE];
    lt_handle_t *h;
    lt_ret_t ret;

    if ((pin == NULL) || (pin_len < SE_TROPIC_PIN_SIZE_MIN) ||
        (pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
        return SECURE_PEER_ERR;
    }
    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SECURE_PEER_ERR;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return SECURE_PEER_ERR;
    }
    ret = se_tropic_pin_check(h, pin, (uint8_t)pin_len, NULL, 0U, final_key);
    wc_ForceZero(final_key, sizeof(final_key));
    if (ret != LT_OK) {
        return SECURE_PEER_PIN_FAIL;
    }
    return SECURE_PEER_OK;
}

uint32_t CSME_NSE_API SECURE_PeerAdd_nsc_call(const SECURE_PeerAddArgs *args)
{
    const SECURE_PeerAddArgs *ns_args;
    SECURE_PeerAddArgs local;
    const uint8_t *ns_name;
    const uint8_t *ns_hash;
    const uint8_t *ns_pin;
    uint8_t local_pin[SE_TROPIC_PIN_SIZE_MAX];
    uint32_t st;

    ns_args = (const SECURE_PeerAddArgs *)ns_sanitize_in(args, (uint32_t)sizeof(*args));
    if (ns_args == NULL) {
        return SECURE_PEER_ERR;
    }
    (void)memcpy(&local, ns_args, sizeof(local));
    if ((local.name_len < 1U) || (local.name_len > SECURE_PEER_NAME_MAX)) {
        return SECURE_PEER_ERR;
    }
    if ((local.pin_len < SE_TROPIC_PIN_SIZE_MIN) || (local.pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
        return SECURE_PEER_ERR;
    }
    ns_name = (const uint8_t *)ns_sanitize_in(local.name, local.name_len);
    ns_hash = (const uint8_t *)ns_sanitize_in(local.hash48, SECURE_PEER_HASH_LEN);
    ns_pin = (const uint8_t *)ns_sanitize_in(local.pin, local.pin_len);
    if ((ns_name == NULL) || (ns_hash == NULL) || (ns_pin == NULL)) {
        return SECURE_PEER_ERR;
    }
    (void)memcpy(local_pin, ns_pin, local.pin_len);
    st = peer_require_pin(local_pin, local.pin_len);
    wc_ForceZero(local_pin, sizeof(local_pin));
    if (st != SECURE_PEER_OK) {
        return st;
    }
    return peer_lt_to_nsc(se_nv_peer_add(ns_name, (uint8_t)local.name_len, ns_hash));
}

uint32_t CSME_NSE_API SECURE_PeerRemove_nsc_call(const uint8_t *name, uint32_t name_len,
                                                 const uint8_t *pin, uint32_t pin_len)
{
    const uint8_t *ns_name;
    const uint8_t *ns_pin;
    uint8_t local_pin[SE_TROPIC_PIN_SIZE_MAX];
    uint32_t st;

    if ((name_len < 1U) || (name_len > SECURE_PEER_NAME_MAX)) {
        return SECURE_PEER_ERR;
    }
    if ((pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
        return SECURE_PEER_ERR;
    }
    ns_name = (const uint8_t *)ns_sanitize_in(name, name_len);
    ns_pin = (const uint8_t *)ns_sanitize_in(pin, pin_len);
    if ((ns_name == NULL) || (ns_pin == NULL)) {
        return SECURE_PEER_ERR;
    }
    (void)memcpy(local_pin, ns_pin, pin_len);
    st = peer_require_pin(local_pin, pin_len);
    wc_ForceZero(local_pin, sizeof(local_pin));
    if (st != SECURE_PEER_OK) {
        return st;
    }
    return peer_lt_to_nsc(se_nv_peer_remove(ns_name, (uint8_t)name_len));
}

uint32_t CSME_NSE_API SECURE_PeerCount_nsc_call(void)
{
    uint8_t n = 0U;
    lt_ret_t ret = se_nv_peer_count(&n);

    if (ret == SE_TROPIC_LT_TAMPERED) {
        return SECURE_TROPIC_TAMPERED;
    }
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
