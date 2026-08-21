/**
 * @file    se_tls_nsc.h
 * @brief   Non-secure callable USB byte pipe + time for Secure TLS
 *
 * NonSecure owns command parsing and when TLS may run. Secure owns TLS crypto
 * and the wall clock used by wolfSSL.
 */
#ifndef SE_TLS_NSC_H
#define SE_TLS_NSC_H

#include <stdint.h>
#include "se_nsc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECURE_USB_PKT_MAX 64u

#define SECURE_USB_OK        0u
#define SECURE_USB_BUSY      1u
#define SECURE_USB_LINK_DOWN 2u
#define SECURE_USB_ERR       3u
/** No active TLS session — NonSecure is in command mode. */
#define SECURE_USB_IDLE      4u

#define SECURE_USB_EVT_ACTIVATE   0u
#define SECURE_USB_EVT_DEACTIVATE 1u
#define SECURE_USB_EVT_DTR_ON     2u
#define SECURE_USB_EVT_DTR_OFF    3u

uint32_t CSME_NSE_API SECURE_UsbRx_nsc_call(const uint8_t *buf, uint32_t len);
uint32_t CSME_NSE_API SECURE_UsbTx_nsc_call(uint8_t *buf, uint32_t max, uint32_t *out_len);
uint32_t CSME_NSE_API SECURE_UsbEvent_nsc_call(uint32_t event);
/** Run one TLS step if armed (time synced); returns IDLE when no session. */
uint32_t CSME_NSE_API SECURE_UsbService_nsc_call(void);

/** Set Secure wall clock from host Unix UTC; enables TLS start on next Service. */
uint32_t CSME_NSE_API SECURE_SetUnixTime_nsc_call(uint32_t unix_utc);
uint32_t CSME_NSE_API SECURE_GetUnixTime_nsc_call(void);

/** Queue a DEBUG status line on the CDC TX ring (ASCII, no TLS). */
uint32_t CSME_NSE_API SECURE_UsbLog_nsc_call(const uint8_t *msg, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* SE_TLS_NSC_H */
