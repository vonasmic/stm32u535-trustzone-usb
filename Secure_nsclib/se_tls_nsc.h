/**
 * @file    se_tls_nsc.h
 * @brief   Non-secure callable USB byte pipe + time for Secure TLS
 *
 * NonSecure owns command parsing and when TLS may run. PROVISION / ENCRYPT /
 * DECRYPT each carry a Unix timestamp (clock + arm). PIN is only on the TLS
 * channel. Secure owns TLS crypto and the wall clock used by wolfSSL.
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
/** Run one TLS step if a session is armed; returns IDLE when none is active. */
uint32_t CSME_NSE_API SECURE_UsbService_nsc_call(void);

/** Set Secure wall clock from host Unix UTC. Does not start TLS. */
uint32_t CSME_NSE_API SECURE_SetUnixTime_nsc_call(uint32_t unix_utc);
uint32_t CSME_NSE_API SECURE_GetUnixTime_nsc_call(void);

/**
 * Post-handshake TLS role, chosen by NonSecure USB commands (not on the wire).
 * Timestamp is applied as the wall clock, then the session is armed.
 * PROVISION verifies the SAE application CA. ENCRYPT / DECRYPT verify the
 * client CA; PIN + payload arrive over TLS (not on USB).
 */
#define SECURE_TLS_MODE_PROVISION 1u
#define SECURE_TLS_MODE_ENCRYPT   2u
#define SECURE_TLS_MODE_DECRYPT   3u

uint32_t CSME_NSE_API SECURE_TlsStart_nsc_call(uint32_t mode, uint32_t unix_utc);

/** Queue a DEBUG status line on the CDC TX ring (ASCII, no TLS). */
uint32_t CSME_NSE_API SECURE_UsbLog_nsc_call(const uint8_t *msg, uint32_t len);

/** TROPIC01 host commands Status codes match SE_TROPIC_* in Secure. */
#define SECURE_TROPIC_OK       0u
#define SECURE_TROPIC_ERR      1u
#define SECURE_TROPIC_SLOT_OCC 3u

#define SECURE_TROPIC_NOT_READY 4u
#define SECURE_TROPIC_TAMPERED  5u

uint32_t CSME_NSE_API SECURE_TropicPing_nsc_call(void);
uint32_t CSME_NSE_API SECURE_TropicInfo_nsc_call(void);
uint32_t CSME_NSE_API SECURE_TropicPub_nsc_call(uint8_t *out_xy64);
/**
 * Empty slot: generate. Occupied: PIN required, then erase+generate.
 * @param pin     unused on first generate; required to replace an occupied slot
 * @param pin_len 0 when unused; 4–8 for occupied replace
 */
uint32_t CSME_NSE_API SECURE_TropicKeygen_nsc_call(const uint8_t *pin, uint32_t pin_len);
uint32_t CSME_NSE_API SECURE_TropicSign_nsc_call(const uint8_t *hash32, uint8_t *rs64_out);

uint32_t CSME_NSE_API SECURE_TropicKemInit_nsc_call(const uint8_t *pin, uint32_t pin_len,
                                                    uint32_t confirm);
uint32_t CSME_NSE_API SECURE_TropicKemPub_nsc_call(void);

/** Write pairing key to TROPIC slot 1–3 and invalidate factory SH0. */
uint32_t CSME_NSE_API SECURE_TropicPairing_nsc_call(uint32_t slot);

#ifdef __cplusplus
}
#endif

#endif /* SE_TLS_NSC_H */
