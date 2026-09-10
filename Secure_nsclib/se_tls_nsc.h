/**
 * @file    se_tls_nsc.h
 * @brief   Non-secure callable USB byte pipe + time for Secure TLS
 *
 * NonSecure owns command parsing and when TLS may run. PROVISION / ENCRYPT /
 * DECRYPT / MANAGE each carry a Unix timestamp (clock + arm). PIN-gated and
 * identity-changing commands after first-wins OWNER SET run on MANAGE TLS
 * as unsigned application data (no USB challenge). ENCRYPT/DECRYPT stay mTLS.
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
 * PROVISION verifies the SAE application CA from FLASH_CREDS. ENCRYPT / DECRYPT
 * are mTLS and pin the peer leaf SPKI to the enrolled owner key. MANAGE pins
 * the same owner but presents no device client cert. One unsigned command
 * follows the MANAGE handshake.
 */
#define SECURE_TLS_MODE_PROVISION 1u
#define SECURE_TLS_MODE_ENCRYPT   2u
#define SECURE_TLS_MODE_DECRYPT   3u
#define SECURE_TLS_MODE_MANAGE    4u

uint32_t CSME_NSE_API SECURE_TlsStart_nsc_call(uint32_t mode, uint32_t unix_utc);

/** First-wins USB OWNER SET: wait for an unsigned binary blob. */
uint32_t CSME_NSE_API SECURE_OwnerBegin_nsc_call(void);

/** Queue a framed DEBUG:<text>:DEBUG status line on the CDC TX ring (ASCII, no TLS). */
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
uint32_t CSME_NSE_API SECURE_TropicClientHash_nsc_call(void);
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
/** Remaining OTP bytes for encrypt and decrypt (no PIN). */
uint32_t CSME_NSE_API SECURE_TropicOtpLeft_nsc_call(void);

/** Write pairing key to TROPIC slot 1–3 and invalidate factory SH0.
 *  On OK, @p out64 is priv[32] || pub[32] for host backup. */
uint32_t CSME_NSE_API SECURE_TropicPairing_nsc_call(uint32_t slot, uint8_t *out64);
/** Restore pairing priv||pub (64 B) into MCU NV; no Tropic write. */
uint32_t CSME_NSE_API SECURE_TropicPairingLoad_nsc_call(uint32_t slot, const uint8_t *in64);

/**
 * PEER NV commands. ADD/REMOVE require a Tropic PIN. OK/ERR match Tropic;
 * EXISTS/NOT_FOUND/FULL/PIN_FAIL are PEER-only (do not reuse SLOT_OCC /
 * NOT_READY / TAMPERED).
 */
#define SECURE_PEER_OK        0u
#define SECURE_PEER_ERR       1u
#define SECURE_PEER_EXISTS    6u
#define SECURE_PEER_NOT_FOUND 7u
#define SECURE_PEER_FULL      8u
#define SECURE_PEER_PIN_FAIL  9u

#define SECURE_PEER_NAME_MAX 16u
#define SECURE_PEER_MAX      8u
/** SHA-384 of the peer SPKI (mirrors SE_NV_PEER_HASH_LEN). */
#define SECURE_PEER_HASH_LEN 48u

/**
 * NSC entries may only pass arguments in r0–r3. Five scalars would put
 * pin_len on the stack, which GCC rejects for cmse_nonsecure_entry.
 */
typedef struct {
    const uint8_t *name;
    uint32_t name_len;
    const uint8_t *hash48;
    const uint8_t *pin;
    uint32_t pin_len;
} SECURE_PeerAddArgs;

uint32_t CSME_NSE_API SECURE_PeerAdd_nsc_call(const SECURE_PeerAddArgs *args);
uint32_t CSME_NSE_API SECURE_PeerRemove_nsc_call(const uint8_t *name, uint32_t name_len,
                                                 const uint8_t *pin, uint32_t pin_len);
/** Occupied count 0..8 on success; >8 means load/store failed (see TAMPERED). */
uint32_t CSME_NSE_API SECURE_PeerCount_nsc_call(void);
/**
 * One occupied slot. @p name_len_inout in: buffer size; out: actual name length.
 * NSC payload stays within SECURE_USB_PKT_MAX.
 */
uint32_t CSME_NSE_API SECURE_PeerGet_nsc_call(uint32_t index, uint8_t *name_out,
                                              uint32_t *name_len_inout, uint8_t *hash48_out);

#ifdef __cplusplus
}
#endif

#endif /* SE_TLS_NSC_H */
