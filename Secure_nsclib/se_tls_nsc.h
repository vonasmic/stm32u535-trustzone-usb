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

/** Queue a plain ASCII line on the CDC TX ring (HELP / PING / INFO). Errors use {@code failed}. */
uint32_t CSME_NSE_API SECURE_UsbLog_nsc_call(const uint8_t *msg, uint32_t len);
/** Dump frame: {@code 0xB1 | status | u16le len | body}. Status 0 ok, 1 err, 2 empty, 3 refused. */
uint32_t CSME_NSE_API SECURE_UsbDump_nsc_call(uint8_t status, const uint8_t *body, uint32_t len);

/**
 * USB-facing Tropic results. Failures are collapsed to ERR so NonSecure cannot
 * tell Tropic / TLS / auth / tamper apart. Occupancy uses DUMP_EMPTY on PUB /
 * KEM PUB (not a failure type).
 */
#define SECURE_TROPIC_OK       0u
#define SECURE_TROPIC_ERR      1u

#define SECURE_USB_DUMP_MAGIC    0xB1u
#define SECURE_USB_DUMP_OK       0u
#define SECURE_USB_DUMP_ERR      1u
#define SECURE_USB_DUMP_EMPTY    2u
#define SECURE_USB_DUMP_REFUSED  3u
#define SECURE_USB_DUMP_BODY_MAX 1312u
#define SE_TROPIC_MLKEM_PK_LEN   1184u

uint32_t CSME_NSE_API SECURE_TropicPing_nsc_call(void);
uint32_t CSME_NSE_API SECURE_TropicInfo_nsc_call(void);
uint32_t CSME_NSE_API SECURE_TropicPub_nsc_call(uint8_t *out_xy64);
/** SHA-384 client hash, 48 bytes. */
uint32_t CSME_NSE_API SECURE_TropicClientHash_nsc_call(uint8_t *out48);
/** Raw ML-DSA-44 pub. @p len_inout in: cap; out: actual length. */
uint32_t CSME_NSE_API SECURE_ClientCsr_nsc_call(uint8_t *out, uint32_t *len_inout);
/** ML-KEM-768 pk. @p len_inout in: cap; out: actual length. */
uint32_t CSME_NSE_API SECURE_TropicKemPub_nsc_call(uint8_t *out, uint32_t *len_inout);
/** Four u32le: enc left, enc cap, dec left, dec cap. */
uint32_t CSME_NSE_API SECURE_TropicOtpLeft_nsc_call(uint32_t out_quotas[4]);

/**
 * PEER LIST is the only PEER path on NSC. ADD/REMOVE mutate through MANAGE TLS.
 * NOT_FOUND is end-of-list occupancy while walking indexes, not a Tropic failure.
 */
#define SECURE_PEER_OK        0u
#define SECURE_PEER_ERR       1u
#define SECURE_PEER_NOT_FOUND 7u

#define SECURE_PEER_NAME_MAX 16u
#define SECURE_PEER_MAX      8u
/** SHA-384 of the peer SPKI (mirrors SE_NV_PEER_HASH_LEN). */
#define SECURE_PEER_HASH_LEN 48u

/** Occupied count 0..8 on success; >8 means the table could not be read. */
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
