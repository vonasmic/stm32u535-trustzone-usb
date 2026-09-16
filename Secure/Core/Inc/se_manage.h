/**
 * @file    se_manage.h
 * @brief   Owner-pinned TLS manage commands (no USB challenge)
 *
 * One request per MANAGE session. PIN-gated Tropic ops and identity changes
 * run here. ENCRYPT/DECRYPT stay on their own mTLS modes.
 */
#ifndef SE_MANAGE_H
#define SE_MANAGE_H

#include <stdint.h>
#include "se_creds.h"
#include "se_tropic_pin.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SE_MANAGE_KEM_INIT       1u
#define SE_MANAGE_KEYGEN         2u
#define SE_MANAGE_PEER_ADD       3u
#define SE_MANAGE_PEER_REMOVE    4u
#define SE_MANAGE_CREDS_SAE      5u
#define SE_MANAGE_CREDS_DEVICE   6u
#define SE_MANAGE_OWNER_REPLACE  7u

#define SE_MANAGE_OK             0u
#define SE_MANAGE_ERR            1u
#define SE_MANAGE_SLOT_OCC       3u
#define SE_MANAGE_NOT_READY      4u
#define SE_MANAGE_TAMPERED       5u
#define SE_MANAGE_PEER_EXISTS    6u
#define SE_MANAGE_PEER_NOT_FOUND 7u
#define SE_MANAGE_PEER_FULL      8u
#define SE_MANAGE_PIN_FAIL       9u
#define SE_MANAGE_BAD_CMD        10u
#define SE_MANAGE_PARSE          11u
#define SE_MANAGE_PW_FAIL        12u

/** PKCS#8 / SEC1 device SK; must fit SE_NV_SK_MAX. */
#define SE_MANAGE_KEY_DER_MAX 3000u
#define SE_MANAGE_BODY_MAX    (2u + SE_CREDS_DER_MAX + 2u + SE_MANAGE_KEY_DER_MAX)
#define SE_MANAGE_REQ_MAX \
    (1u + 1u + SE_TROPIC_PIN_SIZE_MAX + 2u + SE_MANAGE_BODY_MAX)
#define SE_MANAGE_MSG_MAX 80u
#define SE_MANAGE_RSP_MAX (1u + 2u + SE_MANAGE_MSG_MAX)

/**
 * Shared ingest BSS for USB OWNER SET and TLS MANAGE (never concurrent).
 * Sized for the first-wins USB blob (pw + SPKI + cert + key + SAE CA).
 */
#define SE_MANAGE_BUF_MAX 12288u

uint8_t *se_manage_buf(void);
uint32_t se_manage_buf_cap(void);
void se_manage_buf_wipe(void);

/**
 * Unsigned TLS request (no ML-DSA):
 *   u8 cmd | u8 pin_len | pin[pin_len] | u16le body_len | body[body_len]
 * @return needed size, 0 if more bytes required, 0xffffffff on parse fail
 */
uint32_t se_manage_req_need(const uint8_t *buf, uint32_t got);

/**
 * Execute one manage command. PIN is ASCII digits (same bytes as ENCRYPT OTP).
 * @return SE_MANAGE_* status; @p msg is a short ASCII detail (may be empty).
 */
uint32_t se_manage_apply(uint8_t cmd, const uint8_t *pin, uint8_t pin_len,
                         const uint8_t *body, uint16_t body_len, char *msg,
                         uint16_t msg_cap);

/** Parse a complete unsigned request buffer and call se_manage_apply. */
uint32_t se_manage_apply_buf(const uint8_t *buf, uint32_t len, char *msg,
                             uint16_t msg_cap);

/** Store device cert (creds page) and SK DER (NV). */
uint32_t se_manage_store_device(const uint8_t *cert, uint16_t cert_len,
                                const uint8_t *key, uint16_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* SE_MANAGE_H */
