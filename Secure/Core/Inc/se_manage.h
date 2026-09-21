/**
 * @file    se_manage.h
 * @brief   Owner-pinned TLS manage commands (no USB challenge)
 *
 * One request per MANAGE session. PIN-gated Tropic ops and identity changes
 * run here. ENCRYPT/DECRYPT stay on their own mTLS modes.
 *
 * Wire codec (need/parse/reply) matches Java fel.cvut.se.SeManage.
 * USB OWNER SET ingest stays in se_auth.c; TLS apply stays below.
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
#define SE_MANAGE_PAIRING        8u

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

/** Device cert DER; must match the on-chip ML-DSA public key. */
#define SE_MANAGE_KEY_DER_MAX 3000u
#define SE_MANAGE_BODY_MAX    (2u + SE_CREDS_DER_MAX)
#define SE_MANAGE_REQ_MAX \
    (1u + 1u + SE_TROPIC_PIN_SIZE_MAX + 2u + SE_MANAGE_BODY_MAX)
#define SE_MANAGE_MSG_MAX 80u
#define SE_MANAGE_RSP_MAX (1u + 2u + SE_MANAGE_MSG_MAX)

/**
 * Shared ingest BSS for USB OWNER SET and TLS MANAGE (never concurrent).
 * Sized for OWNER SET (pw + SPKI + SAE CA) and MANAGE bodies.
 */
#define SE_MANAGE_BUF_MAX 12288u

uint8_t *se_manage_buf(void);
uint32_t se_manage_buf_cap(void);
void se_manage_buf_wipe(void);

#define SE_FRAME_NEED_MORE 0
#define SE_FRAME_COMPLETE  1

/**
 * Append @p n bytes and evaluate @p need against the shared ingest buffer.
 * @return {@code SE_FRAME_COMPLETE} when got equals need, {@code SE_FRAME_NEED_MORE},
 *         or -1 on overflow / parse fail / extra bytes.
 */
int se_manage_accum(uint32_t *got, const uint8_t *chunk, uint32_t n,
                    uint32_t (*need)(const uint8_t *buf, uint32_t got));

/** Same as {@code se_manage_accum} after bytes were already copied into the buffer. */
int se_manage_frame_ready(uint32_t got, uint32_t (*need)(const uint8_t *buf, uint32_t got));

/**
 * Unsigned TLS request (no ML-DSA):
 *   u8 cmd | u8 pin_len | pin[pin_len] | u16le body_len | body[body_len]
 * @return needed size, 0 if more bytes required, 0xffffffff on parse fail
 */
uint32_t se_manage_req_need(const uint8_t *buf, uint32_t got);

/**
 * OWNER SET USB blob (same incremental contract as se_manage_req_need):
 *   u8 pw_len | pw | u16le spki_len | spki | u16le ca_len | ca
 * ca length may be 0.
 */
uint32_t se_manage_owner_set_need(const uint8_t *buf, uint32_t got);

/**
 * Split a complete OWNER SET blob. Pointers alias @p buf.
 * @return SE_MANAGE_OK or SE_MANAGE_PARSE
 */
uint32_t se_manage_owner_set_parse(const uint8_t *buf, uint32_t len,
                                   const uint8_t **pw, uint8_t *pw_len,
                                   const uint8_t **spki, uint16_t *spki_len,
                                   const uint8_t **ca, uint16_t *ca_len);

/**
 * MANAGE reply: u8 status | u16le msg_len | msg (ASCII, no NUL on the wire).
 * @return encoded length, or 0 if @p cap is too small
 */
uint16_t se_manage_rsp_encode(uint8_t *out, uint16_t cap, uint8_t status,
                              const char *msg);

/**
 * Execute one manage command. PIN is printable ASCII (same bytes as ENCRYPT OTP).
 * @return SE_MANAGE_* status; @p msg is a short ASCII detail (may be empty).
 */
uint32_t se_manage_apply(uint8_t cmd, const uint8_t *pin, uint8_t pin_len,
                         const uint8_t *body, uint16_t body_len, char *msg,
                         uint16_t msg_cap);

/** Parse a complete unsigned request buffer and call se_manage_apply. */
uint32_t se_manage_apply_buf(const uint8_t *buf, uint32_t len, char *msg,
                             uint16_t msg_cap);

/** Store device cert (creds page) after it matches the on-chip ML-DSA public key. */
uint32_t se_manage_store_device_cert(const uint8_t *cert, uint16_t cert_len);

#ifdef __cplusplus
}
#endif

#endif /* SE_MANAGE_H */
