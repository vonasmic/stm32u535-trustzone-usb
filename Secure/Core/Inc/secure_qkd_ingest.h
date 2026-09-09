/**
 * @file    secure_qkd_ingest.h
 * @brief   Streamed QKD key ingest (shared LV envelope, see secure_lv.h)
 *
 * Wire format is the versioned envelope from secure_lv.h: a version byte, an
 * item count, then length-prefixed items. The version is checked before any
 * item is read, so a schema mismatch is reported as SECURE_QKD_WRONG_VERSION rather
 * than surfacing later as a truncated or nonsensical stream.
 *
 * Chunks are parsed on the fly (no full-message buffer). Item 0 is the 1088-byte
 * ML-KEM ciphertext (kem_ct_write); item 1 is decrypt_half (1 byte, 0 or 1);
 * later items are finished pad images (qkd_store, logical = i-2). Zero-length
 * pad items are skipped positionally. SECURE_QKD_MAX_BYTES caps key payload.
 */
#ifndef SECURE_QKD_INGEST_H
#define SECURE_QKD_INGEST_H

#include <stdint.h>
#include "secure_lv.h"
#include "se_tropic_rmem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECURE_QKD_INGEST_CHUNK   0u
#define SECURE_QKD_INGEST_FINISH  1u
#define SECURE_QKD_INGEST_DISCARD 2u

#define SECURE_QKD_OK             0u
#define SECURE_QKD_ERR            1u
#define SECURE_QKD_OVERFLOW       2u
#define SECURE_QKD_PARSE          3u
/** Envelope version this build does not understand; distinct from a parse error. */
#define SECURE_QKD_WRONG_VERSION  4u
/** Tropic write failed (session, store, tamper, occupied slot). */
#define SECURE_QKD_STORE          5u

/**
 * Max sum of key bytes for a full fill: kem_ct + every pad slot image.
 * Payload only; LV framing is not counted.
 */
#define SECURE_QKD_MAX_BYTES \
    ((uint32_t)SE_TROPIC_KEM_CT_LEN + \
     ((uint32_t)SE_TROPIC_PAD_COUNT * (uint32_t)SE_TROPIC_RMEM_SLOT_MAX))

void secure_qkd_discard(void);
/** Non-zero when the full downlink envelope has been parsed (before FINISH). */
uint8_t secure_qkd_ready_to_finish(void);
uint32_t secure_qkd_ingest(const uint8_t *chunk, uint32_t len, uint32_t flags,
                           uint32_t *bytesOut);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_QKD_INGEST_H */
