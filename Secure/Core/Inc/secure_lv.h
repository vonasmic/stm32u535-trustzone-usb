/**
 * @file    secure_lv.h
 * @brief   Shared length-value envelope for the SAE downlink and session uplink
 *
 * Wire format (little-endian), identical framing in both directions:
 *
 *   u8   version
 *   u16  count
 *   repeat count times:
 *     u16 len
 *     u8  value[len]
 *
 * Read version first and stop on a value this build does not understand. An
 * unknown layout parsed as an older version puts every later field at the wrong
 * offset, which fails silently instead of loudly. Absent items are sent as
 * zero-length items, never omitted, because items are identified by position
 * rather than by tag.
 *
 * Versions are independent per message type: a new uplink item does not change
 * the downlink schema. Bump the envelope you change.
 */
#ifndef SECURE_LV_H
#define SECURE_LV_H

#include <stdint.h>
#include <string.h>
#include "se_le.h"
#include "secure_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECURE_LV_DOWNLINK_VERSION 2u

/** Session uplink after TLS; includes R-MEM pad geometry, fill_id, and ML-KEM PK. */
#define SECURE_LV_UPLINK_VERSION   3u

/**
 * OTP pad stream (not an LV envelope). ENCRYPT TLS body after PIN is
 *   u32 msg_len LE | plaintext[msg_len]
 * ENCRYPT reply and DECRYPT TLS body after PIN:
 *   u32 n_pads LE | repeat: u16 logical_slot LE | u16 chunk_len LE | chunk
 * DECRYPT reply:
 *   u32 n_pads LE | repeat: u16 chunk_len LE | chunk
 *
 * Uplink v3 items, in order: session signature (64 B), TROPIC01 P-256 public
 * key (64 B), client hash (32 B), R-MEM slot size (u16 LE), pad slot count
 * (u16 LE), pending fill_id (32 B), ML-KEM-768 public key (1184 B), then
 * alternating peer hash (32 B) / peer name from MCU NV (PEER ADD).
 * count = SECURE_LV_UPLINK_FIXED_ITEMS + 2 * se_nv_peer_count().
 *
 * Downlink v2 items: kem_ct (1088 B), decrypt_half (1 B, 0 or 1), then pad
 * images (logical index = item index - 2).
 */
#define SECURE_LV_UPLINK_FIXED_ITEMS 7u

/** Write version and little-endian item count. */
static inline void secure_lv_put_header(uint8_t *buf, uint32_t *off, uint8_t version,
                                        uint16_t count)
{
    buf[(*off)++] = version;
    se_append_u16le(buf, off, count);
}

/** One LV item: 2-byte LE length then the value. @p val may be NULL when @p len is 0. */
static inline void secure_lv_put_item(uint8_t *buf, uint32_t *off, const uint8_t *val,
                                      uint16_t len)
{
    se_append_u16le(buf, off, len);
    if (len > 0U) {
        (void)memcpy(buf + *off, val, len);
        *off += len;
    }
}

static inline int secure_lv_write_u16(uint16_t value, secure_stream_write_fn write, void *ctx)
{
    uint8_t le[2];

    se_put_u16le(le, value);
    return write(le, (uint32_t)sizeof(le), ctx);
}

/** One LV item streamed through @p write: 2-byte LE length then the value. */
static inline int secure_lv_write_item(const uint8_t *value, uint16_t len,
                                       secure_stream_write_fn write, void *ctx)
{
    if (secure_lv_write_u16(len, write, ctx) != 0) {
        return -1;
    }
    if (len == 0U) {
        return 0;
    }
    return write(value, len, ctx);
}

#ifdef __cplusplus
}
#endif

#endif /* SECURE_LV_H */
