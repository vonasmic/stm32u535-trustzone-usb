/**
 * @file    se_nv.h
 * @brief   MCU-only sealed NV: fill_id, dual OTP cursors, TIME floor, pairing key
 *
 * Tropic R-MEM / mcounter are not the source of truth under a broken ECC L3
 * session. This record lives in Secure flash (device) or process RAM (host model).
 */
#ifndef SE_NV_H
#define SE_NV_H

#include <stdint.h>
#include "libtropic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SE_NV_FILL_ID_LEN 32u
#define SE_NV_PAIRING_KEY_LEN 32u

#define SE_NV_FLAG_FILL    0x00000001u
#define SE_NV_FLAG_TIME    0x00000002u
#define SE_NV_FLAG_PAIRING 0x00000004u
#define SE_NV_FLAG_OTP     0x00000008u

/**
 * Project-local sentinel (not a libtropic enum value). Mapped to
 * SE_TROPIC_TAMPERED at the host-command boundary.
 */
#define SE_TROPIC_LT_TAMPERED ((lt_ret_t)200)

/** Which QKD half-cursor to read or advance. */
typedef enum {
    SE_NV_OTP_ENCRYPT = 0,
    SE_NV_OTP_DECRYPT = 1
} se_nv_otp_dir_t;

typedef struct {
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint16_t cursor_encrypt;
    uint16_t cursor_decrypt;
    uint16_t base_encrypt;
    uint16_t base_decrypt;
    uint32_t time_floor;
    uint32_t flags;
    uint8_t pairing_slot;
    uint8_t pairing_priv[SE_NV_PAIRING_KEY_LEN];
    uint8_t pairing_pub[SE_NV_PAIRING_KEY_LEN];
} se_nv_state_t;

/** Load sealed record. Empty/erased page => flags 0, LT_OK. Bad MAC => TAMPERED. */
lt_ret_t se_nv_load(se_nv_state_t *out);

/** Seal and persist the full record (erase-then-write). */
lt_ret_t se_nv_store(const se_nv_state_t *in);

/** Non-zero when a committed fill_id is present. */
int se_nv_have_fill(void);

/** Copy committed fill_id; LT_FAIL when no fill. */
lt_ret_t se_nv_get_fill_id(uint8_t out[SE_NV_FILL_ID_LEN]);

/**
 * MCU cursor for @p dir (physical pad index).
 * LT_FAIL when no fill or OTP halves are not armed.
 */
lt_ret_t se_nv_get_cursor(se_nv_otp_dir_t dir, uint16_t *cursor);

/**
 * Commit a new fill: set fill_id, clear OTP halves, keep TIME floor and pairing.
 * Clears any pending fill_id.
 */
lt_ret_t se_nv_commit_fill(const uint8_t fill_id[SE_NV_FILL_ID_LEN]);

/**
 * Arm both OTP halves: store bases and set both current cursors to those bases.
 * Requires a committed fill.
 */
lt_ret_t se_nv_arm_otp_cursors(uint16_t base_encrypt, uint16_t base_decrypt);

/** Copy armed encrypt/decrypt bases. LT_FAIL when OTP is not armed. */
lt_ret_t se_nv_get_otp_bases(uint16_t *base_encrypt, uint16_t *base_decrypt);

/** Update one direction's current cursor (must already have fill + armed OTP). */
lt_ret_t se_nv_set_cursor(se_nv_otp_dir_t dir, uint16_t cursor);

/** Persist TIME floor (sets SE_NV_FLAG_TIME). Keeps fill fields. */
lt_ret_t se_nv_set_time_floor(uint32_t unix_utc);

/** Persist host pairing key (slot 1–3). Keeps fill / TIME fields. */
lt_ret_t se_nv_set_pairing(uint8_t slot, const uint8_t priv[SE_NV_PAIRING_KEY_LEN],
                           const uint8_t pub[SE_NV_PAIRING_KEY_LEN]);

/** Copy committed pairing key; LT_FAIL when SE_NV_FLAG_PAIRING is unset. */
lt_ret_t se_nv_get_pairing(uint8_t *slot, uint8_t priv[SE_NV_PAIRING_KEY_LEN],
                           uint8_t pub[SE_NV_PAIRING_KEY_LEN]);

/**
 * Read TIME floor if present.
 * @param present 1 when SE_NV_FLAG_TIME is set
 */
lt_ret_t se_nv_get_time_floor(uint32_t *unix_utc, int *present);

/** RAM-only pending fill_id from TLS uplink (not yet committed). */
void se_nv_pending_fill_set(const uint8_t fill_id[SE_NV_FILL_ID_LEN]);

/** Copy and clear pending; returns 1 if a pending id was present. */
int se_nv_pending_fill_take(uint8_t fill_id[SE_NV_FILL_ID_LEN]);

void se_nv_pending_fill_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* SE_NV_H */
