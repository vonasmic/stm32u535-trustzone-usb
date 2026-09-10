/**
 * @file    se_nv.h
 * @brief   MCU-only sealed NV: fill_id, dual OTP cursors, TIME floor, pairing, peers
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
#define SE_NV_PEER_MAX 8u
#define SE_NV_PEER_NAME_MAX 16u
/** SHA-384 of the peer SPKI. */
#define SE_NV_PEER_HASH_LEN 48u

#define SE_NV_FLAG_FILL    0x00000001u
#define SE_NV_FLAG_TIME    0x00000002u
#define SE_NV_FLAG_PAIRING 0x00000004u
#define SE_NV_FLAG_OTP     0x00000008u

#define SE_NV_OWNER_SPKI_MAX 1312u
#define SE_NV_PW_HASH_LEN    48u
#define SE_NV_WRAP_MAX       3072u
#define SE_NV_MLKEM_MAX      1184u

/**
 * Project-local sentinel (not a libtropic enum value). Mapped to
 * SE_TROPIC_TAMPERED at the host-command boundary.
 */
#define SE_TROPIC_LT_TAMPERED ((lt_ret_t)200)
#define SE_NV_PEER_EXISTS     ((lt_ret_t)201)
#define SE_NV_PEER_NOT_FOUND  ((lt_ret_t)202)
#define SE_NV_PEER_FULL       ((lt_ret_t)203)
/** Encrypt/decrypt request needs more pads than this half still has. */
#define SE_TROPIC_LT_OTP_EXHAUSTED ((lt_ret_t)204)

/** Which QKD half-cursor to read or advance. */
typedef enum {
    SE_NV_OTP_ENCRYPT = 0,
    SE_NV_OTP_DECRYPT = 1
} se_nv_otp_dir_t;

typedef struct {
    uint8_t name_len; /* 0 = empty slot */
    uint8_t name[SE_NV_PEER_NAME_MAX];
    uint8_t hash[SE_NV_PEER_HASH_LEN];
} se_nv_peer_t;

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
    uint8_t peer_count; /* 0..SE_NV_PEER_MAX; occupied slots are compact 0..count-1 */
    se_nv_peer_t peers[SE_NV_PEER_MAX];
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

/** Drop pairing flag and zero pairing keys. Keeps fill / TIME / owner / OTP. */
lt_ret_t se_nv_clear_pairing(void);

/**
 * Append a nickname+hash peer. Nickname is unique (case-sensitive).
 * @return LT_OK, SE_NV_PEER_EXISTS, SE_NV_PEER_FULL, LT_PARAM_ERR, or tamper
 */
lt_ret_t se_nv_peer_add(const uint8_t *name, uint8_t name_len,
                        const uint8_t hash48[SE_NV_PEER_HASH_LEN]);

/** Remove by nickname. @return LT_OK, SE_NV_PEER_NOT_FOUND, or tamper */
lt_ret_t se_nv_peer_remove(const uint8_t *name, uint8_t name_len);

/** Occupied peer count (0..8). */
lt_ret_t se_nv_peer_count(uint8_t *count);

/**
 * Copy occupied slot @p index (0 .. count-1).
 * @p name_len in: capacity of @p name; out: actual length.
 */
lt_ret_t se_nv_peer_get(uint8_t index, uint8_t *name, uint8_t *name_len,
                        uint8_t hash48[SE_NV_PEER_HASH_LEN]);

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

int se_nv_has_owner(void);
int se_nv_has_wrap(void);
int se_nv_has_mlkem(void);
lt_ret_t se_nv_get_owner_spki(uint8_t *out, uint16_t *len);
lt_ret_t se_nv_set_owner(const uint8_t *spki, uint16_t spki_len,
                         const uint8_t pw_hash[SE_NV_PW_HASH_LEN]);
lt_ret_t se_nv_get_pw_hash(uint8_t out[SE_NV_PW_HASH_LEN]);
lt_ret_t se_nv_get_wrap(uint8_t *out, uint16_t *len, uint16_t cap);
lt_ret_t se_nv_set_wrap(const uint8_t *wrap, uint16_t len);
lt_ret_t se_nv_get_mlkem_pk(uint8_t *out, uint16_t *len);
lt_ret_t se_nv_set_mlkem_pk(const uint8_t *pk, uint16_t len);

/** Clear fill/OTP/peers/TIME/owner/wrap/mlkem; keep pairing + dwk. */
lt_ret_t se_nv_clear_except_pairing(void);

#ifdef __cplusplus
}
#endif

#endif /* SE_NV_H */
