/**
 * @file    se_tropic_rmem.h
 * @brief   R-MEM slot map, shared AEAD frame, PIN-gated OTP consume
 *
 * All encrypted payloads share one wire format (se_tropic_encrypt_storage_blob /
 * se_tropic_decrypt_storage_blob):
 *   version(1) || nonce(12) || ct || tag(16)
 *
 * Three keys/AAD bindings share that frame and are easy to confuse:
 *
 *   MCU sealed      Key from secure_dwk (MCU flash); binding = slot LE.
 *                   PIN NVM / kem_ct bound to this board only. MCU NV is not AEAD'd.
 *   kem_ct          Same device key; binding = slot LE || fill_id.
 *                   Bound to the MCU-committed fill so old ct cannot decrypt.
 *   KEK wrap        Key from HKDF-SHA384(PIN final_key 48 B, salt=device key);
 *                   binding = seed label. Slot 510. Needs the PIN path and this MCU.
 *   Pad image       Per-slot key from ML-KEM ss + fill_id; binding = slot LE.
 *                   SAE-sealed keystream pads; write via qkd_store, decrypt on consume.
 *
 * Keystream slots carry the pad image only: the device binding would add a second
 * nonce and tag (29 B/slot) on top of material that is already unreadable
 * without the PIN and MCU device key.
 *
 * Anti-rollback (fill_id, dual OTP cursors) lives in MCU NV (se_nv), not on Tropic.
 */
#ifndef SE_TROPIC_RMEM_H
#define SE_TROPIC_RMEM_H

#include <stdint.h>
#include "libtropic.h"
#include "se_le.h"
#include "se_nv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- slot map -------------------------------------------------------- */

/** First keystream slot. */
#ifndef SE_TROPIC_QKD_SLOT_BASE
#define SE_TROPIC_QKD_SLOT_BASE 0u
#endif

/**
 * Last keystream slot. Slot 510 holds the KEK-wrapped ML-KEM seed and slot 511
 * the MAC-and-Destroy PIN NVM, so neither is available for pad.
 */
#ifndef SE_TROPIC_QKD_SLOT_LAST
#define SE_TROPIC_QKD_SLOT_LAST 509u
#endif

/** PIN+MCU KEK-wrapped 64-byte ML-KEM generation seed. */
#ifndef SE_TROPIC_MLKEM_SEED_SLOT
#define SE_TROPIC_MLKEM_SEED_SLOT 510u
#endif

/** Tropic mcounter: encrypt cursor (first or second half). */
#ifndef SE_TROPIC_QKD_MCOUNTER_ENCRYPT
#define SE_TROPIC_QKD_MCOUNTER_ENCRYPT TR01_MCOUNTER_INDEX_0
#endif

/** Tropic mcounter: decrypt cursor (the other half). */
#ifndef SE_TROPIC_QKD_MCOUNTER_DECRYPT
#define SE_TROPIC_QKD_MCOUNTER_DECRYPT TR01_MCOUNTER_INDEX_1
#endif

/** Mcounter value meaning cursor is unset or exhausted (not a keystream slot). */
#define SE_TROPIC_QKD_CURSOR_END TR01_MCOUNTER_VALUE_MAX

/* ---- slot geometry --------------------------------------------------- */

#define SE_TROPIC_RMEM_AES_KEY_LEN   32u
#define SE_TROPIC_RMEM_NONCE_LEN     12u
#define SE_TROPIC_RMEM_TAG_LEN       16u
#define SE_TROPIC_RMEM_VER           1u
#define SE_TROPIC_RMEM_OVERHEAD      (1u + SE_TROPIC_RMEM_NONCE_LEN + SE_TROPIC_RMEM_TAG_LEN)

/**
 * Largest R-MEM user data slot across TROPIC01 Application FW versions, used to
 * size buffers. libtropic deliberately removed R_MEM_DATA_SIZE_MAX because the
 * real ceiling differs per FW (444 below FW 2.0.0, 475 from 2.0.0), and reports
 * the chip's own figure in h->tr01_attrs.r_mem_udata_slot_size_max. Enforce
 * limits against se_tropic_get_rmem_slot_plaintext_max_size(h), not against this constant.
 */
#define SE_TROPIC_RMEM_SLOT_MAX      475u
#define SE_TROPIC_RMEM_PLAIN_MAX     (SE_TROPIC_RMEM_SLOT_MAX - SE_TROPIC_RMEM_OVERHEAD)
#define SE_TROPIC_RMEM_BLOB_MAX      SE_TROPIC_RMEM_SLOT_MAX
/** Generic storage-blob plaintext cap (R-MEM slot minus AEAD overhead). */
#define SE_TROPIC_STORAGE_PLAIN_MAX  8096u

/**
 * One SAE encapsulation covers the whole QKD fill: slots 0..2 hold the 1088 B
 * ML-KEM ciphertext; slots 3..509 are self-contained one-time pads under the
 * single shared secret. Per-slot AEAD keys keep each pad independently openable.
 */
#define SE_TROPIC_KEM_CT_BASE        0u
#define SE_TROPIC_KEM_CT_SLOTS       3u
#define SE_TROPIC_KEM_CT_LEN         1088u
#define SE_TROPIC_MLKEM_SS_LEN       32u
#define SE_TROPIC_PAD_FIRST          ((uint16_t)(SE_TROPIC_KEM_CT_BASE + SE_TROPIC_KEM_CT_SLOTS))

/** How many SAE pad indices exist (logical 0 .. count-1). */
#define SE_TROPIC_PAD_COUNT \
    ((uint16_t)(SE_TROPIC_QKD_SLOT_LAST - SE_TROPIC_PAD_FIRST + 1u))

/** First-half pad count; remainder (if odd) belongs to the second half. */
#define SE_TROPIC_PAD_HALF ((uint16_t)(SE_TROPIC_PAD_COUNT / 2u))

/** Max bytes written to one R-MEM user-data slot (encrypted blob capacity). */
uint16_t se_tropic_get_rmem_slot_max_size(const lt_handle_t *h);

/** Max plaintext bytes that fit in one slot after storage-blob overhead. */
uint16_t se_tropic_get_rmem_slot_plaintext_max_size(const lt_handle_t *h);

/** Non-zero when the physical R-MEM index is a keystream slot. */
int se_tropic_slot_is_keystream(uint16_t phys);

/**
 * SAE pad slot_index (0 = first pad) <-> physical R-MEM slot.
 * STORE, HKDF, and pad binding use slot_index; the cursor stays physical.
 */
lt_ret_t se_tropic_get_slot_index_from_phys(uint16_t phys, uint16_t *slot_index);
lt_ret_t se_tropic_get_phys_from_slot_index(uint16_t slot_index, uint16_t *phys);

/* ---- storage blob format (no chip I/O) -------------------------------- */

/** Write @p slot as little-endian bytes into a 2-byte storage binding. */
static inline void write_storage_slot_binding(uint16_t slot, uint8_t out[2])
{
    se_put_u16le(out, slot);
}

/**
 * AES-GCM encrypt @p plain into a storage blob: version||nonce||ciphertext||tag.
 * Used for R-MEM slot images and other device-bound blobs (e.g. MCU NV).
 * @param blob_len in: capacity, out: blob length
 */
lt_ret_t se_tropic_encrypt_storage_blob(const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                        const uint8_t *binding, uint16_t binding_len,
                                        const uint8_t *plain, uint16_t plain_len,
                                        const uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN],
                                        uint8_t *blob, uint16_t *blob_len);

/** AES-GCM decrypt a storage blob back to @p plain under @p key and @p binding. */
lt_ret_t se_tropic_decrypt_storage_blob(const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                          const uint8_t *binding, uint16_t binding_len,
                                          const uint8_t *blob, uint16_t blob_len,
                                          uint8_t *plain, uint16_t plain_max,
                                          uint16_t *plain_len);

/* ---- R-MEM slot I/O -------------------------------------------------- */

/**
 * Encrypt @p data and write the blob to an R-MEM slot (erase first, random nonce).
 * Used for kem_ct chunks and KEK-wrapped ML-KEM seed.
 */
lt_ret_t se_tropic_encrypt_and_write_to_rmem(lt_handle_t *h, uint16_t slot,
                                              const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                              const uint8_t *binding, uint16_t binding_len,
                                              const uint8_t *data, uint16_t len);

/** Read an R-MEM slot blob and decrypt it under @p key with caller binding. */
lt_ret_t se_tropic_read_and_decrypt_from_rmem(lt_handle_t *h, uint16_t slot,
                                                const uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN],
                                                const uint8_t *binding, uint16_t binding_len,
                                                uint8_t *out, uint16_t out_max,
                                                uint16_t *out_len);

/**
 * Encrypt @p data with the MCU device key (binding = slot LE), erase R-MEM slot, write.
 * For PIN NVM and other MCU-bound records — not SAE keystream pads (see qkd_store).
 */
lt_ret_t se_tropic_encrypt_and_write_mcu_sealed_to_rmem(lt_handle_t *h, uint16_t slot,
                                                          const uint8_t *data, uint16_t len);

/**
 * Read MCU-sealed data from R-MEM and decrypt (binding = slot LE).
 * @param out_len  plaintext length on success
 */
lt_ret_t se_tropic_read_and_decrypt_mcu_sealed_from_rmem(lt_handle_t *h, uint16_t slot,
                                                           uint8_t *out, uint16_t out_max,
                                                           uint16_t *out_len);

/* ---- keystream slots ------------------------------------------------- */

/**
 * Derive the per-pad AES key:
 * HKDF-SHA384(ss, "SE_tropic_qkd_slot_v3" || fill_id || slot_index LE).
 * @p slot_index is the SAE pad index (0 = first pad), not the R-MEM address.
 */
lt_ret_t se_tropic_get_pad_encryption_key(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                                          const uint8_t fill_id[SE_NV_FILL_ID_LEN],
                                          uint16_t slot_index,
                                          uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN]);

/**
 * Erase every QKD R-MEM slot (0..509). Leaves PIN NVM (511) and the wrapped
 * ML-KEM seed (510) alone. Does not arm OTP cursors.
 * Called from kem_ct_write after committing fill_id to MCU NV.
 */
lt_ret_t se_tropic_qkd_provision_begin(lt_handle_t *h);

/**
 * Split the pad pool 50/50 and arm both Tropic mcounters plus MCU NV cursors.
 * @p decrypt_half 0 = first half decrypt / second encrypt; 1 = swapped.
 */
lt_ret_t se_tropic_qkd_arm_halves(lt_handle_t *h, uint8_t decrypt_half);

/**
 * Store one finished slot image into an empty pad (no device-side
 * re-encryption). @p slot is the SAE index (0 = first pad). Requires a
 * committed fill in MCU NV; does not wipe. Refuses rewrite of an occupied slot.
 */
lt_ret_t se_tropic_qkd_store(lt_handle_t *h, uint16_t slot, const uint8_t *image,
                             uint16_t image_len);

/* ---- kem_ct header --------------------------------------------------- */

/**
 * Write the fill's 1088-byte ML-KEM ciphertext across slots 0..2.
 * Commits fill_id (pending TLS id or fresh random), wipes QKD slots.
 * Does not arm OTP cursors — call se_tropic_qkd_arm_halves after decrypt_half.
 */
lt_ret_t se_tropic_kem_ct_write(lt_handle_t *h, const uint8_t ct[SE_TROPIC_KEM_CT_LEN]);

/** Read the fill's 1088-byte ML-KEM ciphertext (binding tied to MCU fill_id). */
lt_ret_t se_tropic_kem_ct_read(lt_handle_t *h, uint8_t ct[SE_TROPIC_KEM_CT_LEN]);

/* ---- consumption cursor ---------------------------------------------- */

/**
 * Arm Tropic mcounter for @p dir at @p start_slot (must be a keystream slot).
 */
lt_ret_t se_tropic_qkd_cursor_init(lt_handle_t *h, se_nv_otp_dir_t dir, uint16_t start_slot);

/**
 * Read next keystream slot for @p dir: MCU NV is authoritative; Tropic
 * mcounter must match or SE_TROPIC_LT_TAMPERED is returned.
 */
lt_ret_t se_tropic_qkd_cursor_get(lt_handle_t *h, se_nv_otp_dir_t dir, uint32_t *next_slot);

/**
 * Advance Tropic then MCU cursor for @p dir by one. Returns LT_FAIL when that
 * half is exhausted.
 */
lt_ret_t se_tropic_qkd_cursor_advance(lt_handle_t *h, se_nv_otp_dir_t dir);

/* ---- OTP consume ----------------------------------------------------- */

/**
 * One keystream slot at the MCU/Tropic cursor for @p dir: match cursors, read
 * pad, advance Tropic then MCU by one, erase the physical slot, XOR @p msg
 * into @p out. @p len must be <= plain_max. Caller supplies an opened ML-KEM
 * shared secret.
 */
lt_ret_t se_tropic_OTP_xor_consume(lt_handle_t *h, se_nv_otp_dir_t dir,
                               const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                               const uint8_t *msg, uint16_t len, uint8_t *out);

/**
 * PIN-unlock and ML-KEM-decapsulate for pad XOR. Refuses with
 * SE_TROPIC_LT_OTP_EXHAUSTED if the pad count does not fit in @p dir's
 * remaining half (no erase yet).
 * Counting follows @p dir, not which argument is non-zero:
 * ENCRYPT uses @p msg_len (plaintext bytes); @p n_pads is ignored.
 * DECRYPT uses @p n_pads (encrypt-reply pad count); @p msg_len is ignored.
 */
lt_ret_t se_tropic_otp_xor_open(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                    const uint8_t *add, uint8_t add_len, se_nv_otp_dir_t dir,
                                    uint32_t msg_len, uint32_t n_pads);

uint16_t se_tropic_otp_xor_pad_max(void);
uint32_t se_tropic_otp_xor_bytes_left(void);
uint32_t se_tropic_otp_xor_pads_needed(void);

/**
 * Remaining and half-capacity keystream bytes for @p dir. Unused pads in that
 * half times slot plaintext max. Unprovisioned OTP (no fill/cursors) reports
 * remaining 0 and the default half capacity. Exhausted cursor reports 0 left.
 * Does not need PIN. Either @p left_out or @p cap_out may be NULL.
 */
lt_ret_t se_tropic_otp_bytes_quota(lt_handle_t *h, se_nv_otp_dir_t dir,
                                   uint32_t *left_out, uint32_t *cap_out);

/** Remaining keystream bytes for @p dir (quota left only). */
lt_ret_t se_tropic_otp_bytes_remaining(lt_handle_t *h, se_nv_otp_dir_t dir, uint32_t *bytes_out);

/**
 * Read, burn, and XOR one pad. ENCRYPT: @p req_slot is NULL. DECRYPT: SAE
 * logical index; first call may skip-ahead, later calls must be previous+1.
 * @p take must be plain_max except on the last pad, which may be short.
 */
lt_ret_t se_tropic_otp_xor_pad(lt_handle_t *h, const uint16_t *req_slot, const uint8_t *msg,
                                  uint16_t take, uint8_t *out, uint16_t *logical_slot,
                                  uint16_t *phys_slot);

/** Wipe the cached shared secret. Safe if xor_open was not called. */
void se_tropic_otp_xor_close(void);

/**
 * XOR a whole message (open, pad loop, close). Used by model tests.
 * ENCRYPT (@p req_slots NULL) opens by plaintext byte length. DECRYPT opens
 * by @p req_slots_n (encrypt-reply pad count) and needs consecutive slots.
 * @p slot_used is the first physical slot burned.
 */
lt_ret_t se_tropic_otp_xor_message(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                    const uint8_t *add, uint8_t add_len, const uint8_t *msg,
                                    uint16_t len, uint8_t *out, se_nv_otp_dir_t dir,
                                    const uint16_t *req_slots, uint16_t req_slots_n,
                                    uint16_t *slot_used, uint16_t *logical_slots,
                                    uint16_t slots_cap, uint16_t *slots_n);

#ifdef __cplusplus
}
#endif

#endif /* SE_TROPIC_RMEM_H */
