/**
 * @file    sae_qkd.h
 * @brief   SAE-side helpers for host model tests (not linked into Secure firmware)
 */
#ifndef SAE_QKD_H
#define SAE_QKD_H

#include <stdint.h>
#include "libtropic.h"
#include "se_tropic_rmem.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build a finished keystream slot image from plaintext pad (SAE role).
 * @param slot SAE pad index (0 = first pad)
 * @param image_len in: capacity, out: image length
 */
lt_ret_t sae_qkd_encrypt_pad_image(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN], uint16_t slot,
                           const uint8_t *plain, uint16_t plain_len,
                           const uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN], uint8_t *image,
                           uint16_t *image_len);

/**
 * Write then read a full-size payload to confirm the runtime ceiling matches
 * the chip. Destroys the slot's contents. Host-test only.
 */
lt_ret_t sae_rmem_probe_slot_max(lt_handle_t *h, uint16_t slot);

#ifdef __cplusplus
}
#endif

#endif /* SAE_QKD_H */
