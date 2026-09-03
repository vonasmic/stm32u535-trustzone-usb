/**
 * @file    se_tropic_mlkem.h
 * @brief   ML-KEM-768 provisioning and PIN-gated private-key recovery
 *
 * The private key never exists at rest: a 64-byte generation seed is wrapped
 * under HKDF(PIN final_key, salt=device-seal key) in slot 510. Opening it
 * needs both a surviving MAC-and-Destroy PIN check and this MCU. The public
 * key is sent in the TLS uplink (v3). Silicon may still embed fw_mlkem_pk so
 * pub_read works without PIN after reboot.
 */
#ifndef SE_TROPIC_MLKEM_H
#define SE_TROPIC_MLKEM_H

#include <stdint.h>
#include "libtropic.h"
#include "se_tropic_rmem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SE_TROPIC_MLKEM_PK_LEN    1184u
#define SE_TROPIC_MLKEM_SEED_LEN  64u

/** Non-zero when slot 510 holds a wrapped seed. */
lt_ret_t se_tropic_mlkem_seed_occupied(lt_handle_t *h, uint32_t *occupied);

/**
 * One-time provisioning (TROPIC KEM INIT CONFIRM). Consumes M&D slots for PIN
 * setup and refuses when slot 510 is already occupied.
 * @param pk_out 1184-byte ML-KEM-768 public key on success
 */
lt_ret_t se_tropic_mlkem_provision(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                   const uint8_t *add, uint8_t add_len,
                                   uint8_t *pk_out, uint16_t pk_max, uint16_t *pk_len);

/**
 * Read the ML-KEM public key for the TLS uplink (no PIN). Prefers embedded
 * fw_mlkem_pk; otherwise the cache filled by KEM INIT or pub_recover.
 */
uint32_t se_tropic_mlkem_pub_read(uint8_t *pk, uint16_t pk_max, uint16_t *pk_len);

/**
 * Unwrap the Tropic seed with PIN and cache the public key. Use when this boot
 * has no embedded fw_mlkem_pk (host skip-provision, pre-reflash silicon).
 */
uint32_t se_tropic_mlkem_pub_recover(const uint8_t *pin, uint8_t pin_len,
                                     const uint8_t *add, uint8_t add_len);

/** Probe: refuse if slot 510 already holds a seed. */
uint32_t se_tropic_kem_init_probe(void);

/** Confirm provisioning with PIN (4..8 bytes). */
uint32_t se_tropic_kem_init_confirm(const uint8_t *pin, uint8_t pin_len,
                                    const uint8_t *add, uint8_t add_len);

/** Hex-dump ML-KEM public key to the host console. */
uint32_t se_tropic_kem_pub_dump(void);

/**
 * PIN -> KEK -> unwrap seed -> regenerate sk. Must be paired with
 * se_tropic_mlkem_key_close after decapsulation.
 */
lt_ret_t se_tropic_mlkem_key_open(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                                  const uint8_t *add, uint8_t add_len);

/** Decapsulate the fill kem_ct using the opened private key. */
lt_ret_t se_tropic_mlkem_decapsulate(const uint8_t ct[SE_TROPIC_KEM_CT_LEN],
                                     uint8_t ss[SE_TROPIC_MLKEM_SS_LEN]);

/** Wipe the in-memory private key. */
void se_tropic_mlkem_key_close(void);

#ifdef __cplusplus
}
#endif

#endif /* SE_TROPIC_MLKEM_H */
