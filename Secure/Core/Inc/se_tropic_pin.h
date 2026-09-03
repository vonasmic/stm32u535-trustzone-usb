/**
 * @file    se_tropic_pin.h
 * @brief   MAC-and-Destroy PIN setup/check (wolfCrypt HMAC via lt_hmac_sha256)
 *
 * Adapted from libtropic examples/model/mac_and_destroy. Attempt budget is
 * deliberately small (SE_TROPIC_PIN_ROUNDS) so model tests cannot exhaust
 * the full 128-slot chip budget by accident when ported to silicon.
 *
 * SPI/L3 is untrusted. Every setup/check mixes a 32-byte MCU pepper
 * (HKDF from the device-seal key) into PIN||add before computing v and the
 * wrap keys. Tropic never sees the pepper; M&D inputs are therefore not a
 * PIN hash. Changing the pepper (new dwk) invalidates existing PIN NVM —
 * re-run KEM INIT.
 */
#ifndef SE_TROPIC_PIN_H
#define SE_TROPIC_PIN_H

#include <stdint.h>
#include "libtropic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PIN attempt slots used by this scheme (max TR01_MACANDD_ROUNDS_MAX = 128).
 * Every wrong attempt destroys one slot permanently; exhausting the budget makes
 * the KEK — and therefore every record stored under it — unrecoverable.
 * The host model overrides this to 4 in host_libtropic_config.h so tests can
 * exercise exhaustion cheaply.
 */
#ifndef SE_TROPIC_PIN_ROUNDS
#define SE_TROPIC_PIN_ROUNDS 8u
#endif

/** R-MEM slot holding M&D NVM blob (reserved; not used for QKD keystream). */
#ifndef SE_TROPIC_PIN_NVM_SLOT
#define SE_TROPIC_PIN_NVM_SLOT 511u
#endif

#define SE_TROPIC_PIN_SIZE_MIN 4u
#define SE_TROPIC_PIN_SIZE_MAX 8u
#define SE_TROPIC_PIN_ADD_SIZE_MAX 128u
/** MCU-only pepper appended to PIN||add; never sent to Tropic. */
#define SE_TROPIC_PIN_PEPPER_SIZE 32u

/**
 * Set up PIN on an open L3 session. Writes M&D NVM into SE_TROPIC_PIN_NVM_SLOT
 * (device-sealed). Always mixes the MCU pepper; @p add is optional extra
 * caller data (NULL/0 is fine).
 * @param master_secret 32-byte entropy (e.g. from lt_random_value_get)
 * @param final_key     out: 32-byte PIN final_key; only on success
 */
lt_ret_t se_tropic_pin_setup(lt_handle_t *h, const uint8_t *master_secret, const uint8_t *pin,
                             uint8_t pin_len, const uint8_t *add, uint8_t add_len,
                             uint8_t *final_key);

/**
 * Check PIN. Wrong PIN permanently consumes one M&D slot until a correct PIN
 * re-initializes the scheme (or the budget is exhausted).
 */
lt_ret_t se_tropic_pin_check(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                             const uint8_t *add, uint8_t add_len, uint8_t *final_key);

#ifdef __cplusplus
}
#endif

#endif /* SE_TROPIC_PIN_H */
