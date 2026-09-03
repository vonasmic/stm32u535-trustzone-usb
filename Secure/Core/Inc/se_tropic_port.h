/**
 * @file    se_tropic_port.h
 * @brief   Platform port for TROPIC01 runtime (STM32 Secure vs host model)
 *
 * Firmware and host model tests share se_tropic*.c. Each platform supplies
 * these hooks: device attach, optional HW power-on, and logging.
 */
#ifndef SE_TROPIC_PORT_H
#define SE_TROPIC_PORT_H

#include <stdarg.h>
#include <stdint.h>
#include "libtropic.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Power / CS prep before first SPI (no-op on host model). */
void se_tropic_port_hw_init(void);

/**
 * Bind transport + crypto context onto an uninitialized handle.
 * Sets h->l2.device and h->l3.crypto_ctx. Does not call lt_init.
 */
uint32_t se_tropic_port_attach(lt_handle_t *h);

/** Debug line (USB CDC on firmware, stdout on host). */
void se_tropic_log(const char *fmt, ...);

/** Hex-dump @p data via se_tropic_log (optional @p label line first). */
void se_tropic_log_hex(const char *label, const uint8_t *data, uint32_t len);

/**
 * Derive or supply the 32-byte device-seal AES key used for R-MEM AEAD,
 * PIN pepper HKDF, and ML-KEM seed-wrap HKDF salt.
 * STM32: HKDF from secure_dwk. Host model: fixed test key.
 */
lt_ret_t se_tropic_port_device_aead_key(uint8_t out[32]);

/**
 * Embedded ML-KEM-768 public key (fw_mlkem_pk on device; host fixture on model).
 * @return pointer valid for the process lifetime; may be empty (len 0).
 */
const uint8_t *se_tropic_port_mlkem_pk(void);

/** Length of se_tropic_port_mlkem_pk(); 0 when not yet embedded. */
unsigned int se_tropic_port_mlkem_pk_len(void);

/**
 * Print chip_id.
 */
void se_tropic_port_print_chip_id(const lt_chip_id_t *chip_id);

/**
 * Dedicated MCU NV page (Secure flash on device, RAM on host model).
 * Read @p len bytes from the start of the page.
 */
lt_ret_t se_tropic_port_nv_raw_read(uint8_t *dst, uint16_t len);

/**
 * Erase the NV page and program @p len bytes at the start.
 */
lt_ret_t se_tropic_port_nv_raw_write(const uint8_t *src, uint16_t len);

/** Fill @p len random bytes (HAL RNG on STM32, getentropy/rand on host). */
lt_ret_t se_tropic_port_nv_random(uint8_t *out, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* SE_TROPIC_PORT_H */
