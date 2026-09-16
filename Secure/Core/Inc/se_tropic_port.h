/**
 * @file    se_tropic_port.h
 * @brief   Platform port for TROPIC01 runtime (STM32 Secure vs host model)
 *
 * Firmware and host model tests share se_tropic*.c. Each platform supplies
 * these hooks: device attach, optional HW power-on, and logging.
 */
#ifndef SE_TROPIC_PORT_H
#define SE_TROPIC_PORT_H

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

/** Debug line (USB CDC DEBUG on firmware and se_host). */
void se_tropic_log(const char *msg);

/** Two CDC DEBUG lines: @p what, then lt_ret_verbose(@p ret). */
static inline void se_tropic_log_fail(const char *what, lt_ret_t ret)
{
    se_tropic_log(what);
    se_tropic_log(lt_ret_verbose(ret));
}

/** Hex-dump @p data via se_tropic_log (optional @p label line first). */
void se_tropic_log_hex(const char *label, const uint8_t *data, uint32_t len);

/**
 * Derive or supply the 32-byte device-seal AES key used for R-MEM AEAD,
 * PIN pepper HKDF, and ML-KEM seed-wrap HKDF salt.
 * STM32: HKDF from secure_dwk. Host model: fixed test key.
 */
lt_ret_t se_tropic_port_device_aead_key(uint8_t out[32]);

/**
 * ML-KEM-768 public key: NV first, then host fixture (model) or empty (silicon).
 * @return pointer valid until the next NV write; may be empty (len 0).
 */
const uint8_t *se_tropic_port_mlkem_pk(void);

/** Length of se_tropic_port_mlkem_pk(); 0 when not yet enrolled. */
unsigned int se_tropic_port_mlkem_pk_len(void);

/**
 * Print chip_id.
 */
void se_tropic_port_print_chip_id(const lt_chip_id_t *chip_id);

#define SE_NV_PAGE_SIZE    8192u
#define SE_NV_DWK_LEN      32u
#define SE_NV_REC_OFF      32u
#define SE_NV_BLOB_OFF     SE_NV_REC_OFF
#define SE_CREDS_PAGE_SIZE 8192u
#define SE_DEVICE_ID_LEN   12u

/**
 * Dedicated MCU NV page (Secure flash on device, RAM on host model).
 * Read @p len bytes from the start of the page.
 */
lt_ret_t se_tropic_port_nv_raw_read(uint8_t *dst, uint16_t len);

/**
 * Erase the NV page and program @p len bytes at the start.
 */
lt_ret_t se_tropic_port_nv_raw_write(const uint8_t *src, uint16_t len);

/** Read/write the full 8 KB NV page (dwk header + plaintext record). */
lt_ret_t se_tropic_port_nv_page_read(uint8_t dst[SE_NV_PAGE_SIZE]);
lt_ret_t se_tropic_port_nv_page_write(const uint8_t src[SE_NV_PAGE_SIZE]);

/** Copy @p len bytes at @p off from the NV page (no 8 KB work buffer). */
lt_ret_t se_tropic_port_nv_slice_read(uint16_t off, uint8_t *dst, uint16_t len);

/** Public cert page (SAE CA + device cert). Secure-only writes. */
lt_ret_t se_tropic_port_creds_page_read(uint8_t dst[SE_CREDS_PAGE_SIZE]);
lt_ret_t se_tropic_port_creds_page_write(const uint8_t src[SE_CREDS_PAGE_SIZE]);

/**
 * 32-byte Tropic-seal root. Generate-once when the NV header is erased.
 * Not used to encrypt NV. STM32 R-MEM AEAD HKDF uses this; host AEAD stays a test key.
 */
lt_ret_t se_tropic_port_dwk(uint8_t out[SE_NV_DWK_LEN]);

/** MCU unique id (STM32 UID) or a fixed host-model id. */
void se_tropic_port_device_id(uint8_t out[SE_DEVICE_ID_LEN]);

/** Fill @p len random bytes (HAL RNG on STM32, getentropy/rand on host). */
lt_ret_t se_tropic_port_nv_random(uint8_t *out, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* SE_TROPIC_PORT_H */
