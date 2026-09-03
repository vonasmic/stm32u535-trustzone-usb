/**
 * @file    secure_otp.h
 * @brief   TLS OTP: parse SAE requests, assemble pads, encode SE replies
 *
 * ENCRYPT request  (SAE → SE):  u8 pin_len | pin | u32 msg_len LE | plaintext
 * ENCRYPT reply    (SE → SAE):  u32 n_pads LE | repeat: slot | chunk_len | ciphertext
 *
 * DECRYPT request  (SAE → SE):  u8 pin_len | pin | ENCRYPT reply (unchanged)
 * DECRYPT reply    (SE → SAE):  u32 n_pads LE | repeat: chunk_len | plaintext
 */
#ifndef SECURE_OTP_H
#define SECURE_OTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Return codes from secure_otp_*_parse_request() and secure_otp_read_pad(). */
#define SECURE_OTP_REQ_OK       0u  /**< Need more bytes; keep feeding input (state kept). */
#define SECURE_OTP_REQ_PARSE    3u  /**< Bad framing; parser reset — abort OTP/TLS session. */
#define SECURE_OTP_REQ_COMPLETE 5u  /**< PIN + u32 length parsed — open XOR, then read pads. */
#define SECURE_OTP_PAD_READY    6u  /**< One pad buffered — XOR, reply, secure_otp_pad_done(), continue. */

void secure_otp_reset(void);
void secure_otp_reset_pad(void);

/* --- request header (PIN + length field) --- */

uint32_t secure_otp_encrypt_parse_request(const uint8_t *chunk, uint32_t len,
                                          uint32_t *consumed);
uint32_t secure_otp_decrypt_parse_request(const uint8_t *chunk, uint32_t len,
                                          uint32_t *consumed);

const uint8_t *secure_otp_request_pin(uint8_t *pin_len);
uint32_t secure_otp_encrypt_msg_len(void);
uint32_t secure_otp_decrypt_n_pads(void);

/* --- request body: fill one pad, then XOR it --- */
/* @p slot_plaintext_max: max plaintext bytes per R-MEM pad (se_tropic_otp_xor_pad_max()). */

void secure_otp_encrypt_begin_plaintext(uint16_t slot_plaintext_max, uint32_t msg_len);
void secure_otp_decrypt_begin_ciphertext(uint16_t slot_plaintext_max, uint32_t n_pads);

uint32_t secure_otp_read_pad(const uint8_t *chunk, uint32_t len, uint32_t *consumed);
uint8_t *secure_otp_pad_payload(uint16_t *len);
uint16_t secure_otp_decrypt_pad_slot(void);
void secure_otp_pad_done(void);

/* --- reply (SE → SAE): encode one n_pads header or pad record into @p out --- */

int secure_otp_encode_n_pads(uint32_t n_pads, uint8_t out[4]);
/** @p decrypt: 0 encrypt (u16 slot | u16 len | data), else decrypt (u16 len | data). */
int secure_otp_encode_pad(uint8_t decrypt, uint16_t slot, const uint8_t *data, uint16_t len,
                          uint8_t *out, uint32_t cap, uint32_t *written);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_OTP_H */
