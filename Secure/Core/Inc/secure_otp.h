/**
 * @file    secure_otp.h
 * @brief   TLS OTP consume session (parse / XOR / reply)
 *
 * ENCRYPT request  (USER → SE):  u8 pin_len | pin | u32 msg_len LE | plaintext
 * ENCRYPT reply    (SE → USER):  u32 n_pads LE | repeat: slot | chunk_len | ciphertext
 *
 * DECRYPT request  (USER → SE):  u8 pin_len | pin | ENCRYPT reply (unchanged)
 * DECRYPT reply    (SE → USER):  u32 n_pads LE | repeat: chunk_len | plaintext
 *
 * TLS pumps bytes through {@code secure_otp_session_feed()}. Parse and encode
 * stay inside secure_otp.c.
 */
#ifndef SECURE_OTP_H
#define SECURE_OTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TLS error reply (SE → UserApp) when n_pads is 0:
 *   u32 n_pads LE = 0 | u32 err_code LE
 */
#define SECURE_OTP_ERR_EXHAUSTED 1u
#define SECURE_OTP_ERR_PARSE     3u
#define SECURE_OTP_ERR_PIN       4u
#define SECURE_OTP_ERR_TAMPERED  5u
#define SECURE_OTP_ERR_FAIL      255u

#define SECURE_OTP_SESSION_NEED_MORE 0
#define SECURE_OTP_SESSION_REPLY     1
#define SECURE_OTP_SESSION_DONE      2

#define SECURE_OTP_PHASE_IDLE 0u
#define SECURE_OTP_PHASE_HDR  1u
#define SECURE_OTP_PHASE_PAD  2u
#define SECURE_OTP_PHASE_TX   3u
#define SECURE_OTP_PHASE_DONE 4u

void secure_otp_session_reset(void);
void secure_otp_session_begin(uint8_t decrypt);
uint8_t secure_otp_session_phase(void);

int secure_otp_session_has_in(void);
int secure_otp_session_feed(const uint8_t *data, uint32_t len);
const uint8_t *secure_otp_session_tx(uint16_t *len);
void secure_otp_session_tx_consumed(uint16_t n);
int secure_otp_session_tx_complete(void);
uint32_t secure_otp_session_err(void);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_OTP_H */
