/**
 * @file    host_secure_otp_test.h
 * @brief   Parser/encode symbols for model tests (not on the firmware public header)
 */
#ifndef HOST_SECURE_OTP_TEST_H
#define HOST_SECURE_OTP_TEST_H

#include "secure_otp.h"

#define SECURE_OTP_REQ_OK       0u
#define SECURE_OTP_REQ_PARSE    3u
#define SECURE_OTP_REQ_COMPLETE 5u
#define SECURE_OTP_PAD_READY    6u

void secure_otp_reset(void);
void secure_otp_reset_pad(void);
uint32_t secure_otp_encrypt_parse_request(const uint8_t *chunk, uint32_t len, uint32_t *consumed);
uint32_t secure_otp_decrypt_parse_request(const uint8_t *chunk, uint32_t len, uint32_t *consumed);
const uint8_t *secure_otp_request_pin(uint8_t *pin_len);
uint32_t secure_otp_encrypt_msg_len(void);
uint32_t secure_otp_decrypt_n_pads(void);
void secure_otp_encrypt_begin_plaintext(uint16_t slot_plaintext_max, uint32_t msg_len);
void secure_otp_decrypt_begin_ciphertext(uint16_t slot_plaintext_max, uint32_t n_pads);
uint32_t secure_otp_read_pad(const uint8_t *chunk, uint32_t len, uint32_t *consumed);
uint8_t *secure_otp_pad_payload(uint16_t *len);
uint16_t secure_otp_decrypt_pad_slot(void);
void secure_otp_pad_done(void);
int secure_otp_encode_n_pads(uint32_t n_pads, uint8_t out[4]);
int secure_otp_encode_err(uint32_t err_code, uint8_t out[8]);
int secure_otp_encode_pad(uint8_t decrypt, uint16_t slot, const uint8_t *data, uint16_t len,
                          uint8_t *out, uint32_t cap, uint32_t *written);

#endif
