/**
 * @file    secure_otp.c
 * @brief   TLS OTP request parsers and reply writers
 */
#include "secure_otp.h"
#include "se_le.h"
#include "se_tropic_pin.h"
#include "se_tropic_rmem.h"
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

/* Accumulates the SAE request prefix until complete:
 *   u8 pin_len | pin | u32 (msg_len encrypt, or n_pads decrypt)
 */
#define OTP_REQ_PREFIX_MAX (1u + SE_TROPIC_PIN_SIZE_MAX + 4u)

static struct {
    uint8_t        bytes[OTP_REQ_PREFIX_MAX];
    uint16_t       n_got;
    uint8_t        complete;
    const uint8_t *pin;
    uint8_t        pin_len;
    union {
        uint32_t msg_len; /* encrypt */
        uint32_t n_pads;  /* decrypt */
    };
} s_req;

/* Current body pad:
 *   encrypt: next plaintext chunk
 *   decrypt: u16 slot | u16 chunk_len, then ciphertext
 */
static struct {
    uint8_t  is_decrypt;
    uint16_t slot_plaintext_max;
    uint8_t  payload[SE_TROPIC_RMEM_PLAIN_MAX];
    uint16_t got;
    uint16_t need;
    uint8_t  ready;
    union {
        struct {
            uint32_t bytes_left;
        } encrypt;
        struct {
            uint32_t pads_left;
            uint8_t  rec_hdr[4]; /* u16 slot | u16 chunk_len */
            uint8_t  rec_hdr_got;
            uint16_t slot;
        } decrypt;
    };
} s_pad;

void secure_otp_reset_pad(void)
{
    wc_ForceZero(s_pad.payload, s_pad.got);
    wc_ForceZero(s_pad.decrypt.rec_hdr, sizeof(s_pad.decrypt.rec_hdr));
    s_pad.is_decrypt = 0U;
    s_pad.slot_plaintext_max = 0U;
    s_pad.encrypt.bytes_left = 0U;
    s_pad.decrypt.rec_hdr_got = 0U;
    s_pad.decrypt.slot = 0U;
    s_pad.got = 0U;
    s_pad.need = 0U;
    s_pad.ready = 0U;
}

void secure_otp_reset(void)
{
    wc_ForceZero(s_req.bytes, s_req.n_got);
    s_req.n_got = 0U;
    s_req.complete = 0U;
    s_req.pin = NULL;
    s_req.pin_len = 0U;
    s_req.msg_len = 0U;
    secure_otp_reset_pad();
}

static uint32_t parse_request(const uint8_t *chunk, uint32_t len, uint32_t *consumed)
{
    uint32_t used = 0U;
    uint32_t need;
    uint32_t take;
    uint8_t pin_len;
    uint32_t v;

    if (consumed != NULL) {
        *consumed = 0U;
    }
    if (s_req.complete != 0U) {
        return SECURE_OTP_REQ_COMPLETE;
    }
    if ((chunk == NULL) && (len > 0U)) {
        return SECURE_OTP_REQ_PARSE;
    }

    if (s_req.n_got == 0U) {
        if (len == 0U) {
            return SECURE_OTP_REQ_OK;
        }
        s_req.bytes[0] = chunk[0];
        s_req.n_got = 1U;
        used = 1U;
        chunk++;
        len--;
    }

    pin_len = s_req.bytes[0];
    if ((pin_len < SE_TROPIC_PIN_SIZE_MIN) || (pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
        if (consumed != NULL) {
            *consumed = used;
        }
        secure_otp_reset();
        return SECURE_OTP_REQ_PARSE;
    }

    need = 1U + (uint32_t)pin_len + 4U;
    take = need - (uint32_t)s_req.n_got;
    if (take > len) {
        take = len;
    }
    if (take > 0U) {
        (void)memcpy(s_req.bytes + s_req.n_got, chunk, take);
        s_req.n_got = (uint16_t)(s_req.n_got + take);
        used += take;
    }
    if ((uint32_t)s_req.n_got < need) {
        if (consumed != NULL) {
            *consumed = used;
        }
        return SECURE_OTP_REQ_OK;
    }

    s_req.pin_len = pin_len;
    s_req.pin = s_req.bytes + 1U;
    v = se_u32le(s_req.bytes + 1U + pin_len);
    if (v == 0U) {
        if (consumed != NULL) {
            *consumed = used;
        }
        secure_otp_reset();
        return SECURE_OTP_REQ_PARSE;
    }
    s_req.msg_len = v;
    s_req.complete = 1U;
    if (consumed != NULL) {
        *consumed = used;
    }
    return SECURE_OTP_REQ_COMPLETE;
}

uint32_t secure_otp_encrypt_parse_request(const uint8_t *chunk, uint32_t len,
                                          uint32_t *consumed)
{
    return parse_request(chunk, len, consumed);
}

uint32_t secure_otp_decrypt_parse_request(const uint8_t *chunk, uint32_t len,
                                          uint32_t *consumed)
{
    return parse_request(chunk, len, consumed);
}

const uint8_t *secure_otp_request_pin(uint8_t *pin_len)
{
    if (pin_len != NULL) {
        *pin_len = s_req.pin_len;
    }
    return s_req.pin;
}

uint32_t secure_otp_encrypt_msg_len(void)
{
    return s_req.msg_len;
}

uint32_t secure_otp_decrypt_n_pads(void)
{
    return s_req.n_pads;
}

static uint16_t encrypt_this_pad_len(void)
{
    if (s_pad.encrypt.bytes_left == 0U) {
        return 0U;
    }
    if (s_pad.encrypt.bytes_left > (uint32_t)s_pad.slot_plaintext_max) {
        return s_pad.slot_plaintext_max;
    }
    return (uint16_t)s_pad.encrypt.bytes_left;
}

/** @return 1 if more pads/chunks remain; 0 if the body count is exhausted. */
static uint8_t pad_body_has_remaining(void)
{
    if (s_pad.is_decrypt != 0U) {
        return (s_pad.decrypt.pads_left != 0U) ? 1U : 0U;
    }
    return (s_pad.encrypt.bytes_left != 0U) ? 1U : 0U;
}

static void pad_set_body_count(uint32_t count)
{
    if (s_pad.is_decrypt != 0U) {
        s_pad.decrypt.pads_left = count;
    } else {
        s_pad.encrypt.bytes_left = count;
        s_pad.need = encrypt_this_pad_len();
    }
}

static void pad_advance_after_ready(void)
{
    if (s_pad.is_decrypt != 0U) {
        s_pad.decrypt.pads_left -= 1U;
    } else {
        s_pad.encrypt.bytes_left -= (uint32_t)s_pad.need;
    }
}

static void pad_prepare_next_chunk(void)
{
    if ((s_pad.is_decrypt == 0U) && (s_pad.encrypt.bytes_left > 0U)) {
        s_pad.need = encrypt_this_pad_len();
    }
}

/** @return 1 record header complete, 0 need more bytes, -1 parse error. */
static int ingest_decrypt_rec_hdr(const uint8_t **chunk, uint32_t *len, uint32_t *n)
{
    uint32_t take = 4U - (uint32_t)s_pad.decrypt.rec_hdr_got;

    if (take > *len) {
        take = *len;
    }
    if (take > 0U) {
        (void)memcpy(s_pad.decrypt.rec_hdr + s_pad.decrypt.rec_hdr_got, *chunk, take);
        s_pad.decrypt.rec_hdr_got = (uint8_t)(s_pad.decrypt.rec_hdr_got + take);
        *n += take;
        *chunk += take;
        *len -= take;
    }
    if (s_pad.decrypt.rec_hdr_got < 4U) {
        return 0;
    }
    s_pad.decrypt.slot = se_u16le(s_pad.decrypt.rec_hdr);
    s_pad.need = se_u16le(s_pad.decrypt.rec_hdr + 2U);
    if ((s_pad.need == 0U) || (s_pad.need > s_pad.slot_plaintext_max) ||
        ((s_pad.decrypt.pads_left > 1U) && (s_pad.need != s_pad.slot_plaintext_max))) {
        return -1;
    }
    s_pad.got = 0U;
    return 1;
}

static uint8_t decrypt_needs_rec_hdr(void)
{
    return (s_pad.is_decrypt != 0U) && (s_pad.decrypt.rec_hdr_got < 4U) && (s_pad.need == 0U);
}

static void begin_request_body(uint8_t decrypt, uint16_t slot_plaintext_max, uint32_t count)
{
    secure_otp_reset_pad();
    s_pad.is_decrypt = (decrypt != 0U) ? 1U : 0U;
    s_pad.slot_plaintext_max = slot_plaintext_max;
    pad_set_body_count(count);
}

void secure_otp_encrypt_begin_plaintext(uint16_t slot_plaintext_max, uint32_t msg_len)
{
    begin_request_body(0U, slot_plaintext_max, msg_len);
}

void secure_otp_decrypt_begin_ciphertext(uint16_t slot_plaintext_max, uint32_t n_pads)
{
    begin_request_body(1U, slot_plaintext_max, n_pads);
}

static uint32_t parse_one_pad_from_chunk(const uint8_t *chunk, uint32_t len, uint32_t *used)
{
    uint32_t n = 0U;

    *used = 0U;
    if (s_pad.ready != 0U) {
        return SECURE_OTP_PAD_READY;
    }
    if (s_pad.slot_plaintext_max == 0U) {
        return SECURE_OTP_REQ_PARSE;
    }
    if (pad_body_has_remaining() == 0U) {
        return SECURE_OTP_REQ_PARSE;
    }

    if (decrypt_needs_rec_hdr() != 0U) {
        int hdr_st = ingest_decrypt_rec_hdr(&chunk, &len, &n);

        if (hdr_st < 0) {
            return SECURE_OTP_REQ_PARSE;
        }
        if (hdr_st == 0) {
            *used = n;
            return SECURE_OTP_REQ_OK;
        }
    }

    if (s_pad.need > 0U) {
        uint32_t take = (uint32_t)s_pad.need - (uint32_t)s_pad.got;

        if (take > len) {
            take = len;
        }
        if (take > 0U) {
            (void)memcpy(s_pad.payload + s_pad.got, chunk, take);
            s_pad.got = (uint16_t)(s_pad.got + take);
            n += take;
        }
        if (s_pad.got < s_pad.need) {
            *used = n;
            return SECURE_OTP_REQ_OK;
        }
        s_pad.ready = 1U;
        pad_advance_after_ready();
        *used = n;
        return SECURE_OTP_PAD_READY;
    }

    *used = n;
    return SECURE_OTP_REQ_OK;
}

uint32_t secure_otp_read_pad(const uint8_t *chunk, uint32_t len, uint32_t *consumed)
{
    uint32_t used = 0U;
    uint32_t st;

    if (consumed != NULL) {
        *consumed = 0U;
    }
    if (s_pad.ready != 0U) {
        return SECURE_OTP_PAD_READY;
    }
    if ((chunk == NULL) && (len > 0U)) {
        return SECURE_OTP_REQ_PARSE;
    }
    st = parse_one_pad_from_chunk(chunk, len, &used);
    if (consumed != NULL) {
        *consumed = used;
    }
    if (st == SECURE_OTP_REQ_PARSE) {
        secure_otp_reset_pad();
    }
    return st;
}

uint8_t *secure_otp_pad_payload(uint16_t *len)
{
    if (len != NULL) {
        *len = (s_pad.ready != 0U) ? s_pad.need : 0U;
    }
    return (s_pad.ready != 0U) ? s_pad.payload : NULL;
}

uint16_t secure_otp_decrypt_pad_slot(void)
{
    return s_pad.decrypt.slot;
}

void secure_otp_pad_done(void)
{
    wc_ForceZero(s_pad.payload, s_pad.got);
    wc_ForceZero(s_pad.decrypt.rec_hdr, sizeof(s_pad.decrypt.rec_hdr));
    s_pad.got = 0U;
    s_pad.need = 0U;
    s_pad.decrypt.rec_hdr_got = 0U;
    s_pad.ready = 0U;
    s_pad.decrypt.slot = 0U;
    pad_prepare_next_chunk();
}

int secure_otp_encode_n_pads(uint32_t n_pads, uint8_t out[4])
{
    if ((out == NULL) || (n_pads == 0U)) {
        return -1;
    }
    se_put_u32le(out, n_pads);
    return 0;
}

int secure_otp_encode_err(uint32_t err_code, uint8_t out[8])
{
    if ((out == NULL) || (err_code == 0U)) {
        return -1;
    }
    se_put_u32le(out, 0U);
    se_put_u32le(out + 4U, err_code);
    return 0;
}

int secure_otp_encode_pad(uint8_t decrypt, uint16_t slot, const uint8_t *data, uint16_t len,
                          uint8_t *out, uint32_t cap, uint32_t *written)
{
    uint32_t hdr = (decrypt != 0U) ? 2U : 4U;
    uint32_t need = hdr + (uint32_t)len;

    if ((data == NULL) || (out == NULL) || (written == NULL) || (len == 0U) || (need > cap)) {
        return -1;
    }
    if (decrypt != 0U) {
        se_put_u16le(out, len);
    } else {
        se_put_u16le(out, slot);
        se_put_u16le(out + 2, len);
    }
    (void)memcpy(out + hdr, data, len);
    *written = need;
    return 0;
}
