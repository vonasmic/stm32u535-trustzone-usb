/**
 * @file    test_i_post_tls.c
 * @brief   Group I: encrypt-mode PIN+plaintext body and OTP reply slots
 *
 * No wolfSSL client. After a G-style QKD load, drive the production
 * secure_otp_session_feed path (PIN + plaintext / decrypt stream) and collect
 * the encoded OTP reply. XOR each pad on the device, leftover TLS bytes,
 * a two-pad Tropic XOR, a 100 KiB encrypt, remaining-byte query,
 * decrypt skip-ahead, and encrypt/decrypt refuse when the request needs more
 * pads than remain (fail-early, no partial ciphertext). Codec-only pad
 * framing stays in test_otp_parse_pads().
 */
#include "test_harness.h"
#include "secure_qkd_ingest.h"
#include "host_secure_otp_test.h"
#include "secure_lv.h"
#include "se_le.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_rmem.h"
#include "se_tropic_pin.h"
#include "se_nv.h"
#include "host_fw_mlkem.h"
#include "libtropic.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#define CHUNK_SIZE 7u
#define LONG_MSG_LEN (100u * 1024u)

static lt_ret_t sae_encapsulate(const uint8_t pk[SE_TROPIC_MLKEM_PK_LEN],
                                uint8_t ct[SE_TROPIC_KEM_CT_LEN],
                                uint8_t ss[SE_TROPIC_MLKEM_SS_LEN])
{
    MlKemKey kem;
    uint8_t rand[32];
    unsigned int i;
    int ret;

    for (i = 0U; i < sizeof(rand); i++) {
        rand[i] = (uint8_t)(0xB0u + (uint8_t)i);
    }

    ret = wc_MlKemKey_Init(&kem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        return LT_CRYPTO_ERR;
    }
    ret = wc_MlKemKey_DecodePublicKey(&kem, pk, SE_TROPIC_MLKEM_PK_LEN);
    if (ret != 0) {
        wc_MlKemKey_Free(&kem);
        return LT_CRYPTO_ERR;
    }
    ret = wc_MlKemKey_EncapsulateWithRandom(&kem, ct, ss, rand, (int)sizeof(rand));
    wc_MlKemKey_Free(&kem);
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

static lt_ret_t seal_pad_pending(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                                 const uint8_t fill_id[SE_NV_FILL_ID_LEN], uint16_t slot_index,
                                 const uint8_t *plain, uint16_t plain_len,
                                 const uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN], uint8_t *image,
                                 uint16_t *image_len)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[2];
    lt_ret_t ret;

    write_storage_slot_binding(slot_index, binding);

    ret = se_tropic_get_pad_encryption_key(ss, fill_id, slot_index, key);
    if (ret == LT_OK) {
        ret = se_tropic_encrypt_storage_blob(key, binding, sizeof(binding), plain, plain_len,
                                             nonce, image, image_len);
    }
    wc_ForceZero(key, sizeof(key));
    return ret;
}

static uint32_t feed_qkd(const uint8_t *blob, uint32_t blob_len)
{
    uint32_t off = 0U;
    uint32_t st = SECURE_QKD_OK;

    while ((off < blob_len) && (st == SECURE_QKD_OK)) {
        uint32_t take = blob_len - off;

        if (take > CHUNK_SIZE) {
            take = CHUNK_SIZE;
        }
        st = secure_qkd_ingest(blob + off, take, SECURE_QKD_INGEST_CHUNK, NULL);
        off += take;
    }
    return st;
}

static int otp_append(uint8_t *buf, uint32_t cap, uint32_t *off, uint8_t decrypt, uint16_t slot,
                      const uint8_t *data, uint16_t len)
{
    uint32_t w = 0U;

    if (secure_otp_encode_pad(decrypt, slot, data, len, buf + *off, cap - *off, &w) != 0) {
        return -1;
    }
    *off += w;
    return 0;
}

/** SAE-side decoder of an ENCRYPT reply (not firmware). */
static int encrypt_parse_reply(const uint8_t *data, uint32_t data_len, uint16_t *slots,
                               uint16_t slots_cap, uint16_t *slots_n, uint8_t *payload,
                               uint32_t payload_cap, uint32_t *payload_len)
{
    uint32_t pos;
    uint32_t n_pads;
    uint16_t n = 0U;
    uint32_t out_len = 0U;

    if ((data == NULL) || (slots == NULL) || (slots_n == NULL) || (payload == NULL) ||
        (payload_len == NULL) || (slots_cap == 0U) || (data_len < 8U)) {
        return -1;
    }
    *slots_n = 0U;
    *payload_len = 0U;
    n_pads = se_u32le(data);
    if ((n_pads == 0U) || (n_pads > (uint32_t)slots_cap)) {
        return -1;
    }
    pos = 4U;
    while (n < n_pads) {
        uint16_t slot;
        uint16_t clen;

        if ((pos + 4U) > data_len) {
            return -1;
        }
        slot = se_u16le(data + pos);
        clen = se_u16le(data + pos + 2U);
        pos += 4U;
        if ((clen == 0U) || ((pos + clen) > data_len) ||
            ((out_len + (uint32_t)clen) > payload_cap)) {
            return -1;
        }
        slots[n] = slot;
        (void)memcpy(payload + out_len, data + pos, clen);
        out_len += (uint32_t)clen;
        pos += clen;
        n = (uint16_t)(n + 1u);
    }
    if (pos != data_len) {
        return -1;
    }
    *slots_n = n;
    *payload_len = out_len;
    return 0;
}

static void put_pad_rec(uint8_t *buf, uint32_t *off, uint16_t slot, const uint8_t *chunk,
                        uint16_t len)
{
    se_append_u16le(buf, off, slot);
    se_append_u16le(buf, off, len);
    if (len > 0U) {
        (void)memcpy(buf + *off, chunk, len);
        *off += len;
    }
}

/** Copy payload bytes in CHUNK_SIZE slices until one pad is full. Leftover stays in *p. */
static uint32_t parse_until_pad_ready(const uint8_t **p, uint32_t *left)
{
    uint32_t st = SECURE_OTP_REQ_OK;

    while (*left > 0U) {
        uint32_t take = *left;
        uint32_t consumed = 0U;

        if (take > CHUNK_SIZE) {
            take = CHUNK_SIZE;
        }
        st = secure_otp_read_pad(*p, take, &consumed);
        if ((consumed == 0U) && (st != SECURE_OTP_PAD_READY)) {
            return SECURE_OTP_REQ_PARSE;
        }
        *p += consumed;
        *left -= consumed;
        if (st != SECURE_OTP_REQ_OK) {
            return st;
        }
    }
    return st;
}

static int session_append_tx(uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    uint16_t n = 0U;
    const uint8_t *p = secure_otp_session_tx(&n);

    if ((p == NULL) || (n == 0U) || (out == NULL) || (out_len == NULL)) {
        return -1;
    }
    if ((*out_len + (uint32_t)n) > cap) {
        return -1;
    }
    (void)memcpy(out + *out_len, p, n);
    *out_len += (uint32_t)n;
    secure_otp_session_tx_consumed(n);
    return 0;
}

static int session_drain_tx(uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    int rc;

    if (session_append_tx(out, cap, out_len) != 0) {
        return -1;
    }
    rc = secure_otp_session_tx_complete();
    while (rc == SECURE_OTP_SESSION_REPLY) {
        if (session_append_tx(out, cap, out_len) != 0) {
            return -1;
        }
        rc = secure_otp_session_tx_complete();
    }
    return rc;
}

/**
 * Feed @p in in CHUNK_SIZE slices through the production session path.
 * @return 0 need more input, 1 session done, -1 fail.
 */
static int pump_otp_session(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t cap,
                            uint32_t *out_len)
{
    uint32_t off = 0U;

    if (out_len == NULL) {
        return -1;
    }
    *out_len = 0U;
    while ((off < in_len) || (secure_otp_session_has_in() != 0)) {
        int rc;

        if (secure_otp_session_has_in() != 0) {
            rc = secure_otp_session_feed(NULL, 0U);
        } else {
            uint32_t take = in_len - off;

            if (take > CHUNK_SIZE) {
                take = CHUNK_SIZE;
            }
            rc = secure_otp_session_feed(in + off, take);
            off += take;
        }
        if (rc < 0) {
            return -1;
        }
        if (rc == SECURE_OTP_SESSION_REPLY) {
            rc = session_drain_tx(out, cap, out_len);
            if (rc < 0) {
                return -1;
            }
            if (rc == SECURE_OTP_SESSION_DONE) {
                return 1;
            }
        }
    }
    return 0;
}

static void pattern_keystream(uint8_t *out, uint16_t len, uint16_t slot)
{
    uint16_t i;

    for (i = 0U; i < len; i++) {
        out[i] = (uint8_t)(((uint32_t)slot * 31u) + (uint32_t)i);
    }
}

static void pattern_plaintext(uint8_t *out, uint16_t len, uint32_t off)
{
    uint16_t i;

    for (i = 0U; i < len; i++) {
        out[i] = (uint8_t)(0xA5u ^ (uint8_t)((off + (uint32_t)i) & 0xFFu));
    }
}

/** Fill @p n_pads encrypt-half slots, then XOR a 100 KiB message pad-by-pad. */
static int test_long_encrypt(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                             const uint8_t pk[SE_TROPIC_MLKEM_PK_LEN])
{
    static uint8_t pad[SE_TROPIC_RMEM_PLAIN_MAX];
    static uint8_t image[SE_TROPIC_RMEM_BLOB_MAX];
    uint8_t kem_ct[SE_TROPIC_KEM_CT_LEN];
    uint8_t ss[SE_TROPIC_MLKEM_SS_LEN];
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t hdr[1u + SE_TROPIC_PIN_SIZE_MAX + 4u];
    uint8_t pt[SE_TROPIC_RMEM_PLAIN_MAX];
    uint16_t image_len;
    uint16_t plain_max;
    uint16_t slot;
    uint32_t n_need;
    uint32_t left_before = 0U;
    uint32_t left_after = 0U;
    uint32_t hdr_len = 0U;
    uint32_t off = 0U;
    uint32_t cursor_before = 0U;
    uint32_t cursor_after = 0U;
    uint16_t n_pads_u16;
    lt_ret_t ret;
    int i;

    printf("--- I: 100 KiB encrypt ---\n");
    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    TEST_ASSERT(plain_max > 16U, "plain_max for 100 KiB");
    n_need = (LONG_MSG_LEN + (uint32_t)plain_max - 1U) / (uint32_t)plain_max;
    TEST_ASSERT(n_need > 1U, "100 KiB spans multiple pads");
    TEST_ASSERT(n_need <= (uint32_t)SE_TROPIC_PAD_HALF, "100 KiB fits encrypt half");
    n_pads_u16 = (uint16_t)n_need;

    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate 100 KiB");
    ret = se_tropic_kem_ct_write(h, kem_ct);
    TEST_ASSERT_EQ(ret, LT_OK, "kem_ct write 100 KiB");
    ret = se_tropic_qkd_arm_halves(h, 1U);
    TEST_ASSERT_EQ(ret, LT_OK, "arm encrypt-first half");
    ret = se_nv_get_fill_id(fill_id);
    TEST_ASSERT_EQ(ret, LT_OK, "fill_id after 100 KiB kem_ct");

    for (slot = 0U; slot < n_pads_u16; slot++) {
        pattern_keystream(pad, plain_max, slot);
        for (i = 0; i < (int)SE_TROPIC_RMEM_NONCE_LEN; i++) {
            nonce[i] = (uint8_t)(0xD0u + (uint8_t)i);
        }
        nonce[0] = (uint8_t)slot;
        nonce[1] = (uint8_t)(slot >> 8);
        image_len = sizeof(image);
        ret = seal_pad_pending(ss, fill_id, slot, pad, plain_max, nonce, image, &image_len);
        TEST_ASSERT_EQ(ret, LT_OK, "seal 100 KiB pad");
        ret = se_tropic_qkd_store(h, slot, image, image_len);
        TEST_ASSERT_EQ(ret, LT_OK, "store 100 KiB pad");
    }

    ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_ENCRYPT, &left_before);
    TEST_ASSERT_EQ(ret, LT_OK, "remaining before 100 KiB");
    TEST_ASSERT(left_before >= LONG_MSG_LEN, "half covers 100 KiB");

    hdr[hdr_len++] = pin_len;
    (void)memcpy(hdr + hdr_len, pin, pin_len);
    hdr_len += (uint32_t)pin_len;
    se_append_u32le(hdr, &hdr_len, LONG_MSG_LEN);
    secure_otp_session_reset();
    secure_otp_session_begin(0U);
    {
        uint8_t rec[4u + 4u + SE_TROPIC_RMEM_PLAIN_MAX];
        uint32_t rec_len = 0U;
        uint16_t rec_i = 0U;
        uint8_t hdr_done = 0U;
        int rc;

        rc = pump_otp_session(hdr, hdr_len, rec, (uint32_t)sizeof(rec), &rec_len);
        TEST_ASSERT_EQ(rc, 0, "100 KiB header needs plaintext");
        TEST_ASSERT_EQ(rec_len, 0u, "100 KiB no reply on header");
        TEST_ASSERT_EQ(secure_otp_session_err(), 0u, "100 KiB open ok");

        while (off < LONG_MSG_LEN) {
            uint16_t take;
            uint32_t pos;
            uint16_t slot;
            uint16_t clen;

            take = plain_max;
            if (((uint32_t)take + off) > LONG_MSG_LEN) {
                take = (uint16_t)(LONG_MSG_LEN - off);
            }
            pattern_plaintext(pt, take, off);
            rec_len = 0U;
            rc = pump_otp_session(pt, (uint32_t)take, rec, (uint32_t)sizeof(rec), &rec_len);
            TEST_ASSERT(rec_len > 4U, "100 KiB pad reply");
            pos = 0U;
            if (hdr_done == 0U) {
                TEST_ASSERT_EQ(se_u32le(rec), n_need, "100 KiB n_pads");
                pos = 4U;
                hdr_done = 1U;
            }
            TEST_ASSERT((pos + 4U) <= rec_len, "100 KiB rec hdr");
            slot = se_u16le(rec + pos);
            clen = se_u16le(rec + pos + 2U);
            pos += 4U;
            TEST_ASSERT_EQ(slot, rec_i, "100 KiB logical");
            TEST_ASSERT_EQ(clen, take, "100 KiB chunk len");
            TEST_ASSERT_EQ(pos + (uint32_t)clen, rec_len, "100 KiB one record");
            pattern_keystream(pad, take, slot);
            for (i = 0; i < (int)take; i++) {
                TEST_ASSERT(rec[pos + (uint32_t)i] == (uint8_t)(pt[i] ^ pad[i]),
                            "100 KiB xor byte");
            }
            rec_i = (uint16_t)(rec_i + 1u);
            off += (uint32_t)take;
            if (off >= LONG_MSG_LEN) {
                TEST_ASSERT_EQ(rc, 1, "100 KiB session done");
            } else {
                TEST_ASSERT_EQ(rc, 0, "100 KiB more pads");
            }
        }
        TEST_ASSERT_EQ(rec_i, n_pads_u16, "100 KiB all pads");
        TEST_ASSERT_EQ(secure_otp_session_err(), 0u, "100 KiB no err");
    }
    secure_otp_session_reset();

    ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_ENCRYPT, &left_after);
    TEST_ASSERT_EQ(ret, LT_OK, "remaining after 100 KiB");
    TEST_ASSERT_EQ(left_after, left_before - (n_need * (uint32_t)plain_max),
                   "100 KiB burned whole pads");

    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &cursor_before);
    TEST_ASSERT_EQ(ret, LT_OK, "cursor after 100 KiB");
    {
        uint8_t over[1u + SE_TROPIC_PIN_SIZE_MAX + 4u];
        uint8_t err_reply[8];
        uint32_t over_len = 0U;
        uint32_t err_len = 0U;
        int rc;

        over[over_len++] = pin_len;
        (void)memcpy(over + over_len, pin, pin_len);
        over_len += (uint32_t)pin_len;
        se_append_u32le(over, &over_len, left_after + 1U);
        secure_otp_session_reset();
        secure_otp_session_begin(0U);
        rc = pump_otp_session(over, over_len, err_reply, (uint32_t)sizeof(err_reply), &err_len);
        TEST_ASSERT_EQ(rc, 1, "oversize session done");
        TEST_ASSERT_EQ(secure_otp_session_err(), SECURE_OTP_ERR_EXHAUSTED, "oversize err");
        TEST_ASSERT_EQ(err_len, 8u, "oversize err reply");
        TEST_ASSERT_EQ(se_u32le(err_reply), 0u, "oversize n_pads");
        TEST_ASSERT_EQ(se_u32le(err_reply + 4U), SECURE_OTP_ERR_EXHAUSTED, "oversize code");
        secure_otp_session_reset();
    }
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &cursor_after);
    TEST_ASSERT_EQ(ret, LT_OK, "cursor after oversize refuse");
    TEST_ASSERT_EQ(cursor_after, cursor_before, "refuse does not burn pads");

    wc_ForceZero(ss, sizeof(ss));
    wc_ForceZero(kem_ct, sizeof(kem_ct));
    return 0;
}

static int advance_until_one_pad(lt_handle_t *h, se_nv_otp_dir_t dir, uint32_t one_pad_bytes)
{
    uint32_t left = 0U;
    lt_ret_t ret;

    while (1) {
        ret = se_tropic_otp_bytes_remaining(h, dir, &left);
        TEST_ASSERT_EQ(ret, LT_OK, "remaining while advancing");
        if (left == one_pad_bytes) {
            return 0;
        }
        TEST_ASSERT(left > one_pad_bytes, "still have pads to burn");
        ret = se_tropic_qkd_cursor_advance(h, dir);
        TEST_ASSERT_EQ(ret, LT_OK, "advance toward last pad");
    }
}

static int test_otp_parse_pads(void)
{
    const uint16_t plain_max = 8U;
    uint8_t pt[20];
    uint8_t stream[4u + (4u + 8u) + (4u + 8u) + (4u + 4u)];
    uint8_t pads[3][8];
    uint16_t lens[3];
    uint16_t npads = 0U;
    const uint8_t *p;
    uint32_t left;
    uint32_t consumed = 0U;
    uint32_t st;
    uint32_t off;
    int i;

    for (i = 0; i < (int)sizeof(pt); i++) {
        pt[i] = (uint8_t)(0x40u + (uint8_t)i);
    }

    secure_otp_reset_pad();
    secure_otp_encrypt_begin_plaintext(plain_max, (uint32_t)sizeof(pt));
    st = secure_otp_read_pad(pt, (uint32_t)sizeof(pt), &consumed);
    TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "full-buffer first pad");
    TEST_ASSERT_EQ(consumed, (uint32_t)plain_max, "consumed one pad");
    {
        uint16_t take = 0U;
        uint8_t *chunk = secure_otp_pad_payload(&take);

        TEST_ASSERT(chunk != NULL, "chunk ptr");
        TEST_ASSERT_EQ(take, plain_max, "first take");
        TEST_ASSERT(memcmp(chunk, pt, plain_max) == 0, "first pad bytes");
    }
    secure_otp_pad_done();
    p = pt + consumed;
    left = (uint32_t)sizeof(pt) - consumed;
    st = parse_until_pad_ready(&p, &left);
    TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "second pad");
    {
        uint16_t take = 0U;
        uint8_t *chunk = secure_otp_pad_payload(&take);

        TEST_ASSERT_EQ(take, plain_max, "second take");
        TEST_ASSERT(memcmp(chunk, pt + plain_max, plain_max) == 0, "second pad bytes");
    }
    secure_otp_pad_done();
    st = parse_until_pad_ready(&p, &left);
    TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "short last pad");
    {
        uint16_t take = 0U;
        uint8_t *chunk = secure_otp_pad_payload(&take);

        TEST_ASSERT_EQ(take, 4u, "tail take");
        TEST_ASSERT(memcmp(chunk, pt + 16, 4) == 0, "tail bytes");
        TEST_ASSERT_EQ(left, 0u, "plaintext exhausted");
    }
    secure_otp_pad_done();

    secure_otp_encrypt_begin_plaintext(plain_max, (uint32_t)sizeof(pt));
    p = pt;
    left = (uint32_t)sizeof(pt);
    while (left > 0U) {
        uint16_t take = 0U;
        uint8_t *chunk;

        st = parse_until_pad_ready(&p, &left);
        TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "chunked pad ready");
        chunk = secure_otp_pad_payload(&take);
        TEST_ASSERT(chunk != NULL, "chunked chunk");
        TEST_ASSERT(npads < 3u, "pad cap");
        (void)memcpy(pads[npads], chunk, take);
        lens[npads] = take;
        npads = (uint16_t)(npads + 1u);
        secure_otp_pad_done();
    }
    TEST_ASSERT_EQ(npads, 3u, "three encrypt pads");
    TEST_ASSERT_EQ(lens[0], 8u, "pad0 len");
    TEST_ASSERT_EQ(lens[1], 8u, "pad1 len");
    TEST_ASSERT_EQ(lens[2], 4u, "pad2 len");

    {
        uint8_t plain_reply[4u + (2u + 8u) + (2u + 8u) + (2u + 4u)];
        uint8_t joined[20];
        uint32_t pos;
        uint32_t out_off = 0U;
        uint16_t clen;

        off = 0U;
        TEST_ASSERT(secure_otp_encode_n_pads(3u, plain_reply) == 0, "pt count");
        off = 4U;
        TEST_ASSERT(otp_append(plain_reply, (uint32_t)sizeof(plain_reply), &off, 1U, 0U, pads[0],
                               lens[0]) == 0,
                    "pt rec0");
        TEST_ASSERT(otp_append(plain_reply, (uint32_t)sizeof(plain_reply), &off, 1U, 0U, pads[1],
                               lens[1]) == 0,
                    "pt rec1");
        TEST_ASSERT(otp_append(plain_reply, (uint32_t)sizeof(plain_reply), &off, 1U, 0U, pads[2],
                               lens[2]) == 0,
                    "pt rec2");
        TEST_ASSERT_EQ(se_u32le(plain_reply), 3u, "pt n_pads");
        pos = 4U;
        while (out_off < (uint32_t)sizeof(pt)) {
            TEST_ASSERT((pos + 2U) <= off, "pt hdr");
            clen = se_u16le(plain_reply + pos);
            pos += 2U;
            TEST_ASSERT((clen > 0U) && ((pos + clen) <= off), "pt chunk");
            (void)memcpy(joined + out_off, plain_reply + pos, clen);
            out_off += clen;
            pos += clen;
        }
        TEST_ASSERT_EQ(pos, off, "pt reply exhausted");
        TEST_ASSERT(memcmp(joined, pt, sizeof(pt)) == 0, "pt joined");
    }

    {
        uint8_t err[8];

        TEST_ASSERT(secure_otp_encode_err(SECURE_OTP_ERR_EXHAUSTED, err) == 0, "err encode");
        TEST_ASSERT_EQ(se_u32le(err), 0u, "err n_pads");
        TEST_ASSERT_EQ(se_u32le(err + 4U), SECURE_OTP_ERR_EXHAUSTED, "err code");
    }

    off = 0U;
    TEST_ASSERT(secure_otp_encode_n_pads(3u, stream) == 0, "synth count");
    off = 4U;
    TEST_ASSERT(otp_append(stream, (uint32_t)sizeof(stream), &off, 0U, 0u, pads[0], lens[0]) == 0,
                "synth rec0");
    TEST_ASSERT(otp_append(stream, (uint32_t)sizeof(stream), &off, 0U, 1u, pads[1], lens[1]) == 0,
                "synth rec1");
    TEST_ASSERT(otp_append(stream, (uint32_t)sizeof(stream), &off, 0U, 2u, pads[2], lens[2]) == 0,
                "synth rec2");

    secure_otp_decrypt_begin_ciphertext(plain_max, 3u);
    p = stream + 4U;
    left = off - 4U;
    npads = 0U;
    while (left > 0U) {
        uint16_t take = 0U;
        uint8_t *chunk;

        st = parse_until_pad_ready(&p, &left);
        TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "decrypt pad ready");
        chunk = secure_otp_pad_payload(&take);
        TEST_ASSERT(chunk != NULL, "decrypt chunk");
        TEST_ASSERT_EQ(take, lens[npads], "decrypt take");
        TEST_ASSERT_EQ(secure_otp_decrypt_pad_slot(), npads, "decrypt slot");
        TEST_ASSERT(memcmp(chunk, pads[npads], take) == 0, "decrypt bytes");
        npads = (uint16_t)(npads + 1u);
        secure_otp_pad_done();
    }
    TEST_ASSERT_EQ(npads, 3u, "three decrypt pads");

    {
        uint8_t bad[4u + 7u];
        uint32_t bad_len = 0U;

        put_pad_rec(bad, &bad_len, 0u, pt, 7u);
        secure_otp_decrypt_begin_ciphertext(plain_max, 2u);
        consumed = 0U;
        st = secure_otp_read_pad(bad, bad_len, &consumed);
        TEST_ASSERT_EQ(st, SECURE_OTP_REQ_PARSE, "non-last short pad");
    }

    secure_otp_reset_pad();
    return 0;
}

int main(void)
{
    lt_handle_t *h;
    const uint8_t pin[] = {'9', '8', '7', '6', '5', '4', '3', '2'};
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint8_t kem_ct[SE_TROPIC_KEM_CT_LEN];
    uint8_t ss[SE_TROPIC_MLKEM_SS_LEN];
    uint8_t pending_fill[SE_NV_FILL_ID_LEN];
    uint8_t pad0[64];
    uint8_t nonce0[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t image0[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t image0_len = sizeof(image0);
    uint8_t msg[32];
    uint8_t out[32];
    uint8_t blob[16u + SE_TROPIC_KEM_CT_LEN + 2u * SE_TROPIC_RMEM_BLOB_MAX];
    uint8_t body[1u + 8u + 4u + 32u];
    uint8_t reply[128];
    static uint8_t pad_a[SE_TROPIC_RMEM_PLAIN_MAX];
    static uint8_t pad_b[SE_TROPIC_RMEM_PLAIN_MAX];
    static uint8_t msg2[SE_TROPIC_RMEM_PLAIN_MAX + 16u];
    static uint8_t out2[SE_TROPIC_RMEM_PLAIN_MAX + 16u];
    static uint8_t image_a[SE_TROPIC_RMEM_BLOB_MAX];
    static uint8_t image_b[SE_TROPIC_RMEM_BLOB_MAX];
    static uint8_t reply2[12u + 2u * SE_TROPIC_RMEM_PLAIN_MAX];
    uint16_t image_a_len;
    uint16_t image_b_len;
    uint16_t plain_max;
    uint32_t msg2_len;
    uint8_t nonce1[SE_TROPIC_RMEM_NONCE_LEN];
    uint32_t blob_len = 0U;
    uint32_t body_len = 0U;
    uint16_t pk_len = 0U;
    uint32_t st;
    uint32_t count = 0U;
    uint32_t cursor = 0U;
    uint32_t reply_off;
    lt_ret_t ret;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== I: encrypt TLS body + OTP reply ===\n");
    if (test_otp_parse_pads() != 0) {
        host_crypto_deinit();
        return 1;
    }

    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");
    {
        uint32_t left_enc = 1U;
        uint32_t left_dec = 1U;
        uint32_t cap_enc = 0U;
        uint32_t cap_dec = 0U;
        uint16_t pmax = se_tropic_get_rmem_slot_plaintext_max_size(h);

        if (pmax == 0U) {
            pmax = SE_TROPIC_RMEM_PLAIN_MAX;
        }
        ret = se_tropic_otp_bytes_quota(h, SE_NV_OTP_ENCRYPT, &left_enc, &cap_enc);
        TEST_ASSERT_EQ(ret, LT_OK, "encrypt quota before fill");
        TEST_ASSERT_EQ(left_enc, 0U, "encrypt empty before fill");
        TEST_ASSERT_EQ(cap_enc,
                       ((uint32_t)SE_TROPIC_PAD_COUNT - (uint32_t)SE_TROPIC_PAD_HALF) *
                           (uint32_t)pmax,
                       "encrypt default half capacity");
        ret = se_tropic_otp_bytes_quota(h, SE_NV_OTP_DECRYPT, &left_dec, &cap_dec);
        TEST_ASSERT_EQ(ret, LT_OK, "decrypt quota before fill");
        TEST_ASSERT_EQ(left_dec, 0U, "decrypt empty before fill");
        TEST_ASSERT_EQ(cap_dec, (uint32_t)SE_TROPIC_PAD_HALF * (uint32_t)pmax,
                       "decrypt default half capacity");
        st = se_tropic_otp_left_dump();
        TEST_ASSERT_EQ(st, SE_TROPIC_OK, "LEFT dump before fill is 0/capacity");
    }

    ret = se_tropic_mlkem_provision(h, pin, sizeof(pin), NULL, 0U, pk, sizeof(pk), &pk_len);
    TEST_ASSERT_EQ(ret, LT_OK, "mlkem provision");
    (void)memcpy(host_fw_mlkem_pk, pk, sizeof(pk));
    host_fw_mlkem_pk_len = SE_TROPIC_MLKEM_PK_LEN;

    /* PIN length 0 is rejected. */
    secure_otp_reset();
    {
        uint8_t bad[2] = {0, 0};
        uint32_t consumed = 0U;

        st = secure_otp_encrypt_parse_request(bad, 2U, &consumed);
        TEST_ASSERT_EQ(st, SECURE_OTP_REQ_PARSE, "zero pin_len rejected");
    }

    for (i = 0; i < (int)SE_NV_FILL_ID_LEN; i++) {
        pending_fill[i] = (uint8_t)(0x50u + (uint8_t)i);
    }
    se_nv_pending_fill_set(pending_fill);

    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate");

    for (i = 0; i < (int)sizeof(pad0); i++) {
        pad0[i] = (uint8_t)(0x11u + (uint8_t)i);
    }
    for (i = 0; i < (int)SE_TROPIC_RMEM_NONCE_LEN; i++) {
        nonce0[i] = (uint8_t)(0xA1u + (uint8_t)i);
    }
    image0_len = sizeof(image0);
    ret = seal_pad_pending(ss, pending_fill, 0u, pad0, (uint16_t)sizeof(pad0), nonce0, image0,
                           &image0_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad logical 0");

    blob_len = 0U;
    secure_lv_put_header(blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 3u);
    secure_lv_put_item(blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    {
        const uint8_t half = 1U;

        secure_lv_put_item(blob, &blob_len, &half, 1u);
    }
    secure_lv_put_item(blob, &blob_len, image0, image0_len);

    secure_qkd_discard();
    st = feed_qkd(blob, blob_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "chunked ingest");
    count = 0U;
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "FINISH ok");

    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &cursor);
    TEST_ASSERT_EQ(ret, LT_OK, "cursor after ingest");
    TEST_ASSERT_EQ(cursor, (uint32_t)SE_TROPIC_PAD_FIRST, "cursor still first pad");
    {
        uint32_t left_enc = 0U;
        uint32_t left_dec = 0U;
        uint16_t pmax = se_tropic_get_rmem_slot_plaintext_max_size(h);

        ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_ENCRYPT, &left_enc);
        TEST_ASSERT_EQ(ret, LT_OK, "encrypt remaining after ingest");
        TEST_ASSERT_EQ(left_enc, (uint32_t)SE_TROPIC_PAD_HALF * (uint32_t)pmax,
                       "encrypt remaining is pads * pad size");
        ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_DECRYPT, &left_dec);
        TEST_ASSERT_EQ(ret, LT_OK, "decrypt remaining after ingest");
        TEST_ASSERT_EQ(left_dec,
                       (uint32_t)(SE_TROPIC_PAD_COUNT - SE_TROPIC_PAD_HALF) * (uint32_t)pmax,
                       "decrypt remaining is pads * pad size");
    }

    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (uint8_t)(0xE1u + (uint8_t)i);
    }

    body_len = 0U;
    body[body_len++] = (uint8_t)sizeof(pin);
    (void)memcpy(body + body_len, pin, sizeof(pin));
    body_len += (uint32_t)sizeof(pin);
    se_append_u32le(body, &body_len, (uint32_t)sizeof(msg));
    (void)memcpy(body + body_len, msg, sizeof(msg));
    body_len += (uint32_t)sizeof(msg);

    secure_otp_session_reset();
    secure_otp_session_begin(0U);
    {
        int rc = pump_otp_session(body, body_len, reply, (uint32_t)sizeof(reply), &reply_off);

        TEST_ASSERT_EQ(rc, 1, "32 B session done");
        TEST_ASSERT_EQ(secure_otp_session_err(), 0u, "32 B no err");
    }
    secure_otp_session_reset();
    TEST_ASSERT(reply_off == (4U + 4U + sizeof(out)), "otp stream size");
    TEST_ASSERT_EQ(se_u32le(reply), 1u, "n_pads");
    TEST_ASSERT_EQ(se_u16le(reply + 4), 0u, "slot 0");
    TEST_ASSERT_EQ(se_u16le(reply + 6), (uint16_t)sizeof(out), "chunk length");
    (void)memcpy(out, reply + 8, sizeof(out));
    for (i = 0; i < (int)sizeof(msg); i++) {
        TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad0[i]), "otp xor pad0");
    }
    {
        uint16_t decoded_slots[4];
        uint16_t decoded_n = 0U;
        uint8_t decoded_ct[32];
        uint32_t decoded_ct_len = 0U;
        uint32_t cursor_after = 0U;

        TEST_ASSERT(encrypt_parse_reply(reply, reply_off, decoded_slots,
                                        (uint16_t)(sizeof(decoded_slots) / sizeof(decoded_slots[0])),
                                        &decoded_n, decoded_ct, sizeof(decoded_ct),
                                        &decoded_ct_len) == 0,
                    "otp decode");
        TEST_ASSERT_EQ(decoded_n, 1u, "decoded one slot");
        TEST_ASSERT_EQ(decoded_slots[0], 0u, "decoded slot 0");
        TEST_ASSERT_EQ(decoded_ct_len, (uint32_t)sizeof(out), "decoded ct len");
        TEST_ASSERT(memcmp(decoded_ct, out, sizeof(out)) == 0, "decoded ct bytes");
        ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &cursor_after);
        TEST_ASSERT_EQ(ret, LT_OK, "cursor after 32 B");
        TEST_ASSERT_EQ(cursor_after, (uint32_t)SE_TROPIC_PAD_FIRST + 1U, "burned first pad");
    }

    /* Two Tropic pads: leftover ingest, two reply records. */
    printf("--- I: two-pad stream ---\n");
    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    TEST_ASSERT(plain_max > 16U, "plain_max for two pads");
    msg2_len = (uint32_t)plain_max + 10U;
    for (i = 0; i < (int)SE_NV_FILL_ID_LEN; i++) {
        pending_fill[i] = (uint8_t)(0x61u + (uint8_t)i);
    }
    se_nv_pending_fill_set(pending_fill);
    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate two-pad");
    for (i = 0; i < (int)plain_max; i++) {
        pad_a[i] = (uint8_t)(0x21u + (uint8_t)i);
        pad_b[i] = (uint8_t)(0x31u + (uint8_t)i);
    }
    for (i = 0; i < (int)SE_TROPIC_RMEM_NONCE_LEN; i++) {
        nonce0[i] = (uint8_t)(0xB1u + (uint8_t)i);
        nonce1[i] = (uint8_t)(0xC1u + (uint8_t)i);
    }
    image_a_len = sizeof(image_a);
    ret = seal_pad_pending(ss, pending_fill, 0u, pad_a, plain_max, nonce0, image_a, &image_a_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad A");
    image_b_len = sizeof(image_b);
    ret = seal_pad_pending(ss, pending_fill, 1u, pad_b, plain_max, nonce1, image_b, &image_b_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad B");

    blob_len = 0U;
    secure_lv_put_header(blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 4u);
    secure_lv_put_item(blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    {
        const uint8_t half = 1U;

        secure_lv_put_item(blob, &blob_len, &half, 1u);
    }
    secure_lv_put_item(blob, &blob_len, image_a, image_a_len);
    secure_lv_put_item(blob, &blob_len, image_b, image_b_len);
    TEST_ASSERT(blob_len <= (uint32_t)sizeof(blob), "two-pad LV fits");

    secure_qkd_discard();
    st = feed_qkd(blob, blob_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "two-pad ingest");
    count = 0U;
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "two-pad FINISH");

    for (i = 0; i < (int)msg2_len; i++) {
        msg2[i] = (uint8_t)(0x80u + (uint8_t)i);
    }
    {
        uint8_t req2[1u + 8u + 4u + SE_TROPIC_RMEM_PLAIN_MAX + 16u];
        uint32_t req2_len = 0U;
        int rc;

        req2[req2_len++] = (uint8_t)sizeof(pin);
        (void)memcpy(req2 + req2_len, pin, sizeof(pin));
        req2_len += (uint32_t)sizeof(pin);
        se_append_u32le(req2, &req2_len, msg2_len);
        (void)memcpy(req2 + req2_len, msg2, msg2_len);
        req2_len += msg2_len;
        TEST_ASSERT(req2_len <= (uint32_t)sizeof(req2), "two-pad request fits");

        secure_otp_session_reset();
        secure_otp_session_begin(0U);
        rc = pump_otp_session(req2, req2_len, reply2, (uint32_t)sizeof(reply2), &reply_off);
        TEST_ASSERT_EQ(rc, 1, "two-pad session done");
        TEST_ASSERT_EQ(secure_otp_session_err(), 0u, "two-pad no err");
        secure_otp_session_reset();
        TEST_ASSERT(reply_off <= (uint32_t)sizeof(reply2), "two-pad reply fits");
        TEST_ASSERT_EQ(se_u32le(reply2), 2u, "two-pad n_pads");
    }
    {
        uint16_t decoded_slots[4];
        uint16_t decoded_n = 0U;
        uint32_t decoded_ct_len = 0U;

        TEST_ASSERT(encrypt_parse_reply(reply2, reply_off, decoded_slots,
                                        (uint16_t)(sizeof(decoded_slots) / sizeof(decoded_slots[0])),
                                        &decoded_n, out2, msg2_len, &decoded_ct_len) == 0,
                    "two-pad decode");
        TEST_ASSERT_EQ(decoded_n, 2u, "decoded two slots");
        TEST_ASSERT_EQ(decoded_slots[0], 0u, "decoded slot 0");
        TEST_ASSERT_EQ(decoded_slots[1], 1u, "decoded slot 1");
        TEST_ASSERT_EQ(decoded_ct_len, msg2_len, "decoded two-pad len");
        {
            uint16_t j;

            for (j = 0U; j < (uint16_t)msg2_len; j++) {
                uint8_t ks = (j < plain_max) ? pad_a[j] : pad_b[j - plain_max];

                TEST_ASSERT(out2[j] == (uint8_t)(msg2[j] ^ ks), "two-pad xor byte");
            }
        }
    }
    {
        const uint8_t *p = reply2 + 4U;
        uint32_t left = reply_off - 4U;

        secure_otp_decrypt_begin_ciphertext(plain_max, 2u);
        st = parse_until_pad_ready(&p, &left);
        TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "decrypt rec0");
        TEST_ASSERT_EQ(secure_otp_decrypt_pad_slot(), 0u, "decrypt slot 0");
        secure_otp_pad_done();
        st = parse_until_pad_ready(&p, &left);
        TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "decrypt rec1");
        TEST_ASSERT_EQ(secure_otp_decrypt_pad_slot(), 1u, "decrypt slot 1");
        TEST_ASSERT_EQ(left, 0u, "decrypt stream exhausted");
        secure_otp_pad_done();
    }

    printf("--- I: decrypt skip-ahead ---\n");
    for (i = 0; i < (int)SE_NV_FILL_ID_LEN; i++) {
        pending_fill[i] = (uint8_t)(0x71u + (uint8_t)i);
    }
    se_nv_pending_fill_set(pending_fill);
    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate skip");
    for (i = 0; i < 32; i++) {
        pad_a[i] = (uint8_t)(0xA0u + (uint8_t)i);
        pad_b[i] = (uint8_t)(0xB0u + (uint8_t)i);
    }
    for (i = 0; i < (int)SE_TROPIC_RMEM_NONCE_LEN; i++) {
        nonce0[i] = (uint8_t)(0xD1u + (uint8_t)i);
        nonce1[i] = (uint8_t)(0xE1u + (uint8_t)i);
    }
    image_a_len = sizeof(image_a);
    ret = seal_pad_pending(ss, pending_fill, 0u, pad_a, 32u, nonce0, image_a, &image_a_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal skip pad0");
    image_b_len = sizeof(image_b);
    ret = seal_pad_pending(ss, pending_fill, 2u, pad_b, 32u, nonce1, image_b, &image_b_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal skip pad2");

    blob_len = 0U;
    secure_lv_put_header(blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 5u);
    secure_lv_put_item(blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    {
        const uint8_t half = 0U;

        secure_lv_put_item(blob, &blob_len, &half, 1u);
    }
    secure_lv_put_item(blob, &blob_len, image_a, image_a_len);
    secure_lv_put_item(blob, &blob_len, NULL, 0u);
    secure_lv_put_item(blob, &blob_len, image_b, image_b_len);
    TEST_ASSERT(blob_len <= (uint32_t)sizeof(blob), "skip LV fits");

    secure_qkd_discard();
    st = feed_qkd(blob, blob_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "skip ingest");
    count = 0U;
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "skip FINISH");

    {
        uint8_t dreq[1u + 8u + 4u + 4u + 32u];
        uint8_t drep[4u + 2u + 32u];
        uint32_t dreq_len = 0U;
        uint32_t drep_len = 0U;
        uint32_t skip_cur = 0U;
        int rc;

        dreq[dreq_len++] = (uint8_t)sizeof(pin);
        (void)memcpy(dreq + dreq_len, pin, sizeof(pin));
        dreq_len += (uint32_t)sizeof(pin);
        se_append_u32le(dreq, &dreq_len, 1U);
        se_append_u16le(dreq, &dreq_len, 2U);
        se_append_u16le(dreq, &dreq_len, 32U);
        for (i = 0; i < 32; i++) {
            dreq[dreq_len++] = (uint8_t)(0x5Au ^ pad_b[i]);
        }

        secure_otp_session_reset();
        secure_otp_session_begin(1U);
        rc = pump_otp_session(dreq, dreq_len, drep, (uint32_t)sizeof(drep), &drep_len);
        TEST_ASSERT_EQ(rc, 1, "decrypt skip session done");
        TEST_ASSERT_EQ(secure_otp_session_err(), 0u, "decrypt skip no err");
        secure_otp_session_reset();
        TEST_ASSERT_EQ(drep_len, 4U + 2U + 32U, "decrypt skip reply size");
        TEST_ASSERT_EQ(se_u32le(drep), 1u, "decrypt skip n_pads");
        TEST_ASSERT_EQ(se_u16le(drep + 4), 32u, "decrypt skip chunk");
        for (i = 0; i < 32; i++) {
            TEST_ASSERT(drep[6 + i] == (uint8_t)(0x5Au), "skip xor recovered pad2");
        }
        ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_DECRYPT, &skip_cur);
        TEST_ASSERT_EQ(ret, LT_OK, "cursor after skip");
        TEST_ASSERT_EQ(skip_cur, (uint32_t)(SE_TROPIC_PAD_FIRST + 3u), "cursor past burned pads");
        {
            uint8_t raw[SE_TROPIC_RMEM_BLOB_MAX];
            uint16_t raw_len = 0U;

            ret = lt_r_mem_data_read(h, SE_TROPIC_PAD_FIRST, raw, sizeof(raw), &raw_len);
            TEST_ASSERT_EQ(ret, LT_L3_R_MEM_DATA_READ_SLOT_EMPTY, "skipped pad0 burned");
        }
    }

    TEST_ASSERT(test_long_encrypt(h, pin, (uint8_t)sizeof(pin), pk) == 0, "100 KiB encrypt");

    printf("--- I: almost-empty encrypt/decrypt refuse ---\n");
    for (i = 0; i < (int)SE_NV_FILL_ID_LEN; i++) {
        pending_fill[i] = (uint8_t)(0x81u + (uint8_t)i);
    }
    se_nv_pending_fill_set(pending_fill);
    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate empty");
    blob_len = 0U;
    secure_lv_put_header(blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 3u);
    secure_lv_put_item(blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    {
        const uint8_t half = 1U;

        secure_lv_put_item(blob, &blob_len, &half, 1u);
    }
    secure_lv_put_item(blob, &blob_len, image0, image0_len);
    secure_qkd_discard();
    st = feed_qkd(blob, blob_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "empty ingest");
    count = 0U;
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "empty FINISH");
    {
        uint16_t pmax = se_tropic_get_rmem_slot_plaintext_max_size(h);
        uint32_t two = (uint32_t)pmax * 2U;
        uint32_t left = 0U;

        TEST_ASSERT(advance_until_one_pad(h, SE_NV_OTP_ENCRYPT, (uint32_t)pmax) == 0,
                    "encrypt one pad left");
        ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_ENCRYPT, &left);
        TEST_ASSERT_EQ(ret, LT_OK, "encrypt remaining one pad");
        TEST_ASSERT_EQ(left, (uint32_t)pmax, "encrypt almost empty");
        {
            uint8_t req[1u + 8u + 4u];
            uint8_t err_reply[8];
            uint32_t req_len;
            uint32_t err_len;
            int rc;

            req_len = 0U;
            req[req_len++] = (uint8_t)sizeof(pin);
            (void)memcpy(req + req_len, pin, sizeof(pin));
            req_len += (uint32_t)sizeof(pin);
            se_append_u32le(req, &req_len, two);
            secure_otp_session_reset();
            secure_otp_session_begin(0U);
            rc = pump_otp_session(req, req_len, err_reply, (uint32_t)sizeof(err_reply), &err_len);
            TEST_ASSERT_EQ(rc, 1, "encrypt over-consume done");
            TEST_ASSERT_EQ(secure_otp_session_err(), SECURE_OTP_ERR_EXHAUSTED, "encrypt over-consume");
            TEST_ASSERT_EQ(err_len, 8u, "encrypt over-consume reply");
            TEST_ASSERT_EQ(se_u32le(err_reply + 4U), SECURE_OTP_ERR_EXHAUSTED, "encrypt over code");
            secure_otp_session_reset();

            req_len = 0U;
            req[req_len++] = (uint8_t)sizeof(pin);
            (void)memcpy(req + req_len, pin, sizeof(pin));
            req_len += (uint32_t)sizeof(pin);
            se_append_u32le(req, &req_len, LONG_MSG_LEN);
            secure_otp_session_begin(0U);
            err_len = 0U;
            rc = pump_otp_session(req, req_len, err_reply, (uint32_t)sizeof(err_reply), &err_len);
            TEST_ASSERT_EQ(rc, 1, "100 KiB over one pad done");
            TEST_ASSERT_EQ(secure_otp_session_err(), SECURE_OTP_ERR_EXHAUSTED,
                           "100 KiB over one pad refuses");
            secure_otp_session_reset();
        }
        ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_ENCRYPT, &left);
        TEST_ASSERT_EQ(ret, LT_OK, "encrypt remaining after 100 KiB refuse");
        TEST_ASSERT_EQ(left, (uint32_t)pmax, "refuse left the last pad");

        TEST_ASSERT(advance_until_one_pad(h, SE_NV_OTP_DECRYPT, (uint32_t)pmax) == 0,
                    "decrypt one pad left");
        ret = se_tropic_otp_bytes_remaining(h, SE_NV_OTP_DECRYPT, &left);
        TEST_ASSERT_EQ(ret, LT_OK, "decrypt remaining one pad");
        TEST_ASSERT_EQ(left, (uint32_t)pmax, "decrypt almost empty");
        {
            uint8_t req[1u + 8u + 4u];
            uint8_t err_reply[8];
            uint32_t req_len = 0U;
            uint32_t err_len = 0U;
            int rc;

            req[req_len++] = (uint8_t)sizeof(pin);
            (void)memcpy(req + req_len, pin, sizeof(pin));
            req_len += (uint32_t)sizeof(pin);
            se_append_u32le(req, &req_len, 2U);
            secure_otp_session_reset();
            secure_otp_session_begin(1U);
            rc = pump_otp_session(req, req_len, err_reply, (uint32_t)sizeof(err_reply), &err_len);
            TEST_ASSERT_EQ(rc, 1, "decrypt over-consume done");
            TEST_ASSERT_EQ(secure_otp_session_err(), SECURE_OTP_ERR_EXHAUSTED, "decrypt over-consume");
            secure_otp_session_reset();
        }
    }

    secure_otp_session_reset();
    wc_ForceZero(ss, sizeof(ss));
    wc_ForceZero(kem_ct, sizeof(kem_ct));
    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS I\n");
    return 0;
}
