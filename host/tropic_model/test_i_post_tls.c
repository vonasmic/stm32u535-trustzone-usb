/**
 * @file    test_i_post_tls.c
 * @brief   Group I: encrypt-mode PIN+plaintext body and OTP reply slots
 *
 * No wolfSSL client. After a G-style QKD load, parse the TLS encrypt header
 * (u8 pin_len | pin | u32 LE msg_len) then plaintext; reply is n_pads + records.
 * XOR each pad, and encode the OTP pad-record reply. Also covers leftover
 * TLS bytes and a two-pad Tropic XOR.
 */
#include "test_harness.h"
#include "secure_qkd_ingest.h"
#include "secure_otp.h"
#include "secure_lv.h"
#include "se_le.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "host_fw_mlkem.h"
#include "libtropic.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#define CHUNK_SIZE 7u

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

/** Parse PIN + length field from @p blob in CHUNK_SIZE slices. */
static uint32_t parse_request_in_chunks(const uint8_t *blob, uint32_t blob_len, uint8_t decrypt)
{
    uint32_t off = 0U;
    uint32_t st = SECURE_OTP_REQ_OK;

    while (off < blob_len) {
        uint32_t take = blob_len - off;
        uint32_t consumed = 0U;

        if (take > CHUNK_SIZE) {
            take = CHUNK_SIZE;
        }
        if (decrypt != 0U) {
            st = secure_otp_decrypt_parse_request(blob + off, take, &consumed);
        } else {
            st = secure_otp_encrypt_parse_request(blob + off, take, &consumed);
        }
        if (consumed == 0U) {
            return SECURE_OTP_REQ_PARSE;
        }
        off += consumed;
        if (st == SECURE_OTP_REQ_COMPLETE) {
            return st;
        }
        if (st != SECURE_OTP_REQ_OK) {
            return st;
        }
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

/** Pad-at-a-time assembler without Tropic: plaintext encrypt, record decrypt. */
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
    const uint8_t pin[] = {9, 8, 7, 6};
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
    uint16_t slot_used = 0U;
    uint16_t logical_slots[4];
    uint16_t slots_n = 0U;
    uint32_t st;
    uint32_t count = 0U;
    uint32_t cursor = 0U;
    uint8_t pin_len = 0U;
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

    secure_otp_reset();
    st = parse_request_in_chunks(body, body_len, 0U);
    TEST_ASSERT_EQ(st, SECURE_OTP_REQ_COMPLETE, "encrypt header complete");
    TEST_ASSERT(secure_otp_request_pin(&pin_len) != NULL, "pin ptr");
    TEST_ASSERT_EQ(pin_len, (uint8_t)sizeof(pin), "pin len");
    TEST_ASSERT_EQ(secure_otp_encrypt_msg_len(), (uint32_t)sizeof(msg), "msg_len");

    ret = se_tropic_otp_xor_open(h, secure_otp_request_pin(&pin_len), pin_len, NULL, 0U,
                                     SE_NV_OTP_ENCRYPT, (uint32_t)sizeof(msg), 0U);
    TEST_ASSERT_EQ(ret, LT_OK, "stream begin");
    TEST_ASSERT_EQ(se_tropic_otp_xor_pads_needed(), 1u, "one pad needed");
    secure_otp_encrypt_begin_plaintext(se_tropic_otp_xor_pad_max(), (uint32_t)sizeof(msg));
    {
        const uint8_t *p = body + 1U + sizeof(pin) + 4U;
        uint32_t left = (uint32_t)sizeof(msg);
        uint8_t *chunk;
        uint16_t take = 0U;
        uint16_t logical = 0U;

        st = parse_until_pad_ready(&p, &left);
        TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "32 B pad ready");
        TEST_ASSERT_EQ(left, 0u, "single pad leftover empty");
        chunk = secure_otp_pad_payload(&take);
        TEST_ASSERT(chunk != NULL, "payload chunk");
        TEST_ASSERT_EQ(take, (uint16_t)sizeof(msg), "take 32");
        ret = se_tropic_otp_xor_pad(h, NULL, chunk, take, chunk, &logical, &slot_used);
        TEST_ASSERT_EQ(ret, LT_OK, "stream pad");
        TEST_ASSERT_EQ(slot_used, SE_TROPIC_PAD_FIRST, "first physical pad");
        TEST_ASSERT_EQ(logical, 0u, "logical 0");
        logical_slots[0] = logical;
        slots_n = 1U;
        (void)memcpy(out, chunk, take);
        for (i = 0; i < (int)sizeof(msg); i++) {
            TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad0[i]), "otp xor pad0");
        }

        reply_off = 0U;
        TEST_ASSERT(secure_otp_encode_n_pads(1u, reply) == 0, "otp count");
        reply_off = 4U;
        TEST_ASSERT(otp_append(reply, (uint32_t)sizeof(reply), &reply_off, 0U, logical, chunk,
                               take) == 0,
                    "otp record");
        secure_otp_pad_done();
        TEST_ASSERT_EQ(se_tropic_otp_xor_bytes_left(), 0u, "stream done");
        se_tropic_otp_xor_close();
    }
    TEST_ASSERT_EQ(slots_n, 1u, "one logical slot");
    TEST_ASSERT(reply_off == (4U + 4U + sizeof(out)), "otp stream size");
    TEST_ASSERT_EQ(se_u32le(reply), 1u, "n_pads");
    TEST_ASSERT_EQ(se_u16le(reply + 4), 0u, "slot 0");
    TEST_ASSERT_EQ(se_u16le(reply + 6), (uint16_t)sizeof(out),
                   "chunk length");
    TEST_ASSERT(memcmp(reply + 8, out, sizeof(out)) == 0, "ct bytes");
    {
        uint16_t decoded_slots[4];
        uint16_t decoded_n = 0U;
        uint8_t decoded_ct[32];
        uint32_t decoded_ct_len = 0U;

        TEST_ASSERT(encrypt_parse_reply(reply, reply_off, decoded_slots,
                                        (uint16_t)(sizeof(decoded_slots) / sizeof(decoded_slots[0])),
                                        &decoded_n, decoded_ct, sizeof(decoded_ct),
                                        &decoded_ct_len) == 0,
                    "otp decode");
        TEST_ASSERT_EQ(decoded_n, 1u, "decoded one slot");
        TEST_ASSERT_EQ(decoded_slots[0], 0u, "decoded slot 0");
        TEST_ASSERT_EQ(decoded_ct_len, (uint32_t)sizeof(out), "decoded ct len");
        TEST_ASSERT(memcmp(decoded_ct, out, sizeof(out)) == 0, "decoded ct bytes");
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
    ret = se_tropic_otp_xor_open(h, pin, sizeof(pin), NULL, 0U, SE_NV_OTP_ENCRYPT, msg2_len, 0U);
    TEST_ASSERT_EQ(ret, LT_OK, "two-pad begin");
    TEST_ASSERT_EQ(se_tropic_otp_xor_pads_needed(), 2u, "two pads needed");
    TEST_ASSERT_EQ(se_tropic_otp_xor_pad_max(), plain_max, "stream plain_max");
    secure_otp_encrypt_begin_plaintext(plain_max, msg2_len);
    {
        const uint8_t *p = msg2;
        uint32_t left = msg2_len;
        uint16_t rec = 0U;
        uint32_t msg_off = 0U;

        reply_off = 0U;
        TEST_ASSERT(secure_otp_encode_n_pads(2u, reply2) == 0, "two-pad count");
        reply_off = 4U;

        while (left > 0U) {
            uint8_t *chunk;
            uint16_t take = 0U;
            uint16_t logical = 0U;
            uint16_t j;

            st = parse_until_pad_ready(&p, &left);
            TEST_ASSERT_EQ(st, SECURE_OTP_PAD_READY, "two-pad ready");
            chunk = secure_otp_pad_payload(&take);
            TEST_ASSERT(chunk != NULL, "two-pad chunk");
            ret = se_tropic_otp_xor_pad(h, NULL, chunk, take, chunk, &logical, NULL);
            TEST_ASSERT_EQ(ret, LT_OK, "two-pad xor");
            TEST_ASSERT_EQ(logical, rec, "two-pad logical");
            for (j = 0U; j < take; j++) {
                uint8_t expect = (uint8_t)(msg2[msg_off + j] ^ ((rec == 0U) ? pad_a[j] : pad_b[j]));

                TEST_ASSERT(chunk[j] == expect, "two-pad xor byte");
            }
            TEST_ASSERT(otp_append(reply2, (uint32_t)sizeof(reply2), &reply_off, 0U, logical, chunk,
                                   take) == 0,
                        "two-pad record");
            (void)memcpy(out2 + msg_off, chunk, take);
            msg_off += take;
            rec = (uint16_t)(rec + 1u);
            secure_otp_pad_done();
        }
        TEST_ASSERT_EQ(rec, 2u, "two records");
        TEST_ASSERT_EQ(se_tropic_otp_xor_bytes_left(), 0u, "two-pad remaining");
        TEST_ASSERT(reply_off <= (uint32_t)sizeof(reply2), "two-pad reply fits");
        se_tropic_otp_xor_close();
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

    secure_otp_reset();
    wc_ForceZero(ss, sizeof(ss));
    wc_ForceZero(kem_ct, sizeof(kem_ct));
    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS I\n");
    return 0;
}
