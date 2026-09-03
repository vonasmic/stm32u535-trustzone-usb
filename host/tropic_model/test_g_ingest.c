/**
 * @file    test_g_ingest.c
 * @brief   Group G: secure_qkd_ingest stores kem_ct + decrypt_half + pads on Tropic
 *
 * Builds a v2 LV downlink (SAE role), feeds it in small chunks, and checks
 * that FINISH commits the pending fill_id and OTP can consume pad 0. Also
 * covers decrypt skip-ahead and rewind-fail with decrypt_half=0.
 */
#include "test_harness.h"
#include "secure_qkd_ingest.h"
#include "secure_lv.h"
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

#define CHUNK_SIZE 17u

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

/** Seal a pad under a known fill_id (pending, not yet committed). */
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

static uint32_t feed_chunks(const uint8_t *blob, uint32_t blob_len)
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

int main(void)
{
    lt_handle_t *h;
    const uint8_t pin[] = {9, 8, 7, 6};
    const uint8_t add[] = {0xde, 0xad};
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint8_t kem_ct[SE_TROPIC_KEM_CT_LEN];
    uint8_t ss[SE_TROPIC_MLKEM_SS_LEN];
    uint8_t pending_fill[SE_NV_FILL_ID_LEN];
    uint8_t committed_fill[SE_NV_FILL_ID_LEN];
    uint8_t pad0[64];
    uint8_t pad2[64];
    uint8_t nonce0[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t nonce2[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t image0[SE_TROPIC_RMEM_BLOB_MAX];
    uint8_t image2[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t image0_len = sizeof(image0);
    uint16_t image2_len = sizeof(image2);
    uint8_t msg[32];
    uint8_t out[32];
    /* version + count + kem_ct + half + pad0 + empty + pad2 */
    uint8_t blob[3u + 3u + SE_TROPIC_KEM_CT_LEN + 2u * (2u + SE_TROPIC_RMEM_BLOB_MAX) + 2u];
    uint8_t bad_blob[64];
    uint32_t blob_len = 0U;
    uint32_t bad_len = 0U;
    uint16_t pk_len = 0U;
    uint16_t slot_used = 0U;
    uint16_t req_slots[4];
    uint32_t enc_cur = 0U;
    uint32_t dec_cur = 0U;
    uint32_t st;
    uint32_t count = 0U;
    lt_ret_t ret;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== G: QKD ingest store ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    ret = se_tropic_mlkem_provision(h, pin, sizeof(pin), add, sizeof(add), pk, sizeof(pk), &pk_len);
    TEST_ASSERT_EQ(ret, LT_OK, "mlkem provision");
    TEST_ASSERT_EQ(pk_len, SE_TROPIC_MLKEM_PK_LEN, "pk len");
    (void)memcpy(host_fw_mlkem_pk, pk, sizeof(pk));
    host_fw_mlkem_pk_len = SE_TROPIC_MLKEM_PK_LEN;

    /* --- Bad item 0 length: must not commit a fill --- */
    secure_qkd_discard();
    bad_len = 0U;
    secure_lv_put_header(bad_blob, &bad_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 1u);
    secure_lv_put_item(bad_blob, &bad_len, (const uint8_t *)"short", 5u);
    st = feed_chunks(bad_blob, bad_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_PARSE, "short kem_ct is PARSE");
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_PARSE, "FINISH after bad item 0");
    TEST_ASSERT(se_nv_have_fill() == 0, "no fill after bad item 0");

    /* --- Happy path: pending fill_id + LV with hole --- */
    for (i = 0; i < (int)SE_NV_FILL_ID_LEN; i++) {
        pending_fill[i] = (uint8_t)(0x40u + (uint8_t)i);
    }
    se_nv_pending_fill_set(pending_fill);

    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate");

    for (i = 0; i < (int)sizeof(pad0); i++) {
        pad0[i] = (uint8_t)(0x10u + (uint8_t)i);
        pad2[i] = (uint8_t)(0x20u + (uint8_t)i);
    }
    for (i = 0; i < (int)SE_TROPIC_RMEM_NONCE_LEN; i++) {
        nonce0[i] = (uint8_t)(0xA0u + (uint8_t)i);
        nonce2[i] = (uint8_t)(0xC0u + (uint8_t)i);
    }

    image0_len = sizeof(image0);
    ret = seal_pad_pending(ss, pending_fill, 0u, pad0, (uint16_t)sizeof(pad0), nonce0, image0,
                           &image0_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad logical 0");
    image2_len = sizeof(image2);
    ret = seal_pad_pending(ss, pending_fill, 2u, pad2, (uint16_t)sizeof(pad2), nonce2, image2,
                           &image2_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad logical 2");

    blob_len = 0U;
    secure_lv_put_header(blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 5u);
    secure_lv_put_item(blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    {
        const uint8_t half = 1U;

        secure_lv_put_item(blob, &blob_len, &half, 1u);
    }
    secure_lv_put_item(blob, &blob_len, image0, image0_len);
    secure_lv_put_item(blob, &blob_len, NULL, 0u);
    secure_lv_put_item(blob, &blob_len, image2, image2_len);

    secure_qkd_discard();
    st = feed_chunks(blob, blob_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "chunked ingest");
    count = 0U;
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "FINISH ok");
    TEST_ASSERT_EQ(count, 5u, "LV item count");

    TEST_ASSERT(se_nv_have_fill() != 0, "fill committed");
    ret = se_nv_get_fill_id(committed_fill);
    TEST_ASSERT_EQ(ret, LT_OK, "get committed fill_id");
    TEST_ASSERT(memcmp(committed_fill, pending_fill, SE_NV_FILL_ID_LEN) == 0,
                "committed fill_id matches pending");

    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (uint8_t)(0xE0u + (uint8_t)i);
    }
    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, LT_OK, "otp consume pad 0");
    TEST_ASSERT_EQ(slot_used, SE_TROPIC_PAD_FIRST, "otp from first pad");
    for (i = 0; i < (int)sizeof(msg); i++) {
        TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad0[i]), "otp xor pad0");
    }

    /* decrypt_half=0: encrypt uses second half; decrypt skip-ahead / rewind-fail */
    for (i = 0; i < (int)SE_NV_FILL_ID_LEN; i++) {
        pending_fill[i] = (uint8_t)(0x70u + (uint8_t)i);
    }
    se_nv_pending_fill_set(pending_fill);
    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate half0");
    image0_len = sizeof(image0);
    ret = seal_pad_pending(ss, pending_fill, 0u, pad0, (uint16_t)sizeof(pad0), nonce0, image0,
                           &image0_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad0 half0");
    image2_len = sizeof(image2);
    ret = seal_pad_pending(ss, pending_fill, 2u, pad2, (uint16_t)sizeof(pad2), nonce2, image2,
                           &image2_len);
    TEST_ASSERT_EQ(ret, LT_OK, "seal pad2 half0");

    blob_len = 0U;
    secure_lv_put_header(blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, 5u);
    secure_lv_put_item(blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    {
        const uint8_t half = 0U;

        secure_lv_put_item(blob, &blob_len, &half, 1u);
    }
    secure_lv_put_item(blob, &blob_len, image0, image0_len);
    secure_lv_put_item(blob, &blob_len, NULL, 0u);
    secure_lv_put_item(blob, &blob_len, image2, image2_len);

    secure_qkd_discard();
    st = feed_chunks(blob, blob_len);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "ingest half0");
    count = 0U;
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "FINISH half0");

    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &enc_cur);
    TEST_ASSERT_EQ(ret, LT_OK, "encrypt cursor half0");
    TEST_ASSERT_EQ(enc_cur, (uint32_t)(SE_TROPIC_PAD_FIRST + SE_TROPIC_PAD_HALF),
                  "encrypt at second half");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_DECRYPT, &dec_cur);
    TEST_ASSERT_EQ(ret, LT_OK, "decrypt cursor half0");
    TEST_ASSERT_EQ(dec_cur, (uint32_t)SE_TROPIC_PAD_FIRST, "decrypt at first pad");

    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT(ret != LT_OK, "encrypt does not consume first-half pads");

    req_slots[0] = 0U;
    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                     SE_NV_OTP_DECRYPT, req_slots, 1U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, LT_OK, "decrypt slot 0");
    TEST_ASSERT_EQ(slot_used, SE_TROPIC_PAD_FIRST, "decrypt physical 0");
    for (i = 0; i < (int)sizeof(msg); i++) {
        TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad0[i]), "decrypt xor pad0");
    }

    req_slots[0] = 0U;
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                     SE_NV_OTP_DECRYPT, req_slots, 1U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT(ret != LT_OK, "decrypt rewind refused");

    req_slots[0] = 2U;
    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                     SE_NV_OTP_DECRYPT, req_slots, 1U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, LT_OK, "decrypt skip-ahead to slot 2");
    TEST_ASSERT_EQ(slot_used, (uint16_t)(SE_TROPIC_PAD_FIRST + 2u), "skipped to pad2");
    for (i = 0; i < (int)sizeof(msg); i++) {
        TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad2[i]), "decrypt xor pad2");
    }

    wc_ForceZero(ss, sizeof(ss));
    wc_ForceZero(kem_ct, sizeof(kem_ct));
    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS G\n");
    return 0;
}
