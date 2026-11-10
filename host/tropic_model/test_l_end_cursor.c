/**
 * @file    test_l_end_cursor.c
 * @brief   Group L: per-half end (write) cursors mirrored in MCU NV + Tropic mcounters 2/3
 *
 * Partial fill -> OTP STATUS quota shows the exact written count; consuming
 * past the end gives SE_TROPIC_LT_OTP_EXHAUSTED (not a 255 fail); the other
 * half is independent; NV end != Tropic end mcounter is TAMPERED; OWNER
 * REPLACE resets the end mcounters and leaves 0 pads.
 */
#include "test_harness.h"
#include "secure_qkd_ingest.h"
#include "secure_lv.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "se_le.h"
#include "se_owner.h"
#include "host_fw_mlkem.h"
#include "libtropic.h"
#include <string.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#define PAD_PLAIN 64u
#define CHUNK_SIZE 509u

static uint8_t s_blob[16384];

static lt_ret_t sae_encapsulate(const uint8_t pk[SE_TROPIC_MLKEM_PK_LEN],
                                uint8_t ct[SE_TROPIC_KEM_CT_LEN],
                                uint8_t ss[SE_TROPIC_MLKEM_SS_LEN], uint8_t seed)
{
    MlKemKey kem;
    uint8_t rand[32];
    unsigned int i;
    int ret;

    for (i = 0U; i < sizeof(rand); i++) {
        rand[i] = (uint8_t)(seed + (uint8_t)i);
    }
    ret = wc_MlKemKey_Init(&kem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        return LT_CRYPTO_ERR;
    }
    ret = wc_MlKemKey_DecodePublicKey(&kem, pk, SE_TROPIC_MLKEM_PK_LEN);
    if (ret == 0) {
        ret = wc_MlKemKey_EncapsulateWithRandom(&kem, ct, ss, rand, (int)sizeof(rand));
    }
    wc_MlKemKey_Free(&kem);
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

static lt_ret_t seal_pad(const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                         const uint8_t fill_id[SE_NV_FILL_ID_LEN], uint16_t slot_index,
                         uint8_t *image, uint16_t *image_len)
{
    uint8_t key[SE_TROPIC_RMEM_AES_KEY_LEN];
    uint8_t binding[2];
    uint8_t plain[PAD_PLAIN];
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    unsigned int i;
    lt_ret_t ret;

    for (i = 0U; i < sizeof(plain); i++) {
        plain[i] = (uint8_t)(slot_index + i);
    }
    for (i = 0U; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0x90u + i);
    }
    nonce[0] = (uint8_t)slot_index;
    nonce[1] = (uint8_t)(slot_index >> 8);
    write_storage_slot_binding(slot_index, binding);
    ret = se_tropic_get_pad_encryption_key(ss, fill_id, slot_index, key);
    if (ret == LT_OK) {
        ret = se_tropic_encrypt_storage_blob(key, binding, sizeof(binding), plain, PAD_PLAIN,
                                             nonce, image, image_len);
    }
    wc_ForceZero(key, sizeof(key));
    return ret;
}

/**
 * Ingest one fill with decrypt_half=1 (encrypt = first half, logical 0..252;
 * decrypt = second half, logical 253..). Writes @p n_enc pads from the encrypt
 * base and @p n_dec pads from the decrypt base, the same layout SeKemFill uses.
 */
static int ingest_fill(const uint8_t pk[SE_TROPIC_MLKEM_PK_LEN], uint8_t fill_tag,
                       uint16_t n_enc, uint16_t n_dec)
{
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint8_t kem_ct[SE_TROPIC_KEM_CT_LEN];
    uint8_t ss[SE_TROPIC_MLKEM_SS_LEN];
    uint8_t image[SE_TROPIC_RMEM_BLOB_MAX];
    uint8_t le[2];
    uint16_t image_len;
    uint16_t items;
    uint16_t i;
    uint32_t blob_len = 0U;
    uint32_t off = 0U;
    uint32_t st = SECURE_QKD_OK;
    uint32_t count = 0U;
    const uint8_t half = 1U;

    for (i = 0U; i < SE_NV_FILL_ID_LEN; i++) {
        fill_id[i] = (uint8_t)(fill_tag + i);
    }
    se_nv_pending_fill_set(fill_id);
    TEST_ASSERT_EQ(sae_encapsulate(pk, kem_ct, ss, fill_tag), LT_OK, "SAE encapsulate");

    items = (uint16_t)(3U + SE_TROPIC_PAD_HALF + n_dec);
    secure_lv_put_header(s_blob, &blob_len, (uint8_t)SECURE_LV_DOWNLINK_VERSION, items);
    secure_lv_put_item(s_blob, &blob_len, kem_ct, SE_TROPIC_KEM_CT_LEN);
    secure_lv_put_item(s_blob, &blob_len, &half, 1u);
    se_put_u16le(le, PAD_PLAIN);
    secure_lv_put_item(s_blob, &blob_len, le, 2u);
    for (i = 0U; i < SE_TROPIC_PAD_HALF; i++) {
        if (i < n_enc) {
            image_len = sizeof(image);
            TEST_ASSERT_EQ(seal_pad(ss, fill_id, i, image, &image_len), LT_OK, "seal enc pad");
            secure_lv_put_item(s_blob, &blob_len, image, image_len);
        } else {
            secure_lv_put_item(s_blob, &blob_len, NULL, 0u); /* placeholder up to the half */
        }
    }
    for (i = 0U; i < n_dec; i++) {
        image_len = sizeof(image);
        TEST_ASSERT_EQ(seal_pad(ss, fill_id, (uint16_t)(SE_TROPIC_PAD_HALF + i), image, &image_len),
                       LT_OK, "seal dec pad");
        secure_lv_put_item(s_blob, &blob_len, image, image_len);
    }
    TEST_ASSERT(blob_len <= (uint32_t)sizeof(s_blob), "LV fits");

    secure_qkd_discard();
    while ((off < blob_len) && (st == SECURE_QKD_OK)) {
        uint32_t take = blob_len - off;

        if (take > CHUNK_SIZE) {
            take = CHUNK_SIZE;
        }
        st = secure_qkd_ingest(s_blob + off, take, SECURE_QKD_INGEST_CHUNK, NULL);
        off += take;
    }
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "ingest");
    st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
    TEST_ASSERT_EQ(st, SECURE_QKD_OK, "FINISH");
    wc_ForceZero(ss, sizeof(ss));
    return 0;
}

int main(void)
{
    lt_handle_t *h;
    WC_RNG rng;
    dilithium_key owner;
    uint8_t owner_pub[SE_NV_OWNER_SPKI_MAX];
    word32 owner_pub_len = (word32)sizeof(owner_pub);
    const uint8_t pin[] = {'9', '8', '7', '6', '5', '4', '3', '2'};
    const uint8_t add[] = {0xde, 0xad};
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint8_t msg[16];
    uint8_t out[16];
    uint16_t pk_len = 0U;
    uint16_t slot_used = 0U;
    uint16_t req[1];
    uint16_t end = 0U;
    uint16_t base_e = SE_TROPIC_PAD_FIRST;
    uint16_t base_d = (uint16_t)(SE_TROPIC_PAD_FIRST + SE_TROPIC_PAD_HALF);
    uint32_t raw = 0U;
    uint32_t left = 0U;
    uint32_t cap = 0U;
    uint32_t q[4];
    lt_ret_t ret;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }
    TEST_ASSERT(wc_InitRng(&rng) == 0, "rng");
    printf("=== L: end (write) cursors ===\n");
    TEST_ASSERT_EQ(se_tropic_init_session(), SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    TEST_ASSERT_EQ(wc_dilithium_init_ex(&owner, NULL, INVALID_DEVID), 0, "owner init");
    TEST_ASSERT_EQ(wc_dilithium_set_level(&owner, WC_ML_DSA_65), 0, "owner level");
    TEST_ASSERT_EQ(wc_dilithium_make_key(&owner, &rng), 0, "owner keygen");
    TEST_ASSERT_EQ(wc_dilithium_export_public(&owner, owner_pub, &owner_pub_len), 0, "owner pub");
    TEST_ASSERT_EQ(se_owner_set((const uint8_t *)"password1", 9U, owner_pub, (uint16_t)owner_pub_len),
                   LT_OK, "OWNER SET");

    ret = se_tropic_mlkem_provision(h, pin, sizeof(pin), add, sizeof(add), pk, sizeof(pk), &pk_len);
    TEST_ASSERT_EQ(ret, LT_OK, "mlkem provision");
    (void)memcpy(host_fw_mlkem_pk, pk, sizeof(pk));
    host_fw_mlkem_pk_len = SE_TROPIC_MLKEM_PK_LEN;
    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (uint8_t)(0x40u + (uint8_t)i);
    }

    /* --- Partial fill: 3 encrypt pads, 1 decrypt pad --- */
    TEST_ASSERT(ingest_fill(pk, 0x10u, 3U, 1U) == 0, "partial fill");
    TEST_ASSERT_EQ(se_tropic_qkd_end_get(h, SE_NV_OTP_ENCRYPT, &end), LT_OK, "enc end");
    TEST_ASSERT_EQ(end, (uint16_t)(base_e + 3U), "enc end = base + 3");
    TEST_ASSERT_EQ(lt_mcounter_get(h, SE_TROPIC_QKD_MCOUNTER_END_ENCRYPT, &raw), LT_OK, "mc2 get");
    TEST_ASSERT_EQ(raw, (uint32_t)(base_e + 3U), "mcounter 2 mirrors enc end");
    TEST_ASSERT_EQ(se_tropic_qkd_end_get(h, SE_NV_OTP_DECRYPT, &end), LT_OK, "dec end");
    TEST_ASSERT_EQ(end, (uint16_t)(base_d + 1U), "dec end = base + 1");
    TEST_ASSERT_EQ(lt_mcounter_get(h, SE_TROPIC_QKD_MCOUNTER_END_DECRYPT, &raw), LT_OK, "mc3 get");
    TEST_ASSERT_EQ(raw, (uint32_t)(base_d + 1U), "mcounter 3 mirrors dec end");

    TEST_ASSERT_EQ(se_tropic_otp_bytes_quota(h, SE_NV_OTP_ENCRYPT, &left, &cap), LT_OK, "enc quota");
    TEST_ASSERT_EQ(left, 3U * PAD_PLAIN, "enc left = 3 pads");
    TEST_ASSERT_EQ(cap, 3U * PAD_PLAIN, "enc written = 3 pads");
    TEST_ASSERT_EQ(se_tropic_otp_bytes_quota(h, SE_NV_OTP_DECRYPT, &left, &cap), LT_OK, "dec quota");
    TEST_ASSERT_EQ(left, 1U * PAD_PLAIN, "dec left = 1 pad");
    TEST_ASSERT_EQ(cap, 1U * PAD_PLAIN, "dec written = 1 pad");
    TEST_ASSERT_EQ(se_tropic_otp_left(q), SE_TROPIC_OK, "OTP STATUS");
    TEST_ASSERT_EQ(q[0], 3U * PAD_PLAIN, "STATUS enc left");
    TEST_ASSERT_EQ(q[1], 3U * PAD_PLAIN, "STATUS enc written");
    TEST_ASSERT_EQ(q[2], 1U * PAD_PLAIN, "STATUS dec left");
    TEST_ASSERT_EQ(q[3], 1U * PAD_PLAIN, "STATUS dec written");

    /* --- Consume encrypt until exhausted: EXHAUSTED, never a generic fail --- */
    for (i = 0; i < 3; i++) {
        ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                   SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used);
        TEST_ASSERT_EQ(ret, LT_OK, "encrypt written pad");
        TEST_ASSERT_EQ(slot_used, (uint16_t)(base_e + (uint16_t)i), "encrypt pad in order");
    }
    TEST_ASSERT_EQ(se_tropic_otp_bytes_remaining(h, SE_NV_OTP_ENCRYPT, &left), LT_OK, "enc left");
    TEST_ASSERT_EQ(left, 0U, "enc left 0 at end");
    ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                               SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_OTP_EXHAUSTED, "start == end -> EXHAUSTED");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &raw);
    TEST_ASSERT_EQ(ret, LT_OK, "enc cursor after refuse");
    TEST_ASSERT_EQ(raw, (uint32_t)(base_e + 3U), "refuse burns nothing");
    TEST_ASSERT_EQ(se_tropic_otp_left(q), SE_TROPIC_OK, "OTP STATUS after");
    TEST_ASSERT_EQ(q[0], 0U, "STATUS enc left 0");
    TEST_ASSERT_EQ(q[1], 3U * PAD_PLAIN, "STATUS enc written stays");

    /* --- The other half is independent --- */
    req[0] = SE_TROPIC_PAD_HALF; /* logical index of the first decrypt pad */
    ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                               SE_NV_OTP_DECRYPT, req, 1U, &slot_used);
    TEST_ASSERT_EQ(ret, LT_OK, "decrypt works with exhausted encrypt half");
    TEST_ASSERT_EQ(slot_used, base_d, "decrypt from its base");
    req[0] = (uint16_t)(SE_TROPIC_PAD_HALF + 1U);
    ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                               SE_NV_OTP_DECRYPT, req, 1U, &slot_used);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_OTP_EXHAUSTED, "decrypt past end -> EXHAUSTED");

    /* --- Empty decrypt half, full-ish encrypt half --- */
    TEST_ASSERT(ingest_fill(pk, 0x30u, 2U, 0U) == 0, "fill without decrypt pads");
    TEST_ASSERT_EQ(se_tropic_otp_bytes_quota(h, SE_NV_OTP_DECRYPT, &left, &cap), LT_OK, "dec quota 0");
    TEST_ASSERT_EQ(left, 0U, "dec left 0");
    TEST_ASSERT_EQ(cap, 0U, "dec written 0");
    req[0] = SE_TROPIC_PAD_HALF;
    ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                               SE_NV_OTP_DECRYPT, req, 1U, &slot_used);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_OTP_EXHAUSTED, "empty decrypt half -> EXHAUSTED");
    ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                               SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used);
    TEST_ASSERT_EQ(ret, LT_OK, "encrypt works with empty decrypt half");

    /* --- Tamper: Tropic end mcounter != MCU NV end --- */
    TEST_ASSERT_EQ(lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_END_ENCRYPT, (uint32_t)(base_e + 7U)),
                   LT_OK, "forge mcounter 2");
    TEST_ASSERT_EQ(se_tropic_qkd_end_get(h, SE_NV_OTP_ENCRYPT, &end), SE_TROPIC_LT_TAMPERED,
                   "end mismatch is TAMPERED");
    TEST_ASSERT_EQ(se_tropic_otp_bytes_quota(h, SE_NV_OTP_ENCRYPT, &left, &cap), SE_TROPIC_LT_TAMPERED,
                   "quota TAMPERED");
    ret = host_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                               SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_TAMPERED, "encrypt TAMPERED");
    TEST_ASSERT_EQ(lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_END_DECRYPT, (uint32_t)(base_d + 1U)),
                   LT_OK, "forge mcounter 3");
    TEST_ASSERT_EQ(se_tropic_qkd_end_get(h, SE_NV_OTP_DECRYPT, &end), SE_TROPIC_LT_TAMPERED,
                   "dec end mismatch is TAMPERED");
    TEST_ASSERT_EQ(lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_END_ENCRYPT, (uint32_t)(base_e + 2U)),
                   LT_OK, "restore mcounter 2");
    TEST_ASSERT_EQ(lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_END_DECRYPT, (uint32_t)base_d),
                   LT_OK, "restore mcounter 3");
    TEST_ASSERT_EQ(se_tropic_otp_bytes_quota(h, SE_NV_OTP_ENCRYPT, &left, &cap), LT_OK, "quota restored");
    TEST_ASSERT_EQ(left, 1U * PAD_PLAIN, "one encrypt pad left");

    /* --- OWNER REPLACE resets the end cursors (0 pads) --- */
    TEST_ASSERT_EQ(se_owner_replace((const uint8_t *)"password1", 9U, (const uint8_t *)"passwordB",
                                    9U, owner_pub, (uint16_t)owner_pub_len),
                   LT_OK, "OWNER REPLACE");
    TEST_ASSERT_EQ(lt_mcounter_get(h, SE_TROPIC_QKD_MCOUNTER_END_ENCRYPT, &raw), LT_OK, "mc2 after");
    TEST_ASSERT_EQ(raw, 0U, "mcounter 2 reset");
    TEST_ASSERT_EQ(lt_mcounter_get(h, SE_TROPIC_QKD_MCOUNTER_END_DECRYPT, &raw), LT_OK, "mc3 after");
    TEST_ASSERT_EQ(raw, 0U, "mcounter 3 reset");
    TEST_ASSERT(se_nv_get_otp_end(SE_NV_OTP_ENCRYPT, &end) != LT_OK, "no NV end after replace");
    TEST_ASSERT_EQ(se_tropic_qkd_end_get(h, SE_NV_OTP_ENCRYPT, &end), LT_FAIL, "no end after replace");
    TEST_ASSERT_EQ(se_tropic_otp_left(q), SE_TROPIC_OK, "OTP STATUS after replace");
    TEST_ASSERT(q[0] == 0U && q[1] == 0U && q[2] == 0U && q[3] == 0U, "STATUS 0/0 after replace");

    wc_dilithium_free(&owner);
    wc_FreeRng(&rng);
    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS L\n");
    return 0;
}