/**
 * @file    test_f_mlkem.c
 * @brief   Group F: ML-KEM PIN-gated keystream store (host plays SAE)
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_pin.h"
#include "se_tropic_rmem.h"
#include "se_tropic_port.h"
#include "se_nv.h"
#include "host_fw_mlkem.h"
#include "sae_qkd.h"
#include "libtropic.h"
#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

static lt_ret_t sae_encapsulate(const uint8_t pk[SE_TROPIC_MLKEM_PK_LEN], uint8_t ct[SE_TROPIC_KEM_CT_LEN],
                                uint8_t ss[SE_TROPIC_MLKEM_SS_LEN])
{
    MlKemKey kem;
    uint8_t rand[32];
    unsigned int i;
    int ret;

    for (i = 0U; i < sizeof(rand); i++) {
        rand[i] = (uint8_t)(0xA0u + (uint8_t)i);
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

static lt_ret_t store_pad_slot(lt_handle_t *h, const uint8_t ss[SE_TROPIC_MLKEM_SS_LEN],
                               uint16_t slot, const uint8_t *pad, uint16_t pad_len)
{
    uint8_t nonce[SE_TROPIC_RMEM_NONCE_LEN];
    uint8_t image[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t image_len = sizeof(image);
    lt_ret_t ret;

    ret = lt_random_value_get(h, nonce, sizeof(nonce));
    if (ret != LT_OK) {
        return ret;
    }
    ret = sae_qkd_encrypt_pad_image(ss, slot, pad, pad_len, nonce, image, &image_len);
    if (ret != LT_OK) {
        return ret;
    }
    return se_tropic_qkd_store(h, slot, image, image_len);
}

static lt_ret_t write_fill_arm_encrypt_first(lt_handle_t *h, const uint8_t ct[SE_TROPIC_KEM_CT_LEN])
{
    lt_ret_t ret = se_tropic_kem_ct_write(h, ct);
    if (ret != LT_OK) {
        return ret;
    }
    return se_tropic_qkd_arm_halves(h, 1U);
}

int main(void)
{
    lt_handle_t *h;
    const uint8_t pin[] = {9, 8, 7, 6};
    const uint8_t pin_bad[] = {0, 8, 7, 6};
    const uint8_t add[] = {0xde, 0xad};
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint8_t pk_saved[SE_TROPIC_MLKEM_PK_LEN];
    uint8_t kem_ct[SE_TROPIC_KEM_CT_LEN];
    uint8_t ss[SE_TROPIC_MLKEM_SS_LEN];
    uint8_t fill_id_a[SE_NV_FILL_ID_LEN];
    uint8_t fill_id_b[SE_NV_FILL_ID_LEN];
    uint8_t old_image[SE_TROPIC_RMEM_BLOB_MAX];
    uint16_t old_image_len = 0;
    uint8_t msg[96];
    uint8_t out[96];
    uint8_t pad[96];
    uint8_t pad2[96];
    uint8_t raw_seed[SE_TROPIC_MLKEM_SEED_LEN];
    uint16_t pk_len = 0;
    uint16_t plain_max;
    uint16_t slot0 = 0u;
    uint16_t phys0 = SE_TROPIC_PAD_FIRST;
    uint16_t slot_used = 0;
    uint32_t next_slot = 0;
    lt_ret_t ret;
    uint32_t st;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== F: ML-KEM OTP ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");
    plain_max = se_tropic_get_rmem_slot_plaintext_max_size(h);
    TEST_ASSERT(plain_max > 32, "plain_max sane");

    ret = se_tropic_qkd_store(h, slot0, pad, 16u);
    TEST_ASSERT(ret == LT_FAIL, "store without fill refused");

    ret = se_tropic_mlkem_provision(h, pin, sizeof(pin), add, sizeof(add), pk, sizeof(pk), &pk_len);
    TEST_ASSERT_EQ(ret, LT_OK, "mlkem provision");
    TEST_ASSERT_EQ(pk_len, SE_TROPIC_MLKEM_PK_LEN, "pk len");
    (void)memcpy(pk_saved, pk, sizeof(pk));
    (void)memcpy(host_fw_mlkem_pk, pk, sizeof(pk));
    host_fw_mlkem_pk_len = SE_TROPIC_MLKEM_PK_LEN;

    {
        uint8_t raw[SE_TROPIC_RMEM_BLOB_MAX];
        uint16_t raw_len = 0;
        ret = lt_r_mem_data_read(h, SE_TROPIC_MLKEM_SEED_SLOT, raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_OK, "raw seed slot read");
        TEST_ASSERT(raw_len > 0, "seed slot occupied");
        TEST_ASSERT(memcmp(raw, pk, 32) != 0, "seed slot is not plaintext pk");
    }

    ret = sae_encapsulate(pk, kem_ct, ss);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE encapsulate");
    ret = write_fill_arm_encrypt_first(h, kem_ct);
    TEST_ASSERT_EQ(ret, LT_OK, "kem_ct write");
    ret = se_nv_get_fill_id(fill_id_a);
    TEST_ASSERT_EQ(ret, LT_OK, "fill_id after first fill");

    for (i = 0; i < (int)sizeof(pad); i++) {
        pad[i] = (uint8_t)(0x50u + (uint8_t)i);
        pad2[i] = (uint8_t)(0x60u + (uint8_t)i);
        msg[i] = (uint8_t)(0xC0u + (uint8_t)i);
    }

    ret = store_pad_slot(h, ss, slot0, pad, (uint16_t)sizeof(pad));
    TEST_ASSERT_EQ(ret, LT_OK, "store pad slot 0");

    ret = lt_r_mem_data_read(h, phys0, old_image, sizeof(old_image), &old_image_len);
    TEST_ASSERT_EQ(ret, LT_OK, "snapshot pad image");

    ret = store_pad_slot(h, ss, slot0, pad, 16u);
    TEST_ASSERT(ret == LT_FAIL, "occupied slot rewrite refused");

    ret = store_pad_slot(h, ss, (uint16_t)(slot0 + 1u), pad2, (uint16_t)sizeof(pad2));
    TEST_ASSERT_EQ(ret, LT_OK, "store extra pad");
    ret = write_fill_arm_encrypt_first(h, kem_ct);
    TEST_ASSERT_EQ(ret, LT_OK, "SAE re-provision kem_ct");
    ret = se_nv_get_fill_id(fill_id_b);
    TEST_ASSERT_EQ(ret, LT_OK, "fill_id after re-provision");
    TEST_ASSERT(memcmp(fill_id_a, fill_id_b, SE_NV_FILL_ID_LEN) != 0, "new fill_id");
    {
        uint8_t raw[SE_TROPIC_RMEM_BLOB_MAX];
        uint16_t raw_len = 0;

        ret = lt_r_mem_data_read(h, phys0, raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_L3_R_MEM_DATA_READ_SLOT_EMPTY, "old pads wiped");
        ret = lt_r_mem_data_read(h, (uint16_t)(phys0 + 1u), raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_L3_R_MEM_DATA_READ_SLOT_EMPTY, "extra pad wiped");
    }
    ret = store_pad_slot(h, ss, slot0, pad, (uint16_t)sizeof(pad));
    TEST_ASSERT_EQ(ret, LT_OK, "store pad after full wipe");
    ret = store_pad_slot(h, ss, (uint16_t)(slot0 + 1u), pad2, (uint16_t)sizeof(pad2));
    TEST_ASSERT_EQ(ret, LT_OK, "store second pad for multi-slot");

    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, sizeof(msg), out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, LT_OK, "otp consume correct PIN");
    TEST_ASSERT_EQ(slot_used, phys0, "otp from first pad");
    for (i = 0; i < (int)sizeof(msg); i++) {
        TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad[i]), "otp xor byte");
    }

    {
        uint8_t raw[SE_TROPIC_RMEM_BLOB_MAX];
        uint16_t raw_len = 0;
        ret = lt_r_mem_data_read(h, phys0, raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_L3_R_MEM_DATA_READ_SLOT_EMPTY, "consumed slot erased");
        ret = lt_r_mem_data_read(h, (uint16_t)(phys0 + 1u), raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_OK, "unused next pad still occupied");
    }

    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next_slot);
    TEST_ASSERT_EQ(ret, LT_OK, "cursor get");
    TEST_ASSERT_EQ(next_slot, (uint32_t)(phys0 + 1u), "cursor advanced one slot");

    /* Multi-slot: consume remaining pad with a short message. */
    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, 16u, out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, &slot_used, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, LT_OK, "otp second pad");
    TEST_ASSERT_EQ(slot_used, (uint16_t)(phys0 + 1u), "otp from second pad");
    for (i = 0; i < 16; i++) {
        TEST_ASSERT(out[i] == (uint8_t)(msg[i] ^ pad2[i]), "otp xor pad2");
    }
    {
        uint8_t raw[SE_TROPIC_RMEM_BLOB_MAX];
        uint16_t raw_len = 0;
        ret = lt_r_mem_data_read(h, (uint16_t)(phys0 + 1u), raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_L3_R_MEM_DATA_READ_SLOT_EMPTY, "second pad erased");
    }

    /* Re-provision, store under new fill_id, then restore old image => tamper. */
    ret = write_fill_arm_encrypt_first(h, kem_ct);
    TEST_ASSERT_EQ(ret, LT_OK, "fill for replay test");
    ret = store_pad_slot(h, ss, slot0, pad, (uint16_t)sizeof(pad));
    TEST_ASSERT_EQ(ret, LT_OK, "store under new fill");
    ret = lt_r_mem_data_erase(h, phys0);
    TEST_ASSERT_EQ(ret, LT_OK, "erase to plant old image");
    ret = lt_r_mem_data_write(h, phys0, old_image, old_image_len);
    TEST_ASSERT_EQ(ret, LT_OK, "plant old pad image");
    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, 8u, out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, NULL, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_TAMPERED, "old fill image is tamper");

    /* Fresh fill + pad, then rewind Tropic mcounter while MCU stays advanced. */
    ret = write_fill_arm_encrypt_first(h, kem_ct);
    TEST_ASSERT_EQ(ret, LT_OK, "fill for cursor rewind");
    ret = store_pad_slot(h, ss, slot0, pad, (uint16_t)sizeof(pad));
    TEST_ASSERT_EQ(ret, LT_OK, "store for cursor rewind");
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, 8u, out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, NULL, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, LT_OK, "consume before rewind");
    ret = lt_mcounter_init(h, SE_TROPIC_QKD_MCOUNTER_ENCRYPT, (uint32_t)phys0);
    TEST_ASSERT_EQ(ret, LT_OK, "rewind Tropic cursor");
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, 8u, out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, NULL, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_TAMPERED, "Tropic rewind is tamper");

    /* Restore aligned state for remaining tests. */
    ret = write_fill_arm_encrypt_first(h, kem_ct);
    TEST_ASSERT_EQ(ret, LT_OK, "fill after tamper tests");
    ret = store_pad_slot(h, ss, slot0, pad, (uint16_t)sizeof(pad));
    TEST_ASSERT_EQ(ret, LT_OK, "store after tamper tests");

    (void)memset(out, 0xEE, sizeof(out));
    ret = se_tropic_otp_xor_message(h, pin_bad, sizeof(pin_bad), add, sizeof(add), msg, 8u, out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, NULL, NULL, 0U, NULL);
    TEST_ASSERT(ret == LT_FAIL, "wrong PIN fails");
    for (i = 0; i < 8; i++) {
        TEST_ASSERT(out[i] == 0xEE, "wrong PIN leaves out untouched");
    }

    {
        uint8_t tamper[SE_TROPIC_MLKEM_PK_LEN];
        uint16_t tlen = 0U;

        TEST_ASSERT_EQ(se_nv_get_mlkem_pk(tamper, &tlen), LT_OK, "nv mlkem pk");
        TEST_ASSERT_EQ(tlen, SE_TROPIC_MLKEM_PK_LEN, "nv mlkem len");
        tamper[0] ^= 0x01u;
        TEST_ASSERT_EQ(se_nv_set_mlkem_pk(tamper, tlen), LT_OK, "tamper nv mlkem");
        (void)memset(out, 0xEE, sizeof(out));
        ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, 8u, out,
                                         SE_NV_OTP_ENCRYPT, NULL, 0U, NULL, NULL, 0U, NULL);
        TEST_ASSERT(ret == LT_FAIL, "pk mismatch refuses before pad");
        tamper[0] ^= 0x01u;
        TEST_ASSERT_EQ(se_nv_set_mlkem_pk(tamper, tlen), LT_OK, "restore nv mlkem");
    }

    while (1) {
        ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next_slot);
        if (ret != LT_OK) {
            break;
        }
        ret = se_tropic_qkd_cursor_advance(h, SE_NV_OTP_ENCRYPT);
        if (ret != LT_OK) {
            break;
        }
    }
    ret = se_tropic_otp_xor_message(h, pin, sizeof(pin), add, sizeof(add), msg, 8u, out,
                                     SE_NV_OTP_ENCRYPT, NULL, 0U, NULL, NULL, 0U, NULL);
    TEST_ASSERT_EQ(ret, SE_TROPIC_LT_OTP_EXHAUSTED, "exhausted cursor refuses");

    se_tropic_deinit_session();
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "re-init session");
    h = se_tropic_handle();

    ret = se_tropic_read_and_decrypt_mcu_sealed_from_rmem(h, SE_TROPIC_MLKEM_SEED_SLOT, raw_seed,
                                                      sizeof(raw_seed), &pk_len);
    TEST_ASSERT(ret != LT_OK, "seed not readable via device key without PIN path");

    /* Slot 510 must not open with PIN-only HKDF (no MCU device-key salt). */
    {
        uint8_t final_key[32];
        uint8_t kek[32];
        uint8_t dwk[32];
        uint8_t seed[SE_TROPIC_MLKEM_SEED_LEN];
        uint16_t got = 0;
        static const uint8_t info_v2[] = "SE_tropic_mlkem_kek_v2";
        static const uint8_t info_v3[] = "SE_tropic_mlkem_kek_v3";
        static const uint8_t aad_v2[] = "SE_tropic_mlkem_seed_v2";

        ret = se_tropic_pin_check(h, pin, sizeof(pin), add, sizeof(add), final_key);
        TEST_ASSERT_EQ(ret, LT_OK, "pin_check for kek bind");

        TEST_ASSERT_EQ(wc_HKDF(WC_SHA384, final_key, 32U, NULL, 0, info_v3,
                               (word32)(sizeof(info_v3) - 1U), kek, 32U),
                       0, "hkdf v3 no salt");
        ret = se_tropic_read_and_decrypt_from_rmem(h, SE_TROPIC_MLKEM_SEED_SLOT, kek, aad_v2,
                                        (uint16_t)(sizeof(aad_v2) - 1U), seed, sizeof(seed), &got);
        TEST_ASSERT(ret != LT_OK, "PIN-only kek_v3 cannot open seed");

        TEST_ASSERT_EQ(se_tropic_port_device_aead_key(dwk), LT_OK, "device key");
        TEST_ASSERT_EQ(wc_HKDF(WC_SHA256, final_key, 32U, dwk, 32U, info_v2,
                               (word32)(sizeof(info_v2) - 1U), kek, 32U),
                       0, "hkdf v2 dwk");
        ret = se_tropic_read_and_decrypt_from_rmem(h, SE_TROPIC_MLKEM_SEED_SLOT, kek, aad_v2,
                                        (uint16_t)(sizeof(aad_v2) - 1U), seed, sizeof(seed), &got);
        TEST_ASSERT(ret != LT_OK, "SHA-256 kek_v2 cannot open seed");

        TEST_ASSERT_EQ(wc_HKDF(WC_SHA384, final_key, 32U, dwk, 32U, info_v3,
                               (word32)(sizeof(info_v3) - 1U), kek, 32U),
                       0, "hkdf v3 dwk");
        ret = se_tropic_read_and_decrypt_from_rmem(h, SE_TROPIC_MLKEM_SEED_SLOT, kek, aad_v2,
                                        (uint16_t)(sizeof(aad_v2) - 1U), seed, sizeof(seed), &got);
        TEST_ASSERT_EQ(ret, LT_OK, "PIN+MCU kek opens seed");
        TEST_ASSERT_EQ(got, SE_TROPIC_MLKEM_SEED_LEN, "seed len");
        wc_ForceZero(final_key, sizeof(final_key));
        wc_ForceZero(kek, sizeof(kek));
        wc_ForceZero(dwk, sizeof(dwk));
        wc_ForceZero(seed, sizeof(seed));
    }

    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS F\n");
    return 0;
}
