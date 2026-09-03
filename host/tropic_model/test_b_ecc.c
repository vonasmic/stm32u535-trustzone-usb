/**
 * @file    test_b_ecc.c
 * @brief   Group B: ECC store / generate / occupied-slot / PIN reroll / sign+verify
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "se_tropic_pin.h"
#include "libtropic.h"
#include "libtropic_user_config.h"
#include <string.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>

/* OpenSSL-generated P-256 private key (same as libtropic functional tests). */
static const uint8_t priv_test_key[32] = {
    0x5e, 0xc6, 0xf1, 0xef, 0x96, 0x1f, 0x69, 0xb5, 0xd4, 0x34, 0xe1, 0x50, 0x6e, 0xa1, 0xcc, 0x51,
    0x11, 0x91, 0x94, 0x65, 0x87, 0xcb, 0x36, 0x82, 0x24, 0x07, 0x70, 0x32, 0x10, 0x1d, 0x62, 0xd1};

static int verify_p256_rs(const uint8_t pub_xy[64], const uint8_t hash32[32], const uint8_t rs64[64])
{
    ecc_key key;
    mp_int r;
    mp_int s;
    int ret;
    int stat = 0;
    uint8_t pub_unc[65];

    wc_ecc_init(&key);
    mp_init(&r);
    mp_init(&s);

    pub_unc[0] = 0x04;
    memcpy(pub_unc + 1, pub_xy, 64);
    ret = wc_ecc_import_x963(pub_unc, 65, &key);
    if (ret != 0) {
        fprintf(stderr, "import pub failed %d\n", ret);
        goto done;
    }

    ret = mp_read_unsigned_bin(&r, rs64, 32);
    if (ret != 0) {
        goto done;
    }
    ret = mp_read_unsigned_bin(&s, rs64 + 32, 32);
    if (ret != 0) {
        goto done;
    }

    ret = wc_ecc_verify_hash_ex(&r, &s, hash32, 32, &stat, &key);
    if (ret != 0 || stat != 1) {
        fprintf(stderr, "verify failed ret=%d stat=%d\n", ret, stat);
        ret = -1;
        goto done;
    }
    ret = 0;

done:
    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&key);
    return ret;
}

int main(void)
{
    lt_handle_t *h;
    uint8_t pub[64];
    uint8_t hash[32];
    uint8_t sig[64];
    uint8_t empty_hash[32];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    lt_ret_t ret;
    uint32_t st;
    Sha256 sha;
    const char *msg = "tropic-model-sign-test";

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== B: ECC ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    /* Empty slot: sign must fail. */
    (void)memset(empty_hash, 0xab, sizeof(empty_hash));
    ret = lt_ecc_key_erase(h, SE_TROPIC_ECC_SLOT);
    TEST_ASSERT_EQ(ret, LT_OK, "erase slot (fresh)");
    st = se_tropic_sign_hash(empty_hash, sig);
    TEST_ASSERT(st == SE_TROPIC_ERR, "sign empty slot fails");

    /* Store known key, read pub, sign, verify. */
    ret = lt_ecc_key_store(h, SE_TROPIC_ECC_SLOT, TR01_CURVE_P256, priv_test_key);
    TEST_ASSERT_EQ(ret, LT_OK, "ecc_key_store");
    st = se_tropic_pub_read(pub);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "pub_read after store");

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (const byte *)msg, (word32)strlen(msg));
    wc_Sha256Final(&sha, hash);

    st = se_tropic_sign_hash(hash, sig);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "sign after store");
    TEST_ASSERT(verify_p256_rs(pub, hash, sig) == 0, "openssl/wc verify stored key");

    /* Occupied-slot KEYGEN: no PIN → refuse. PIN without NVM → fail. */
    st = se_tropic_keygen(NULL, 0U);
    TEST_ASSERT_EQ(st, SE_TROPIC_SLOT_OCC, "keygen occupied");
    {
        const uint8_t pin_early[] = {9, 8, 7, 6};
        st = se_tropic_keygen(pin_early, sizeof(pin_early));
        TEST_ASSERT_EQ(st, SE_TROPIC_ERR, "reroll without PIN NVM fails");
    }
    /* Slot must still hold the stored key. */
    ret = lt_ecc_key_read(h, SE_TROPIC_ECC_SLOT, pub, sizeof(pub), &curve, &origin);
    TEST_ASSERT_EQ(ret, LT_OK, "slot still occupied after refused keygen");

    /* Erase (model-only), KEYGEN, PUB, SIGN, verify. */
    ret = lt_ecc_key_erase(h, SE_TROPIC_ECC_SLOT);
    TEST_ASSERT_EQ(ret, LT_OK, "erase before keygen");
    st = se_tropic_keygen(NULL, 0U);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "keygen empty");
    st = se_tropic_pub_read(pub);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "pub after keygen");
    st = se_tropic_sign_hash(hash, sig);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "sign after keygen");
    TEST_ASSERT(verify_p256_rs(pub, hash, sig) == 0, "verify generated key");

    /* PIN-gated reroll: erase + new P-256. */
    {
        uint8_t master[TR01_MAC_AND_DESTROY_DATA_SIZE];
        uint8_t final_key[TR01_MAC_AND_DESTROY_DATA_SIZE];
        uint8_t pub2[64];
        const uint8_t pin[] = {9, 8, 7, 6};
        const uint8_t pin_bad[] = {0, 8, 7, 6};

        ret = lt_random_value_get(h, master, sizeof(master));
        TEST_ASSERT_EQ(ret, LT_OK, "random for pin_setup");
        ret = se_tropic_pin_setup(h, master, pin, sizeof(pin), NULL, 0U, final_key);
        TEST_ASSERT_EQ(ret, LT_OK, "pin_setup for keygen reroll");

        st = se_tropic_keygen(NULL, 0U);
        TEST_ASSERT_EQ(st, SE_TROPIC_SLOT_OCC, "reroll without PIN refused");
        st = se_tropic_keygen(pin_bad, sizeof(pin_bad));
        TEST_ASSERT_EQ(st, SE_TROPIC_ERR, "reroll wrong PIN refused");
        st = se_tropic_pub_read(pub2);
        TEST_ASSERT_EQ(st, SE_TROPIC_OK, "pub after refused reroll");
        TEST_ASSERT(memcmp(pub, pub2, sizeof(pub)) == 0, "pub unchanged after refused reroll");

        st = se_tropic_keygen(pin, sizeof(pin));
        TEST_ASSERT_EQ(st, SE_TROPIC_OK, "reroll with PIN");
        st = se_tropic_pub_read(pub2);
        TEST_ASSERT_EQ(st, SE_TROPIC_OK, "pub after reroll");
        TEST_ASSERT(memcmp(pub, pub2, sizeof(pub)) != 0, "pub changed after reroll");
        st = se_tropic_sign_hash(hash, sig);
        TEST_ASSERT_EQ(st, SE_TROPIC_OK, "sign after reroll");
        TEST_ASSERT(verify_p256_rs(pub2, hash, sig) == 0, "verify rerolled key");
    }

    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS B\n");
    return 0;
}
