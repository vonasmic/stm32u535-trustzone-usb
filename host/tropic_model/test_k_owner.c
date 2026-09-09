/**
 * @file    test_k_owner.c
 * @brief   Group K: owner enrollment, creds, TLS-ready, NV ML-KEM, pairing wipe
 */
#include "test_harness.h"
#include "se_creds.h"
#include "se_le.h"
#include "se_manage.h"
#include "se_nv.h"
#include "se_owner.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include <string.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

static int make_owner(dilithium_key *key, WC_RNG *rng, uint8_t *pub, word32 *pub_len)
{
    int rc;

    rc = wc_dilithium_init_ex(key, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_dilithium_set_level(key, WC_ML_DSA_44);
    }
    if (rc == 0) {
        rc = wc_dilithium_make_key(key, rng);
    }
    if (rc == 0) {
        rc = wc_dilithium_export_public(key, pub, pub_len);
    }
    return rc;
}

int main(void)
{
    WC_RNG rng;
    dilithium_key key_a;
    dilithium_key key_b;
    uint8_t pub_a[SE_NV_OWNER_SPKI_MAX];
    uint8_t pub_b[SE_NV_OWNER_SPKI_MAX];
    uint8_t pairing_priv[SE_NV_PAIRING_KEY_LEN];
    uint8_t pairing_pub[SE_NV_PAIRING_KEY_LEN];
    uint8_t pairing_priv2[SE_NV_PAIRING_KEY_LEN];
    uint8_t pairing_pub2[SE_NV_PAIRING_KEY_LEN];
    uint8_t hash48[SE_NV_PEER_HASH_LEN];
    uint8_t der[32];
    uint8_t device_body[2U + 32U + 2U + 32U];
    uint8_t req[8];
    uint8_t pk[SE_TROPIC_MLKEM_PK_LEN];
    uint8_t pk2[SE_TROPIC_MLKEM_PK_LEN];
    char manage_msg[SE_MANAGE_MSG_MAX];
    word32 pub_len_a = (word32)sizeof(pub_a);
    word32 pub_len_b = (word32)sizeof(pub_b);
    uint16_t pk_len = 0U;
    uint8_t slot = 0U;
    uint8_t npeers = 0U;
    uint32_t st;
    int rc;
    unsigned int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }
    TEST_ASSERT(wc_InitRng(&rng) == 0, "rng");

    printf("=== K: owner / creds / ready ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");

    TEST_ASSERT(se_ready_encrypt() == 0, "encrypt not ready");
    TEST_ASSERT(se_ready_provision() == 0, "provision not ready");
    TEST_ASSERT(se_nv_has_owner() == 0, "no owner yet");

    rc = make_owner(&key_a, &rng, pub_a, &pub_len_a);
    TEST_ASSERT_EQ(rc, 0, "owner A keygen");
    rc = make_owner(&key_b, &rng, pub_b, &pub_len_b);
    TEST_ASSERT_EQ(rc, 0, "owner B keygen");

    TEST_ASSERT_EQ(se_owner_set((const uint8_t *)"short", 5U, pub_a, (uint16_t)pub_len_a),
                   LT_PARAM_ERR, "pw too short");
    TEST_ASSERT_EQ(se_owner_set((const uint8_t *)"password1", 9U, pub_a, (uint16_t)pub_len_a),
                   LT_OK, "OWNER SET");
    TEST_ASSERT(se_nv_has_owner() != 0, "owner present");
    TEST_ASSERT_EQ(se_owner_set((const uint8_t *)"password2", 9U, pub_b, (uint16_t)pub_len_b),
                   LT_FAIL, "first-wins");

    for (i = 0U; i < SE_NV_PAIRING_KEY_LEN; i++) {
        pairing_priv[i] = (uint8_t)(0x11u + i);
        pairing_pub[i] = (uint8_t)(0xA0u + i);
        hash48[i % SE_NV_PEER_HASH_LEN] = (uint8_t)i;
    }
    for (i = 0U; i < SE_NV_PEER_HASH_LEN; i++) {
        hash48[i] = (uint8_t)(0x5Au + i);
    }
    TEST_ASSERT_EQ(se_nv_set_pairing(1U, pairing_priv, pairing_pub), LT_OK, "pairing persist");
    TEST_ASSERT_EQ(se_nv_peer_add((const uint8_t *)"alice", 5U, hash48), LT_OK, "peer add");

    TEST_ASSERT_EQ(se_owner_replace((const uint8_t *)"wrongpass", 9U, (const uint8_t *)"passwordB",
                                    9U, pub_b, (uint16_t)pub_len_b),
                   LT_FAIL, "bad reset password");
    TEST_ASSERT_EQ(se_owner_replace((const uint8_t *)"password1", 9U, (const uint8_t *)"passwordB",
                                    9U, pub_b, (uint16_t)pub_len_b),
                   LT_OK, "OWNER REPLACE");
    TEST_ASSERT_EQ(se_nv_get_pairing(&slot, pairing_priv2, pairing_pub2), LT_OK,
                   "pairing survived wipe");
    TEST_ASSERT_EQ(slot, 1U, "pairing slot");
    TEST_ASSERT(memcmp(pairing_priv, pairing_priv2, sizeof(pairing_priv)) == 0, "pairing priv");
    TEST_ASSERT(memcmp(pairing_pub, pairing_pub2, sizeof(pairing_pub)) == 0, "pairing pub");
    TEST_ASSERT_EQ(se_nv_peer_count(&npeers), LT_OK, "peer count after wipe");
    TEST_ASSERT_EQ(npeers, 0U, "peers cleared");
    TEST_ASSERT(se_ready_encrypt() == 0, "encrypt not ready after replace");
    TEST_ASSERT(se_creds_has_sae_ca() == 0, "SAE CA cleared");
    TEST_ASSERT(se_nv_has_mlkem() == 0, "mlkem cleared");

    (void)memset(der, 0x33, sizeof(der));
    se_put_u16le(device_body, (uint16_t)sizeof(der));
    (void)memcpy(device_body + 2U, der, sizeof(der));
    se_put_u16le(device_body + 2U + sizeof(der), (uint16_t)sizeof(der));
    (void)memcpy(device_body + 4U + sizeof(der), der, sizeof(der));
    manage_msg[0] = '\0';
    TEST_ASSERT_EQ(se_manage_apply(SE_MANAGE_CREDS_DEVICE, NULL, 0U, device_body,
                                   (uint16_t)sizeof(device_body), manage_msg,
                                   (uint16_t)sizeof(manage_msg)),
                   SE_MANAGE_OK, "manage CREDS DEVICE");
    TEST_ASSERT(se_ready_encrypt() != 0, "encrypt ready");
    TEST_ASSERT(se_creds_has_sae_ca() == 0, "user/client CA unused for encrypt");
    TEST_ASSERT(se_ready_provision() == 0, "provision needs SAE CA + mlkem");
    TEST_ASSERT_EQ(se_manage_apply(SE_MANAGE_CREDS_SAE, NULL, 0U, der, (uint16_t)sizeof(der),
                                   manage_msg, (uint16_t)sizeof(manage_msg)),
                   SE_MANAGE_OK, "manage CREDS SAE");
    (void)memset(pk, 0x7A, sizeof(pk));
    TEST_ASSERT_EQ(se_nv_set_mlkem_pk(pk, SE_TROPIC_MLKEM_PK_LEN), LT_OK, "store mlkem");
    TEST_ASSERT(se_ready_provision() != 0, "provision ready");
    TEST_ASSERT_EQ(se_nv_get_mlkem_pk(pk2, &pk_len), LT_OK, "mlkem reboot");
    TEST_ASSERT_EQ(pk_len, SE_TROPIC_MLKEM_PK_LEN, "mlkem len");
    TEST_ASSERT(memcmp(pk, pk2, sizeof(pk)) == 0, "mlkem survived NV reload");

    req[0] = (uint8_t)SE_MANAGE_CREDS_SAE;
    req[1] = 0U;
    se_put_u16le(req + 2U, 4U);
    req[4] = 1U;
    req[5] = 2U;
    req[6] = 3U;
    req[7] = 4U;
    TEST_ASSERT_EQ(se_manage_req_need(req, 3U), 0U, "unsigned stream needs more");
    TEST_ASSERT_EQ(se_manage_req_need(req, 8U), 8U, "unsigned stream complete");
    TEST_ASSERT_EQ(se_manage_apply_buf(req, 8U, manage_msg, (uint16_t)sizeof(manage_msg)),
                   SE_MANAGE_OK, "apply unsigned stream");

    wc_dilithium_free(&key_a);
    wc_dilithium_free(&key_b);
    wc_FreeRng(&rng);
    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS K\n");
    return 0;
}
