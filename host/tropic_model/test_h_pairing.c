/**
 * @file    test_h_pairing.c
 * @brief   Group H: pairing-key install, SH0 invalidate, session uses new key
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "se_tropic_port.h"
#include "se_nv.h"
#include "libtropic_user_config.h"
#include "libtropic.h"
#include <string.h>

static int factory_session_fails(void)
{
    lt_handle_t h;
    lt_ret_t ret;

    (void)memset(&h, 0, sizeof(h));
    if (se_tropic_port_attach(&h) != SE_TROPIC_OK) {
        fprintf(stderr, "factory attach fail\n");
        return -1;
    }
    ret = lt_init(&h);
    if (ret != LT_OK) {
        fprintf(stderr, "factory init fail %s\n", lt_ret_verbose(ret));
        return -1;
    }
    ret = lt_reboot(&h, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "factory reboot fail %s\n", lt_ret_verbose(ret));
        (void)lt_deinit(&h);
        return -1;
    }
    ret = lt_verify_chip_and_start_secure_session(&h, SE_TROPIC_SH0_PRIV, SE_TROPIC_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    (void)lt_deinit(&h);
    if (ret == LT_OK) {
        return 0;
    }
    return 1;
}

int main(void)
{
    lt_handle_t *h;
    uint32_t st;
    lt_ret_t ret;
    uint8_t pub[32];
    uint8_t tropic_pub[32];
    uint8_t priv[32];
    uint8_t bad_pub[32];
    uint8_t slot_out = 0U;
    const uint8_t slot = (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_1;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== H: pairing key ===\n");

    st = se_create_pairing_key_to_tropic(0U);
    TEST_ASSERT_EQ(st, SE_TROPIC_ERR, "create slot 0 refused");

    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session factory SH0");
    st = se_tropic_ping();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "ping factory SH0");

    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle before pairing");
    ret = lt_pairing_key_read(h, tropic_pub, (lt_pkey_index_t)slot);
    TEST_ASSERT_EQ(ret, LT_L3_SLOT_EMPTY, "slot 1 empty before create");

    st = se_create_pairing_key_to_tropic(slot);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "create write+invalidate");

    st = se_tropic_pairing_pub_read(pub);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "host pairing pub");

    st = se_tropic_ping();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "ping with new pairing key");

    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle after confirm");
    ret = lt_pairing_key_read(h, tropic_pub, (lt_pkey_index_t)slot);
    TEST_ASSERT_EQ(ret, LT_OK, "read new pairing pub");
    TEST_ASSERT(memcmp(pub, tropic_pub, sizeof(pub)) == 0, "host pub matches Tropic slot 1");

    ret = lt_pairing_key_read(h, tropic_pub, TR01_PAIRING_KEY_SLOT_INDEX_0);
    TEST_ASSERT_EQ(ret, LT_L3_SLOT_INVALID, "factory SH0 slot invalid");

    st = se_create_pairing_key_to_tropic(slot);
    TEST_ASSERT_EQ(st, SE_TROPIC_SLOT_OCC, "second create occupied");

    se_tropic_deinit_session();
    TEST_ASSERT(factory_session_fails() == 1, "factory SH0 handshake fails");

    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "re-init uses new pairing key");
    st = se_tropic_ping();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "ping after re-init with new key");

    st = se_tropic_pairing_export(&slot_out, priv, pub);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "export host pairing key");
    TEST_ASSERT_EQ(slot_out, slot, "exported slot");

    se_tropic_deinit_session();
    se_tropic_pairing_unload();
    TEST_ASSERT_EQ(se_nv_clear_pairing(), LT_OK, "simulate MCU rewrite (NV pairing gone)");

    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_ERR, "rewrite without host backup cannot open L3");

    (void)memcpy(bad_pub, pub, sizeof(bad_pub));
    bad_pub[0] ^= 1U;
    st = se_tropic_pairing_load(slot, priv, bad_pub);
    TEST_ASSERT_EQ(st, SE_TROPIC_ERR, "load rejects pub that does not match priv");

    st = se_tropic_pairing_load(slot, priv, pub);
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "load after rewrite");
    st = se_tropic_ping();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "ping after pairing LOAD");
    se_tropic_deinit_session();

    host_crypto_deinit();
    printf("PASS H\n");
    return 0;
}
