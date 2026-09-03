/**
 * @file    brick_lab.c
 * @brief   Group F: irreversible APIs on the MODEL only
 *
 * After this binary runs, restart the model before other tests.
 * Firmware may call lt_pairing_key_invalidate from TROPIC PAIRING;
 * this lab still gates i_config_write / occupied SH0 overwrite.
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "libtropic.h"
#include "libtropic_user_config.h"
#include <string.h>

int main(void)
{
    lt_handle_t *h;
    uint32_t st;
    lt_ret_t ret;
    uint32_t obj = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== F: brick lab (MODEL ONLY) ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    /* Pairing write into occupied SH0 must fail without invalidate. */
    {
        uint8_t dummy_pub[32];
        (void)memset(dummy_pub, 0x55, sizeof(dummy_pub));
        ret = lt_pairing_key_write(h, dummy_pub, TR01_PAIRING_KEY_SLOT_INDEX_0);
        TEST_ASSERT(ret != LT_OK, "pairing_key_write occupied SH0 fails");
        printf("pairing_write occupied -> %s\n", lt_ret_verbose(ret));
    }

    /* r_config_write without erase — observe model behavior (do not use on silicon). */
    ret = lt_r_config_write(h, TR01_CFG_START_UP_ADDR, 0u);
    printf("r_config_write without erase -> %s\n", lt_ret_verbose(ret));

    /* i_config_write is one-way on silicon; on model just exercise the call. */
    ret = lt_i_config_read(h, TR01_CFG_START_UP_ADDR, &obj);
    if (ret == LT_OK) {
        ret = lt_i_config_write(h, TR01_CFG_START_UP_ADDR, obj & 0xFFFFFFFEu);
        printf("i_config_write -> %s\n", lt_ret_verbose(ret));
    } else {
        printf("i_config_read skipped/fail %s\n", lt_ret_verbose(ret));
    }

    /* Invalidate SH0 — next session start must fail until model restart. */
    ret = lt_pairing_key_invalidate(h, TR01_PAIRING_KEY_SLOT_INDEX_0);
    TEST_ASSERT_EQ(ret, LT_OK, "pairing_key_invalidate SH0");
    printf("SH0 invalidated\n");

    se_tropic_deinit_session();

    st = se_tropic_init_session();
    TEST_ASSERT(st != SE_TROPIC_OK, "session fails after SH0 invalidate");
    printf("session after invalidate failed as expected\n");

    host_crypto_deinit();
    printf("PASS F (restart model before other tests)\n");
    return 0;
}
