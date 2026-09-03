/**
 * @file    test_d_pin.c
 * @brief   Group D: MAC-and-Destroy PIN setup/check and exhaustion
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "se_tropic_pin.h"
#include "libtropic.h"
#include <string.h>

int main(void)
{
    lt_handle_t *h;
    uint8_t master[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t final_setup[TR01_MAC_AND_DESTROY_DATA_SIZE];
    uint8_t final_check[TR01_MAC_AND_DESTROY_DATA_SIZE];
    const uint8_t pin[] = {1, 2, 3, 4};
    const uint8_t pin_wrong[] = {2, 2, 3, 4};
    const uint8_t add[] = {0x11, 0x22, 0x33, 0x44};
    lt_ret_t ret;
    uint32_t st;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== D: PIN-gated ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    ret = lt_random_value_get(h, master, sizeof(master));
    TEST_ASSERT_EQ(ret, LT_OK, "random master_secret");

    ret = se_tropic_pin_setup(h, master, pin, sizeof(pin), add, sizeof(add), final_setup);
    TEST_ASSERT_EQ(ret, LT_OK, "pin_setup");

    ret = se_tropic_pin_check(h, pin, sizeof(pin), add, sizeof(add), final_check);
    TEST_ASSERT_EQ(ret, LT_OK, "correct PIN right after setup");
    TEST_ASSERT(memcmp(final_setup, final_check, sizeof(final_setup)) == 0, "final_key matches");

    ret = se_tropic_pin_check(h, pin_wrong, sizeof(pin_wrong), add, sizeof(add), final_check);
    TEST_ASSERT_EQ(ret, LT_FAIL, "wrong PIN fails");
    {
        uint8_t zeros[32] = {0};
        TEST_ASSERT(memcmp(final_check, zeros, 32) == 0, "final_key wiped on fail");
    }

    ret = se_tropic_pin_check(h, pin, sizeof(pin), add, sizeof(add), final_check);
    TEST_ASSERT_EQ(ret, LT_OK, "correct PIN after one wrong");
    TEST_ASSERT(memcmp(final_setup, final_check, sizeof(final_setup)) == 0, "final_key matches again");

    for (i = 0; i < (int)SE_TROPIC_PIN_ROUNDS; i++) {
        ret = se_tropic_pin_check(h, pin_wrong, sizeof(pin_wrong), add, sizeof(add), final_check);
        TEST_ASSERT_EQ(ret, LT_FAIL, "wrong PIN consumes attempt");
    }
    ret = se_tropic_pin_check(h, pin, sizeof(pin), add, sizeof(add), final_check);
    TEST_ASSERT_EQ(ret, LT_FAIL, "correct PIN fails after exhaustion");

    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS D\n");
    return 0;
}
