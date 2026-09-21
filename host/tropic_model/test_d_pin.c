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
    uint8_t master[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t final_setup[SE_TROPIC_PIN_HMAC_LEN];
    uint8_t final_check[SE_TROPIC_PIN_HMAC_LEN];
    const uint8_t pin[] = {'1', '2', '3', '4', '5', '6', '7', '8'};
    const uint8_t pin_wrong[] = {'1', '2', '3', '4', '5', '6', '7', '9'};
    const uint8_t add[] = {0x11, 0x22, 0x33, 0x44};
    lt_ret_t ret;
    uint32_t st;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== D: PIN-gated ===\n");
    TEST_ASSERT(se_tropic_pin_ascii_ok(pin, (uint8_t)sizeof(pin)) != 0, "ascii PIN ok");
    TEST_ASSERT(se_tropic_pin_ascii_ok(pin, 4U) == 0, "PIN too short");
    TEST_ASSERT(se_tropic_pin_ascii_ok((const uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08", 8U) == 0,
                "non-printable PIN");
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
        uint8_t zeros[SE_TROPIC_PIN_HMAC_LEN] = {0};
        TEST_ASSERT(memcmp(final_check, zeros, sizeof(zeros)) == 0, "final_key wiped on fail");
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
