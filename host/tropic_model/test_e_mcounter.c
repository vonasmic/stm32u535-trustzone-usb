/**
 * @file    test_e_mcounter.c
 * @brief   Group E: dual monotonic consumption cursors (encrypt / decrypt halves)
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "libtropic.h"

int main(void)
{
    lt_handle_t *h;
    uint8_t fill_id[SE_NV_FILL_ID_LEN];
    uint32_t next = 0;
    uint32_t dec = 0;
    uint32_t st;
    lt_ret_t ret;
    const uint16_t slot0 = SE_TROPIC_PAD_FIRST;
    const uint16_t dec_base = (uint16_t)(SE_TROPIC_PAD_FIRST + SE_TROPIC_PAD_HALF);
    unsigned int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== E: mcounter ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    for (i = 0U; i < SE_NV_FILL_ID_LEN; i++) {
        fill_id[i] = (uint8_t)(0xE0u + (uint8_t)i);
    }
    ret = se_nv_commit_fill(fill_id);
    TEST_ASSERT_EQ(ret, LT_OK, "MCU fill");
    ret = se_tropic_qkd_arm_halves(h, 1U);
    TEST_ASSERT_EQ(ret, LT_OK, "arm decrypt=second half");

    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next);
    TEST_ASSERT_EQ(ret, LT_OK, "encrypt cursor_get");
    TEST_ASSERT_EQ(next, (uint32_t)slot0, "encrypt at first pad");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_DECRYPT, &dec);
    TEST_ASSERT_EQ(ret, LT_OK, "decrypt cursor_get");
    TEST_ASSERT_EQ(dec, (uint32_t)dec_base, "decrypt at second half");

    ret = se_tropic_qkd_cursor_advance(h, SE_NV_OTP_ENCRYPT);
    TEST_ASSERT_EQ(ret, LT_OK, "encrypt advance #1");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next);
    TEST_ASSERT_EQ(ret, LT_OK, "get after advance");
    TEST_ASSERT_EQ(next, (uint32_t)(slot0 + 1u), "encrypt slot+1");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_DECRYPT, &dec);
    TEST_ASSERT_EQ(dec, (uint32_t)dec_base, "decrypt cursor unchanged");

    /* Power-cut analogue: advance without using keystream — cursor still moved. */
    ret = se_tropic_qkd_cursor_advance(h, SE_NV_OTP_ENCRYPT);
    TEST_ASSERT_EQ(ret, LT_OK, "advance without use");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next);
    TEST_ASSERT_EQ(next, (uint32_t)(slot0 + 2u), "lost slot, no reuse");

    while (1) {
        ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next);
        if (ret != LT_OK) {
            break;
        }
        TEST_ASSERT(next < (uint32_t)dec_base, "encrypt stays in first half");
        ret = se_tropic_qkd_cursor_advance(h, SE_NV_OTP_ENCRYPT);
        if (ret != LT_OK) {
            break;
        }
    }

    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_ENCRYPT, &next);
    TEST_ASSERT(ret != LT_OK, "encrypt exhausted get fails");
    ret = se_tropic_qkd_cursor_advance(h, SE_NV_OTP_ENCRYPT);
    TEST_ASSERT(ret != LT_OK, "encrypt exhausted advance fails");
    ret = se_tropic_qkd_cursor_get(h, SE_NV_OTP_DECRYPT, &dec);
    TEST_ASSERT_EQ(ret, LT_OK, "decrypt still live");
    TEST_ASSERT_EQ(dec, (uint32_t)dec_base, "decrypt not exhausted");

    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS E\n");
    return 0;
}
