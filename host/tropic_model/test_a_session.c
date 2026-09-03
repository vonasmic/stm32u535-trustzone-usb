/**
 * @file    test_a_session.c
 * @brief   Group A: session runtime against TROPIC01 model
 */
#include "test_harness.h"
#include "se_tropic.h"

int main(void)
{
    uint32_t st;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== A: session ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    TEST_ASSERT(se_tropic_is_session_active() != 0U, "session active");

    st = se_tropic_ping();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "ping");

    st = se_tropic_info();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "info");

    se_tropic_deinit_session();
    TEST_ASSERT(se_tropic_is_session_active() == 0U, "session inactive after deinit");

    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "re-init session");
    st = se_tropic_ping();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "ping after re-init");
    se_tropic_deinit_session();

    host_crypto_deinit();
    printf("PASS A\n");
    return 0;
}
