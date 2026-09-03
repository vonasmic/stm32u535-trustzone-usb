/**
 * @file    test_harness.c
 * @brief   wolfCrypt init for host model tests
 */
#include "test_harness.h"
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

int host_crypto_init(void)
{
    int ret = wolfCrypt_Init();
    if (ret != 0) {
        fprintf(stderr, "wolfCrypt_Init failed %d (%s)\n", ret, wc_GetErrorString(ret));
        return -1;
    }
    return 0;
}

void host_crypto_deinit(void)
{
    (void)wolfCrypt_Cleanup();
}
