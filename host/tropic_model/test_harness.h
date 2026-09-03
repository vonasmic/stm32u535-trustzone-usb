/**
 * @file    test_harness.h
 * @brief   Shared asserts / crypto init for host model tests
 */
#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include "se_tropic.h"

#define TEST_ASSERT(cond, msg)                                                                     \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));                         \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define TEST_ASSERT_EQ(a, b, msg)                                                                  \
    do {                                                                                           \
        if ((a) != (b)) {                                                                          \
            fprintf(stderr, "FAIL %s:%d: %s (got %lu expected %lu)\n", __FILE__, __LINE__, (msg),   \
                    (unsigned long)(a), (unsigned long)(b));                                       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int host_crypto_init(void);
void host_crypto_deinit(void);

#endif /* TEST_HARNESS_H */
