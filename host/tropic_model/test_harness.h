/**
 * @file    test_harness.h
 * @brief   Shared asserts / crypto init for host model tests
 */
#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include "se_tropic.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include <wolfssl/wolfcrypt/memory.h>

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

/**
 * Open/pad/close loop used by model tests. ENCRYPT: @p req_slots NULL.
 * DECRYPT: consecutive SAE indices in @p req_slots.
 */
lt_ret_t host_otp_xor_message(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                              const uint8_t *add, uint8_t add_len, const uint8_t *msg,
                              uint16_t len, uint8_t *out, se_nv_otp_dir_t dir,
                              const uint16_t *req_slots, uint16_t req_slots_n,
                              uint16_t *slot_used);

#endif /* TEST_HARNESS_H */
