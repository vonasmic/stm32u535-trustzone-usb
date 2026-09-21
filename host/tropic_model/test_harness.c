/**
 * @file    test_harness.c
 * @brief   wolfCrypt init for host model tests
 */
#include "test_harness.h"
#include "host_tropic.h"
#include <stdlib.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/wc_port.h>

int host_crypto_init(void)
{
    int ret = wolfCrypt_Init();
    const char *port;

    if (ret != 0) {
        fprintf(stderr, "wolfCrypt_Init failed %d (%s)\n", ret, wc_GetErrorString(ret));
        return -1;
    }
    port = getenv("TROPIC_PORT");
    if ((port != NULL) && (port[0] != '\0')) {
        host_tropic_set_port((unsigned)strtoul(port, NULL, 10));
    }
    return 0;
}

void host_crypto_deinit(void)
{
    (void)wolfCrypt_Cleanup();
}

lt_ret_t host_otp_xor_message(lt_handle_t *h, const uint8_t *pin, uint8_t pin_len,
                              const uint8_t *add, uint8_t add_len, const uint8_t *msg,
                              uint16_t len, uint8_t *out, se_nv_otp_dir_t dir,
                              const uint16_t *req_slots, uint16_t req_slots_n,
                              uint16_t *slot_used)
{
    uint16_t off = 0U;
    uint16_t i = 0U;
    uint16_t plain_max;
    lt_ret_t ret;

    if (slot_used != NULL) {
        *slot_used = 0U;
    }
    if ((h == NULL) || (msg == NULL) || (out == NULL) || (len == 0u)) {
        return LT_PARAM_ERR;
    }
    if (dir == SE_NV_OTP_ENCRYPT) {
        if ((req_slots != NULL) || (req_slots_n != 0U)) {
            return LT_PARAM_ERR;
        }
        ret = se_tropic_otp_xor_open(h, pin, pin_len, add, add_len, dir, (uint32_t)len, 0U);
    } else {
        if ((req_slots == NULL) || (req_slots_n == 0U)) {
            return LT_PARAM_ERR;
        }
        ret = se_tropic_otp_xor_open(h, pin, pin_len, add, add_len, dir, 0U, (uint32_t)req_slots_n);
    }
    if (ret != LT_OK) {
        return ret;
    }
    if ((dir == SE_NV_OTP_DECRYPT) && (req_slots_n != se_tropic_otp_xor_pads_needed())) {
        se_tropic_otp_xor_close();
        return LT_PARAM_ERR;
    }

    plain_max = se_tropic_otp_xor_pad_max();
    while (off < len) {
        uint16_t take = (uint16_t)(len - off);
        uint16_t phys = 0U;
        const uint16_t *req = NULL;

        if (take > plain_max) {
            take = plain_max;
        }
        if (dir == SE_NV_OTP_DECRYPT) {
            req = &req_slots[i];
        }
        ret = se_tropic_otp_xor_pad(h, req, msg + off, take, out + off, NULL, &phys);
        if (ret != LT_OK) {
            wc_ForceZero(out, len);
            break;
        }
        if ((i == 0U) && (slot_used != NULL)) {
            *slot_used = phys;
        }
        i = (uint16_t)(i + 1u);
        off = (uint16_t)(off + take);
    }
    se_tropic_otp_xor_close();
    return ret;
}
