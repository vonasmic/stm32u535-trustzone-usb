/**
 * @file    port_posix.c
 * @brief   Host model port: POSIX TCP HAL + stdout logging
 */
#include "se_tropic_port.h"
#include "se_tropic.h"
#include "host_fw_mlkem.h"
#include "host_libtropic_config.h"
#include "libtropic_user_config.h"
#include "libtropic_wolfcrypt.h"
#include "libtropic_port_posix_tcp.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static lt_dev_posix_tcp_t s_dev;
static lt_ctx_wolfcrypt_t s_crypto;
static uint8_t s_prng_seeded;

void se_tropic_port_hw_init(void)
{
    unsigned int seed;

    if (s_prng_seeded != 0U) {
        return;
    }
    /* Model TCP HAL / examples use rand(); seed once like upstream examples. */
    if (getentropy(&seed, sizeof(seed)) != 0) {
        seed = (unsigned int)getpid();
    }
    srand(seed);
    s_prng_seeded = 1U;
}

uint32_t se_tropic_port_attach(lt_handle_t *h)
{
    if (h == NULL) {
        return SE_TROPIC_ERR;
    }

    (void)memset(&s_dev, 0, sizeof(s_dev));
    (void)memset(&s_crypto, 0, sizeof(s_crypto));
    s_dev.addr = inet_addr("127.0.0.1");
    s_dev.port = 28992;
    h->l2.device = &s_dev;
    h->l3.crypto_ctx = &s_crypto;
    return SE_TROPIC_OK;
}

void se_tropic_log(const char *fmt, ...)
{
    va_list ap;

    if (fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    (void)vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    (void)fflush(stdout);
}

/* se_tropic_session.c logs through the USB debug hook; host has no CDC. */
void se_usb_debug_printf(const char *fmt, ...)
{
    va_list ap;

    if (fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    (void)vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    (void)fflush(stdout);
}

lt_ret_t se_tropic_port_device_aead_key(uint8_t out[32])
{
    static const uint8_t k[32] = {
        0x52, 0x4d, 0x45, 0x4d, 0x2d, 0x41, 0x45, 0x53, 0x2d, 0x47, 0x43, 0x4d, 0x2d, 0x4b, 0x45,
        0x59, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x32, 0x10};

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(out, k, sizeof(k));
    return LT_OK;
}

const uint8_t *se_tropic_port_mlkem_pk(void)
{
    return host_fw_mlkem_pk;
}

unsigned int se_tropic_port_mlkem_pk_len(void)
{
    return host_fw_mlkem_pk_len;
}

void se_tropic_port_print_chip_id(const lt_chip_id_t *chip_id)
{
    /* Upstream lt_print_chip_id can smash a 35-byte scratch on some fields. */
    (void)chip_id;
    se_tropic_log("TROPIC chip_id ok");
}

#define SE_NV_HOST_PAGE 256u
static uint8_t s_nv_page[SE_NV_HOST_PAGE];
static uint8_t s_nv_inited;

static void nv_host_ensure(void)
{
    if (s_nv_inited == 0U) {
        (void)memset(s_nv_page, 0xff, sizeof(s_nv_page));
        s_nv_inited = 1U;
    }
}

lt_ret_t se_tropic_port_nv_raw_read(uint8_t *dst, uint16_t len)
{
    if ((dst == NULL) || (len == 0U) || (len > SE_NV_HOST_PAGE)) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    (void)memcpy(dst, s_nv_page, len);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_raw_write(const uint8_t *src, uint16_t len)
{
    if ((src == NULL) || (len == 0U) || (len > SE_NV_HOST_PAGE)) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    (void)memset(s_nv_page, 0xff, sizeof(s_nv_page));
    (void)memcpy(s_nv_page, src, len);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_random(uint8_t *out, uint16_t len)
{
    if ((out == NULL) || (len == 0U)) {
        return LT_PARAM_ERR;
    }
    if (getentropy(out, len) != 0) {
        uint16_t i;
        for (i = 0U; i < len; i++) {
            out[i] = (uint8_t)(rand() & 0xff);
        }
    }
    return LT_OK;
}
