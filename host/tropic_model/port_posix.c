/**
 * @file    port_posix.c
 * @brief   Host model port: POSIX TCP HAL + CDC DEBUG logging
 */
#include "se_tropic_port.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_nv.h"
#include "se_usb_tls.h"
#include "host_fw_mlkem.h"
#include "host_tropic.h"
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
static uint16_t s_tcp_port = HOST_TROPIC_DEFAULT_PORT;

void host_tropic_set_port(unsigned port)
{
    if (port > 0U && port <= 65535U) {
        s_tcp_port = (uint16_t)port;
    }
}

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
    s_dev.port = s_tcp_port;
    h->l2.device = &s_dev;
    h->l3.crypto_ctx = &s_crypto;
    return SE_TROPIC_OK;
}

void se_tropic_log(const char *fmt, ...)
{
    char buf[160];
    va_list ap;

    if (fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    /* Same CDC DEBUG path as se_tropic_port_stm32.c so UserApp transact sees a reply. */
    se_usb_debug_printf("%s", buf);
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

static uint8_t s_mlkem_nv[SE_TROPIC_MLKEM_PK_LEN];

const uint8_t *se_tropic_port_mlkem_pk(void)
{
    uint16_t len = 0U;

    if (se_nv_get_mlkem_pk(s_mlkem_nv, &len) == LT_OK && len == SE_TROPIC_MLKEM_PK_LEN) {
        return s_mlkem_nv;
    }
    return host_fw_mlkem_pk;
}

unsigned int se_tropic_port_mlkem_pk_len(void)
{
    uint16_t len = 0U;

    if (se_nv_get_mlkem_pk(s_mlkem_nv, &len) == LT_OK && len == SE_TROPIC_MLKEM_PK_LEN) {
        return len;
    }
    return host_fw_mlkem_pk_len;
}

void se_tropic_port_print_chip_id(const lt_chip_id_t *chip_id)
{
    /* Upstream lt_print_chip_id can smash a 35-byte scratch on some fields. */
    (void)chip_id;
    se_tropic_log("TROPIC chip_id ok");
}

static uint8_t s_nv_page[SE_NV_PAGE_SIZE];
static uint8_t s_creds_page[SE_CREDS_PAGE_SIZE];
static uint8_t s_nv_inited;
static uint8_t s_creds_inited;

static void nv_host_ensure(void)
{
    if (s_nv_inited == 0U) {
        (void)memset(s_nv_page, 0xff, sizeof(s_nv_page));
        s_nv_inited = 1U;
    }
}

static void creds_host_ensure(void)
{
    if (s_creds_inited == 0U) {
        (void)memset(s_creds_page, 0xff, sizeof(s_creds_page));
        s_creds_inited = 1U;
    }
}

static int page_dwk_blank(const uint8_t *p)
{
    uint16_t i;

    for (i = 0U; i < SE_NV_DWK_LEN; i++) {
        if (p[i] != 0xffu) {
            return 0;
        }
    }
    return 1;
}

lt_ret_t se_tropic_port_nv_page_read(uint8_t dst[SE_NV_PAGE_SIZE])
{
    if (dst == NULL) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    (void)memcpy(dst, s_nv_page, SE_NV_PAGE_SIZE);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_page_write(const uint8_t src[SE_NV_PAGE_SIZE])
{
    if (src == NULL) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    (void)memcpy(s_nv_page, src, SE_NV_PAGE_SIZE);
    return LT_OK;
}

lt_ret_t se_tropic_port_creds_page_read(uint8_t dst[SE_CREDS_PAGE_SIZE])
{
    if (dst == NULL) {
        return LT_PARAM_ERR;
    }
    creds_host_ensure();
    (void)memcpy(dst, s_creds_page, SE_CREDS_PAGE_SIZE);
    return LT_OK;
}

lt_ret_t se_tropic_port_creds_page_write(const uint8_t src[SE_CREDS_PAGE_SIZE])
{
    if (src == NULL) {
        return LT_PARAM_ERR;
    }
    creds_host_ensure();
    (void)memcpy(s_creds_page, src, SE_CREDS_PAGE_SIZE);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_raw_read(uint8_t *dst, uint16_t len)
{
    if ((dst == NULL) || (len == 0U) || (len > SE_NV_PAGE_SIZE)) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    (void)memcpy(dst, s_nv_page, len);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_raw_write(const uint8_t *src, uint16_t len)
{
    if ((src == NULL) || (len == 0U) || (len > SE_NV_PAGE_SIZE)) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    (void)memset(s_nv_page, 0xff, sizeof(s_nv_page));
    (void)memcpy(s_nv_page, src, len);
    return LT_OK;
}

lt_ret_t se_tropic_port_dwk(uint8_t out[SE_NV_DWK_LEN])
{
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    nv_host_ensure();
    if (page_dwk_blank(s_nv_page) != 0) {
        ret = se_tropic_port_nv_random(s_nv_page, SE_NV_DWK_LEN);
        if (ret != LT_OK) {
            return ret;
        }
    }
    (void)memcpy(out, s_nv_page, SE_NV_DWK_LEN);
    return LT_OK;
}

void se_tropic_port_device_id(uint8_t out[SE_DEVICE_ID_LEN])
{
    static const uint8_t k_id[SE_DEVICE_ID_LEN] = {
        'H', 'O', 'S', 'T', '-', 'T', 'E', 'S', 'T', '-', 'I', 'D'};

    if (out == NULL) {
        return;
    }
    (void)memcpy(out, k_id, SE_DEVICE_ID_LEN);
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
