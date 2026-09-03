/**
 * @file    se_tropic_port_stm32.c
 * @brief   STM32U5 SPI1 + USB log port for TROPIC01
 */
#include "se_tropic_port.h"
#include "se_tropic.h"
#include "libtropic_user_config.h"
#include "libtropic_wolfcrypt.h"
#include "libtropic_port_stm32u5xx.h"
#include "se_usb_tls.h"
#include "main.h"
#include "fw_creds.h"
#include "wrapped_client_key.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/hmac.h>

static lt_dev_stm32u5xx_t s_lt_dev;
static lt_ctx_wolfcrypt_t s_lt_crypto;
static uint8_t s_hw_ready;

extern RNG_HandleTypeDef hrng;

#if !defined(PWR_Pin) || !defined(CS_Pin)
#error "Configure SPI1 and Tropic GPIO (PA0 PWR, PA4 CS, PA5/6/7 SPI, PB0 GPO) in CubeMX Secure context and regenerate."
#endif

void se_tropic_port_hw_init(void)
{
    if (s_hw_ready != 0U) {
        return;
    }

    /* GPIO modes/levels come from CubeMX MX_GPIO_Init (see cubemx-configuration.mdc). */
    HAL_GPIO_WritePin(CS_GPIO_Port, CS_Pin, GPIO_PIN_SET);
    HAL_GPIO_WritePin(PWR_GPIO_Port, PWR_Pin, GPIO_PIN_SET);
    HAL_Delay(5);
    s_hw_ready = 1U;
}

uint32_t se_tropic_port_attach(lt_handle_t *h)
{
    if (h == NULL) {
        return SE_TROPIC_ERR;
    }

    (void)memset(&s_lt_dev, 0, sizeof(s_lt_dev));
    (void)memset(&s_lt_crypto, 0, sizeof(s_lt_crypto));

    s_lt_dev.spi_instance = SPI1;
    s_lt_dev.baudrate_prescaler = SPI_BAUDRATEPRESCALER_32;
    s_lt_dev.spi_cs_gpio_bank = CS_GPIO_Port;
    s_lt_dev.spi_cs_gpio_pin = CS_Pin;
    s_lt_dev.rng_handle = &hrng;
#ifdef LT_USE_INT_PIN
    s_lt_dev.int_gpio_bank = GPO_GPIO_Port;
    s_lt_dev.int_gpio_pin = GPO_Pin;
#endif

    h->l2.device = &s_lt_dev;
    h->l3.crypto_ctx = &s_lt_crypto;
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
    se_usb_debug_printf("%s", buf);
}

lt_ret_t se_tropic_port_device_aead_key(uint8_t out[32])
{
    int ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = wc_HKDF(WC_SHA384, secure_dwk, secure_dwk_len, NULL, 0,
                  (const byte *)"SE_tropic_rmem_aes_v1", 21U, out, 32U);
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

const uint8_t *se_tropic_port_mlkem_pk(void)
{
    return fw_mlkem_pk;
}

unsigned int se_tropic_port_mlkem_pk_len(void)
{
    return fw_mlkem_pk_len;
}

void se_tropic_port_print_chip_id(const lt_chip_id_t *chip_id)
{
    if (chip_id == NULL) {
        return;
    }
    /* Compact dump*/
    se_tropic_log_hex("TROPIC chip_id", (const uint8_t *)chip_id,
                      (uint32_t)sizeof(*chip_id));
}

/* Page 22: 0x0C02C000 — see STM32U535CCTX_FLASH.ld FLASH_NV */
#define SE_NV_FLASH_ADDR  0x0C02C000u
#define SE_NV_FLASH_PAGE  22u

lt_ret_t se_tropic_port_nv_raw_read(uint8_t *dst, uint16_t len)
{
    if ((dst == NULL) || (len == 0U) || (len > FLASH_PAGE_SIZE)) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(dst, (const void *)SE_NV_FLASH_ADDR, len);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_raw_write(const uint8_t *src, uint16_t len)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t page_error = 0U;
    uint32_t addr;
    uint16_t off;
    uint8_t qw[16];
    HAL_StatusTypeDef st;

    if ((src == NULL) || (len == 0U) || (len > FLASH_PAGE_SIZE)) {
        return LT_PARAM_ERR;
    }

    if (HAL_FLASH_Unlock() != HAL_OK) {
        return LT_HAL_ERROR;
    }

    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.Banks = FLASH_BANK_1;
    erase.Page = SE_NV_FLASH_PAGE;
    erase.NbPages = 1U;
    st = HAL_FLASHEx_Erase(&erase, &page_error);
    if (st != HAL_OK) {
        (void)HAL_FLASH_Lock();
        return LT_HAL_ERROR;
    }

    addr = SE_NV_FLASH_ADDR;
    off = 0U;
    while (off < len) {
        uint16_t take = (uint16_t)(len - off);
        uint16_t i;

        (void)memset(qw, 0xff, sizeof(qw));
        if (take > (uint16_t)sizeof(qw)) {
            take = (uint16_t)sizeof(qw);
        }
        for (i = 0U; i < take; i++) {
            qw[i] = src[off + i];
        }
        st = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, addr, (uint32_t)qw);
        if (st != HAL_OK) {
            (void)HAL_FLASH_Lock();
            return LT_HAL_ERROR;
        }
        addr += 16U;
        off = (uint16_t)(off + take);
    }

    (void)HAL_FLASH_Lock();
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_random(uint8_t *out, uint16_t len)
{
    uint16_t i;

    if ((out == NULL) || (len == 0U)) {
        return LT_PARAM_ERR;
    }
    for (i = 0U; i < len; i++) {
        uint32_t r = 0U;

        if (HAL_RNG_GenerateRandomNumber(&hrng, &r) != HAL_OK) {
            return LT_HAL_ERROR;
        }
        out[i] = (uint8_t)(r & 0xffu);
    }
    return LT_OK;
}

#include "se_libtropic_sources.inc"
