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
#include "se_nv.h"
#include "main.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "se_tropic_mlkem.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/wc_port.h"

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
    uint8_t dwk[SE_NV_DWK_LEN];
    int ret;
    lt_ret_t lret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    lret = se_tropic_port_dwk(dwk);
    if (lret != LT_OK) {
        return lret;
    }
    ret = wc_HKDF(WC_SHA384, dwk, SE_NV_DWK_LEN, NULL, 0,
                  (const byte *)"SE_tropic_rmem_aes_v1", 21U, out, 32U);
    wc_ForceZero(dwk, sizeof(dwk));
    return (ret == 0) ? LT_OK : LT_CRYPTO_ERR;
}

static uint8_t s_mlkem_pk_cache[SE_TROPIC_MLKEM_PK_LEN];

const uint8_t *se_tropic_port_mlkem_pk(void)
{
    uint16_t len = 0U;

    (void)memset(s_mlkem_pk_cache, 0, sizeof(s_mlkem_pk_cache));
    if (se_nv_get_mlkem_pk(s_mlkem_pk_cache, &len) == LT_OK &&
        len == SE_TROPIC_MLKEM_PK_LEN) {
        return s_mlkem_pk_cache;
    }
    (void)memset(s_mlkem_pk_cache, 0, sizeof(s_mlkem_pk_cache));
    return s_mlkem_pk_cache;
}

unsigned int se_tropic_port_mlkem_pk_len(void)
{
    uint16_t len = 0U;

    if (se_nv_get_mlkem_pk(s_mlkem_pk_cache, &len) != LT_OK) {
        (void)memset(s_mlkem_pk_cache, 0, sizeof(s_mlkem_pk_cache));
        return 0U;
    }
    return len;
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
#define SE_NV_FLASH_ADDR    0x0C02C000u
#define SE_NV_FLASH_PAGE    22u
#define SE_CREDS_FLASH_ADDR 0x0C02A000u
#define SE_CREDS_FLASH_PAGE 21u

static uint8_t s_flash_work[SE_NV_PAGE_SIZE];

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

static lt_ret_t flash_program_page(uint32_t addr, uint32_t page, const uint8_t *src)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t page_error = 0U;
    uint32_t off;
    uint8_t qw[16];
    HAL_StatusTypeDef st;

    if (src == NULL) {
        return LT_PARAM_ERR;
    }
    if (HAL_FLASH_Unlock() != HAL_OK) {
        return LT_HAL_ERROR;
    }
    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.Banks = FLASH_BANK_1;
    erase.Page = page;
    erase.NbPages = 1U;
    st = HAL_FLASHEx_Erase(&erase, &page_error);
    if (st != HAL_OK) {
        (void)HAL_FLASH_Lock();
        return LT_HAL_ERROR;
    }
    off = 0U;
    while (off < SE_NV_PAGE_SIZE) {
        uint16_t i;

        for (i = 0U; i < 16U; i++) {
            qw[i] = src[off + i];
        }
        st = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, addr + off, (uint32_t)qw);
        if (st != HAL_OK) {
            (void)HAL_FLASH_Lock();
            return LT_HAL_ERROR;
        }
        off += 16U;
    }
    (void)HAL_FLASH_Lock();
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_page_read(uint8_t dst[SE_NV_PAGE_SIZE])
{
    if (dst == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(dst, (const void *)SE_NV_FLASH_ADDR, SE_NV_PAGE_SIZE);
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_page_write(const uint8_t src[SE_NV_PAGE_SIZE])
{
    return flash_program_page(SE_NV_FLASH_ADDR, SE_NV_FLASH_PAGE, src);
}

lt_ret_t se_tropic_port_creds_page_read(uint8_t dst[SE_CREDS_PAGE_SIZE])
{
    if (dst == NULL) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(dst, (const void *)SE_CREDS_FLASH_ADDR, SE_CREDS_PAGE_SIZE);
    return LT_OK;
}

lt_ret_t se_tropic_port_creds_page_write(const uint8_t src[SE_CREDS_PAGE_SIZE])
{
    return flash_program_page(SE_CREDS_FLASH_ADDR, SE_CREDS_FLASH_PAGE, src);
}

lt_ret_t se_tropic_port_nv_raw_read(uint8_t *dst, uint16_t len)
{
    lt_ret_t ret;

    if ((dst == NULL) || (len == 0U) || (len > SE_NV_PAGE_SIZE)) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_port_nv_page_read(s_flash_work);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memcpy(dst, s_flash_work, len);
    wc_ForceZero(s_flash_work, sizeof(s_flash_work));
    return LT_OK;
}

lt_ret_t se_tropic_port_nv_raw_write(const uint8_t *src, uint16_t len)
{
    lt_ret_t ret;

    if ((src == NULL) || (len == 0U) || (len > SE_NV_PAGE_SIZE)) {
        return LT_PARAM_ERR;
    }
    (void)memset(s_flash_work, 0xff, sizeof(s_flash_work));
    (void)memcpy(s_flash_work, src, len);
    ret = se_tropic_port_nv_page_write(s_flash_work);
    wc_ForceZero(s_flash_work, sizeof(s_flash_work));
    return ret;
}

lt_ret_t se_tropic_port_dwk(uint8_t out[SE_NV_DWK_LEN])
{
    lt_ret_t ret;

    if (out == NULL) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_port_nv_page_read(s_flash_work);
    if (ret != LT_OK) {
        return ret;
    }
    if (page_dwk_blank(s_flash_work) != 0) {
        ret = se_tropic_port_nv_random(s_flash_work, SE_NV_DWK_LEN);
        if (ret != LT_OK) {
            wc_ForceZero(s_flash_work, sizeof(s_flash_work));
            return ret;
        }
        ret = se_tropic_port_nv_page_write(s_flash_work);
        if (ret != LT_OK) {
            wc_ForceZero(s_flash_work, sizeof(s_flash_work));
            return ret;
        }
    }
    (void)memcpy(out, s_flash_work, SE_NV_DWK_LEN);
    wc_ForceZero(s_flash_work, sizeof(s_flash_work));
    return LT_OK;
}

void se_tropic_port_device_id(uint8_t out[SE_DEVICE_ID_LEN])
{
    uint32_t w;

    if (out == NULL) {
        return;
    }
    w = HAL_GetUIDw0();
    out[0] = (uint8_t)w;
    out[1] = (uint8_t)(w >> 8);
    out[2] = (uint8_t)(w >> 16);
    out[3] = (uint8_t)(w >> 24);
    w = HAL_GetUIDw1();
    out[4] = (uint8_t)w;
    out[5] = (uint8_t)(w >> 8);
    out[6] = (uint8_t)(w >> 16);
    out[7] = (uint8_t)(w >> 24);
    w = HAL_GetUIDw2();
    out[8] = (uint8_t)w;
    out[9] = (uint8_t)(w >> 8);
    out[10] = (uint8_t)(w >> 16);
    out[11] = (uint8_t)(w >> 24);
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
