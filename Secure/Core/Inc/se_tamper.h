/**
 * @file    se_tamper.h
 * @brief   SRAM erase-on-reset check and TAMP internal tampers with erase
 */
#ifndef SE_TAMPER_H
#define SE_TAMPER_H

#include <stdint.h>
#include "stm32u5xx_hal.h"

/** se_sram_erase_status bits, sampled from FLASH_OPTR at boot. 0 = both erases on. */
#define SE_SRAM_ERASE_OK        0x0u
#define SE_SRAM_ERASE_NO_SRAM   0x1u /**< SRAM_RST = 1: SRAM1 and SRAM4 kept over a reset */
#define SE_SRAM_ERASE_NO_SRAM2  0x2u /**< SRAM2_RST = 1: SRAM2 kept over a reset */

/** Diagnostic only. Reset_Handler zeroes Secure SRAM whatever the option bytes say. */
extern volatile uint32_t se_sram_erase_status;
/** TAMP_SR as found at boot, before se_tamper_init() clears it. Diagnostic only. */
extern volatile uint32_t se_tamper_boot_sr;

/** Call once after MX_RTC_Init(). Makes TAMP Secure-only and arms the internal tampers. */
void se_tamper_init(RTC_HandleTypeDef *hrtc);

/** TAMP_IRQHandler body: clear the flags, then reset. */
void se_tamper_event(void) __attribute__((noreturn));

#endif /* SE_TAMPER_H */
