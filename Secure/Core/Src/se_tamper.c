/**
 * @file    se_tamper.c
 * @brief   SRAM erase-on-reset check and TAMP internal tampers with erase
 *
 * Option bytes SRAM_RST = 0 and SRAM2_RST = 0 make the hardware erase all
 * SRAM on every system reset. They are set at lockdown and are frozen at
 * RDP 2, so the boot check only records their state in se_sram_erase_status.
 * Reset_Handler zeroes Secure SRAM1, Secure SRAM2 and SRAM4 either way.
 *
 * The internal tampers run in confirmed mode (ITAMPxNOER = 0). On detection
 * the hardware erases the backup registers, BKPSRAM, SRAM2 (which holds the
 * Secure stack) and PKA SRAM. TAMP_IRQHandler then clears the flags and
 * resets the MCU, and the reset erases SRAM1 and SRAM4.
 *
 *   ITAMP1  backup domain voltage out of range (PWR_BDCR1.MONEN)
 *   ITAMP2  temperature out of range (PWR_BDCR1.MONEN)
 *   ITAMP6  JTAG/SWD access at RDP > 0. Armed only at RDP level 2. Levels
 *           0, 0.5 and 1 keep SWD for lab debugging and for the hot-plug
 *           steps of the lock and regression procedures. TAMP_CR1 is in the
 *           backup domain, so ITAMP6 is cleared explicitly below level 2.
 *   ITAMP9  cryptographic peripheral fault (RNG, AES, HASH, PKA)
 *
 * ITAMP3 (LSE monitor) is not used: the RTC runs on LSI.
 */
#include "se_tamper.h"
#include "main.h"

#define SE_TAMPER_SOURCES (RTC_INT_TAMPER_1 | RTC_INT_TAMPER_2 | RTC_INT_TAMPER_9)
#define SE_RDP_LEVEL2     0xCCu

volatile uint32_t se_sram_erase_status;
volatile uint32_t se_tamper_boot_sr;

static void sram_erase_check(uint32_t optr)
{
    uint32_t st = SE_SRAM_ERASE_OK;

    if ((optr & FLASH_OPTR_SRAM_RST) != 0U) {
        st |= SE_SRAM_ERASE_NO_SRAM;
    }
    if ((optr & FLASH_OPTR_SRAM2_RST) != 0U) {
        st |= SE_SRAM_ERASE_NO_SRAM2;
    }
    se_sram_erase_status = st;
}

void se_tamper_init(RTC_HandleTypeDef *hrtc)
{
    RTC_SecureStateTypeDef sec = {0};
    RTC_InternalTamperTypeDef itamp = {0};
    uint32_t optr = FLASH->OPTR;
    uint32_t sources = SE_TAMPER_SOURCES;

    sram_erase_check(optr);

    HAL_PWR_EnableBkUpAccess();

    /* TAMPSEC = 1: TAMP configuration and flags are Secure-only. The RTC and
     * backup register zones keep what MX_RTC_Init() set. */
    if (HAL_RTCEx_SecureModeGet(hrtc, &sec) != HAL_OK) {
        Error_Handler();
    }
    sec.tampSecureFull = TAMP_SECURE_FULL_YES;
    if (HAL_RTCEx_SecureModeSet(hrtc, &sec) != HAL_OK) {
        Error_Handler();
    }

    /* Backup domain voltage and temperature monitors feed ITAMP1 and ITAMP2. */
    HAL_PWREx_EnableMonitoring();

    if ((optr & FLASH_OPTR_RDP_Msk) == SE_RDP_LEVEL2) {
        sources |= RTC_INT_TAMPER_6;
    } else {
        (void)HAL_RTCEx_DeactivateInternalTamper(hrtc, RTC_INT_TAMPER_6);
    }

    /* Flags left from before this boot. */
    se_tamper_boot_sr = READ_REG(TAMP->SR);
    WRITE_REG(TAMP->SCR, se_tamper_boot_sr);

    itamp.IntTamper = sources;
    itamp.TimeStampOnTamperDetection = RTC_TIMESTAMPONTAMPERDETECTION_DISABLE;
    itamp.NoErase = RTC_TAMPER_ERASE_BACKUP_ENABLE;
    if (HAL_RTCEx_SetInternalTamper_IT(hrtc, &itamp) != HAL_OK) {
        Error_Handler();
    }

    HAL_NVIC_SetPriority(TAMP_IRQn, 0U, 0U);
    HAL_NVIC_EnableIRQ(TAMP_IRQn);
}

void se_tamper_event(void)
{
    /* The erase is already done in hardware. Clear the flags so the next boot
     * finds the secrets unblocked, then reset: the reset erases SRAM1 and
     * SRAM4 (SRAM_RST = 0) and Reset_Handler zeroes Secure SRAM again. A
     * condition that persists raises the flag again on the next boot. */
    WRITE_REG(TAMP->SCR, READ_REG(TAMP->SR));
    NVIC_SystemReset();
}
