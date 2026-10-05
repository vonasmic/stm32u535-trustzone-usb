#ifndef LIBTROPIC_USER_CONFIG_H
#define LIBTROPIC_USER_CONFIG_H

/**
 * libtropic compile-time options for SE_firmware Secure world.
 * Included before libtropic headers via -include or from se_tropic.c.
 */

#define LT_USE_WOLFCRYPT              1
#define LT_SILICON_REV_ACAB           1
#define LT_HELPERS                    1

#define LT_LOG_ENABLE_DEBUG           0
#define LT_LOG_ENABLE_INFO            0
#define LT_LOG_ENABLE_WARN            0
#define LT_LOG_ENABLE_ERROR           0

#define LT_CRC_ERR_RETRY_ATTEMPTS     3
#define LT_L1_READ_MAX_TRIES          50
#define LT_L1_READ_RETRY_DELAY_MS     25
#define LT_L1_SPI_TIMEOUT_MS          70
#define LT_L1_INT_TIMEOUT_MS            200

/** Production SH0 keys (TS13 dev kits ship prod0); define SE_TROPIC_SH0_ENG for engineering samples. */
#ifdef SE_TROPIC_SH0_ENG
#define SE_TROPIC_SH0_PRIV            lt_sh0priv_eng_sample
#define SE_TROPIC_SH0_PUB             lt_sh0pub_eng_sample
#else
#define SE_TROPIC_SH0_PRIV            lt_sh0priv_prod0
#define SE_TROPIC_SH0_PUB             lt_sh0pub_prod0
#endif

#define SE_TROPIC_ECC_SLOT            TR01_ECC_SLOT_0

#endif /* LIBTROPIC_USER_CONFIG_H */
