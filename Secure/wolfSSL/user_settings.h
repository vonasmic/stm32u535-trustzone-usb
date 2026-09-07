/**
 ******************************************************************************
 * @file    Secure/wolfSSL/user_settings.h
 * @brief   wolfSSL configuration for the Secure world (STM32U535, TrustZone)
 *
 * Durable Secure wolfSSL settings (-DWOLFSSL_USER_SETTINGS). CubeMX may
 * regenerate wolfSSL.I-CUBE-wolfSSL_conf.h; this file is not overwritten.
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * WOLF_CONF_* values
 * ========================================================================= */

#define WOLF_CONF_DEBUG           0
#define WOLF_CONF_WOLFCRYPT_ONLY  0   /* Full TLS 1.3 client in Secure */
#define WOLF_CONF_TLS13           1
#define WOLF_CONF_TLS12           0
#define WOLF_CONF_DTLS            0
#define WOLF_CONF_MATH            4
#define WOLF_CONF_RTOS            1
#define WOLF_CONF_RNG             1
#define WOLF_CONF_RSA             0
/* Keep ECC enabled: wolfSSL TLS requires HAVE_ECC for pkCurveOID (ML-DSA)
 * and the "No cipher suites available" guard, even though KE is ML-KEM. */
#define WOLF_CONF_ECC             1
#define WOLF_CONF_DH              0
#define WOLF_CONF_AESGCM          1
#define WOLF_CONF_AESCBC          0
#define WOLF_CONF_CHAPOLY         0
#define WOLF_CONF_EDCURVE25519    0
#define WOLF_CONF_MD5             0
#define WOLF_CONF_SHA1            0
#define WOLF_CONF_SHA2_224        0
#define WOLF_CONF_SHA2_256        1
#define WOLF_CONF_SHA2_384        1
#define WOLF_CONF_SHA2_512        0
#define WOLF_CONF_SHA3            1
#define WOLF_CONF_PSK             0
#define WOLF_CONF_PWDBASED        0
#define WOLF_CONF_KEEP_PEER_CERT  1
#define WOLF_CONF_BASE64_ENCODE   0
#define WOLF_CONF_OPENSSL_EXTRA   0
#define WOLF_CONF_TEST            0
#define WOLF_CONF_KYBER           1
#define WOLF_CONF_ARMASM          0
#define WOLF_CONF_IO              1
#define WOLF_CONF_RESUMPTION      0
#define WOLF_CONF_TPM             0
#define WOLF_CONF_PK              0

/* =========================================================================
 * Hardware platform
 * =========================================================================
 * Defaults (no HW acceleration, no TLS UART test).
 */
#define NO_STM32_HASH
#define NO_STM32_CRYPTO
#define NO_TLS_UART_TEST

#if defined(STM32WB55xx)
    #define WOLFSSL_STM32WB
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#elif defined(STM32WBA52xx)
    #define WOLFSSL_STM32WBA
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#elif defined(STM32WL55xx)
    #define WOLFSSL_STM32WL
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32F407xx)
    #define WOLFSSL_STM32F4
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32F437xx) || defined(STM32F439xx)
    #define WOLFSSL_STM32F4
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define STM32_HAL_V2
    #ifndef HAL_CONSOLE_UART
        #ifdef STM32F439xx
        #define HAL_CONSOLE_UART huart3
        #else
        #define HAL_CONSOLE_UART huart4
        #endif
    #endif
#elif defined(STM32F777xx)
    #define WOLFSSL_STM32F7
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define STM32_HAL_V2
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32F756xx)
    #define WOLFSSL_STM32F7
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define STM32_HAL_V2
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart3
    #endif
#elif defined(STM32H7S3xx)
    #define WOLFSSL_STM32H7S
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define WOLFSSL_STM32_PKA
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart3
    #endif
#elif defined(STM32H753xx)
    #define WOLFSSL_STM32H7
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart3
    #endif
#elif defined(STM32H723xx) || defined(STM32H725xx) || defined(STM32H743xx)
    #define WOLFSSL_STM32H7
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart3
    #endif
#elif defined(STM32L4A6xx)
    #define WOLFSSL_STM32L4
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART hlpuart1
    #endif
#elif defined(STM32L475xx)
    #define WOLFSSL_STM32L4
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#elif defined(STM32L562xx)
    #define WOLFSSL_STM32L5
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#elif defined(STM32L552xx)
    #define WOLFSSL_STM32L5
    #undef  NO_STM32_HASH
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART hlpuart1
    #endif
#elif defined(STM32F207xx)
    #define WOLFSSL_STM32F2
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart3
    #endif
#elif defined(STM32F217xx)
    #define WOLFSSL_STM32F2
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32F107xC)
    #define WOLFSSL_STM32F1
    #define NO_STM32_RNG
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart4
    #endif
#elif defined(STM32F401xE)
    #define WOLFSSL_STM32F4
    #define NO_STM32_RNG
    #define WOLFSSL_GENSEED_FORTEST
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32G071xx)
    #define WOLFSSL_STM32G0
    #define NO_STM32_RNG
    #define WOLFSSL_GENSEED_FORTEST
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32G491xx)
    #define WOLFSSL_STM32G4
    #define HAL_CONSOLE_UART hlpuart1
#elif defined(STM32U385xx)
    #define WOLFSSL_STM32U3
    #define STM32_HAL_V2
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#elif defined(STM32U535xx) || defined(STM32U575xx) || defined(STM32U585xx) || defined(STM32U5A9xx)
    #define WOLFSSL_STM32U5
    #define STM32_HAL_V2
    #if defined(STM32U585xx) || defined(STM32U5A9xx)
        #undef  NO_STM32_HASH
        #undef  NO_STM32_CRYPTO
        #define WOLFSSL_STM32_PKA
    #endif
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#elif defined(STM32H563xx)
    #define WOLFSSL_STM32H5
    #define STM32_HAL_V2
    #undef  NO_STM32_HASH
    #define WOLFSSL_STM32_PKA
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart3
    #endif
#elif defined(STM32MP135Fxx)
    #define WOLFSSL_STM32MP13
    #define STM32_HAL_V2
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define WOLFSSL_STM32_PKA
    #define WOLFSSL_STM32_PKA_V2
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart4
    #endif
#elif defined(STM32N657xx)
    #define WOLFSSL_STM32N6
    #define STM32_HAL_V2
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define WOLFSSL_STM32_PKA
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart1
    #endif
#else
    #warning Please define a hardware platform!
    #define WOLFSSL_STM32F4
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart4
    #endif
#endif

/* =========================================================================
 * Platform
 * ========================================================================= */
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define WOLFSSL_STM32_CUBEMX
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_IGNORE_FILE_WARN

/* =========================================================================
 * Network stack
 * ========================================================================= */
#if defined(WOLF_CONF_IO) && WOLF_CONF_IO == 2
    #define WOLFSSL_LWIP
#elif defined(WOLF_CONF_IO) && WOLF_CONF_IO == 3
    #define WOLFSSL_LWIP_NATIVE
#else
    #define WOLFSSL_USER_IO
    #define WOLFSSL_NO_SOCK
#endif

/* =========================================================================
 * Operating System
 * ========================================================================= */
#if defined(WOLF_CONF_RTOS) && WOLF_CONF_RTOS == 2
    #define FREERTOS
    #define WOLFSSL_NO_REALLOC
#else
    #define SINGLE_THREADED
#endif

/* =========================================================================
 * Math Configuration
 * ========================================================================= */
#if defined(WOLF_CONF_MATH) && WOLF_CONF_MATH == 1
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
    #if !defined(NO_RSA) || !defined(NO_DH)
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS     4096
    #endif
#elif defined(WOLF_CONF_MATH) && WOLF_CONF_MATH == 2
    #define USE_INTEGER_HEAP_MATH
#elif defined(WOLF_CONF_MATH) && (WOLF_CONF_MATH >= 3)
    #define WOLFSSL_SP
    #if WOLF_CONF_MATH != 7
        #define WOLFSSL_SP_SMALL
    #endif
    #if defined(WOLF_CONF_RSA) && WOLF_CONF_RSA == 1
        #define WOLFSSL_HAVE_SP_RSA
    #endif
    #if defined(WOLF_CONF_DH) && WOLF_CONF_DH == 1
        #define WOLFSSL_HAVE_SP_DH
    #endif
    #if defined(WOLF_CONF_ECC) && WOLF_CONF_ECC == 1
        #define WOLFSSL_HAVE_SP_ECC
    #endif
    #if WOLF_CONF_MATH == 6 || WOLF_CONF_MATH == 7
        #define WOLFSSL_SP_MATH_ALL
    #else
        #define WOLFSSL_SP_MATH
    #endif
    #define SP_WORD_SIZE 32
    #if WOLF_CONF_MATH == 4 || WOLF_CONF_MATH == 5
        #define WOLFSSL_SP_ASM
        #if WOLF_CONF_MATH == 4
            #define WOLFSSL_SP_ARM_CORTEX_M_ASM
        #endif
        #if WOLF_CONF_MATH == 5
            #define WOLFSSL_SP_ARM_THUMB_ASM
        #endif
    #endif
#endif

/* =========================================================================
 * Enable Features
 * ========================================================================= */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_EXTENDED_MASTER
#define WOLFSSL_ASN_TEMPLATE
#define HAVE_SNI

#if defined(WOLF_CONF_TLS13) && WOLF_CONF_TLS13 == 1
    #define WOLFSSL_TLS13
    #define HAVE_HKDF
    /* wolfSSL_export_keying_material: session binding value for the LV uplink. */
    #define HAVE_KEYING_MATERIAL
#endif
#if defined(WOLF_CONF_DTLS) && WOLF_CONF_DTLS == 1
    #define WOLFSSL_DTLS
#endif
#if defined(WOLF_CONF_DTLS13) && WOLF_CONF_DTLS13 == 1
    #define WOLFSSL_DTLS13
    #define WOLFSSL_SEND_HRR_COOKIE
#endif
#if defined(WOLF_CONF_PSK) && WOLF_CONF_PSK == 0
    #define NO_PSK
#endif
#if defined(WOLF_CONF_PWDBASED) && WOLF_CONF_PWDBASED == 0
    #define NO_PWDBASED
#endif
#if defined(WOLF_CONF_KEEP_PEER_CERT) && WOLF_CONF_KEEP_PEER_CERT == 1
    #define KEEP_PEER_CERT
#endif
#if defined(WOLF_CONF_BASE64_ENCODE) && WOLF_CONF_BASE64_ENCODE == 1
    #define WOLFSSL_BASE64_ENCODE
#endif
#if defined(WOLF_CONF_OPENSSL_EXTRA) && WOLF_CONF_OPENSSL_EXTRA >= 1
    #define OPENSSL_EXTRA
    #if !defined(INT_MAX)
        #include <limits.h>
    #endif
#endif
#if defined(WOLF_CONF_OPENSSL_EXTRA) && WOLF_CONF_OPENSSL_EXTRA >= 2
    #define OPENSSL_ALL
#endif

/* TLS Session Cache */
#if defined(WOLF_CONF_RESUMPTION) && WOLF_CONF_RESUMPTION == 1
    #define SMALL_SESSION_CACHE
    #define HAVE_SESSION_TICKET
#else
    #define NO_SESSION_CACHE
#endif

/* TPM / WOLF_CRYPTO_CB */
#if defined(WOLF_CONF_TPM) && WOLF_CONF_TPM == 1
    #define WOLF_CRYPTO_CB
    #define WOLFSSL_PUBLIC_MP
#endif

/* TLS key callbacks */
#if defined(WOLF_CONF_PK) && WOLF_CONF_PK == 1
    #define HAVE_PK_CALLBACKS
#endif

/* =========================================================================
 * Crypto
 * ========================================================================= */
#undef NO_RSA
#if defined(WOLF_CONF_RSA) && WOLF_CONF_RSA == 1
    #undef  WC_RSA_BLINDING
    #define WC_RSA_BLINDING
    #ifdef WOLFSSL_TLS13
        #define WC_RSA_PSS
    #endif
#else
    #define NO_RSA
#endif

#undef HAVE_ECC
#if defined(WOLF_CONF_ECC) && WOLF_CONF_ECC == 1
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #undef  FP_ECC
    #undef  ECC_SHAMIR
    #define ECC_SHAMIR
    #define ECC_TIMING_RESISTANT
    #ifdef USE_FAST_MATH
        #if defined(NO_RSA) && defined(NO_DH)
            #define FP_MAX_BITS     (256 * 2)
        #else
            #define ALT_ECC_SIZE
        #endif
    #endif
#endif

#undef NO_DH
#if defined(WOLF_CONF_DH) && WOLF_CONF_DH == 1
    #define HAVE_DH
    #define HAVE_FFDHE_2048
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

#if defined(WOLF_CONF_AESGCM) && WOLF_CONF_AESGCM >= 1
    #define HAVE_AESGCM
    #define HAVE_AES_DECRYPT
    /* Te/Td T-tables are 8KB; S-box only fits Secure FLASH with libtropic. */
    #define WOLFSSL_AES_SMALL_TABLES
    #if WOLF_CONF_AESGCM == 2
        #define GCM_TABLE_4BIT
    #else
        #define GCM_SMALL
    #endif
#endif

#if defined(WOLF_CONF_AESCBC) && WOLF_CONF_AESCBC == 1
    #define HAVE_AES_CBC
    #define HAVE_AES_DECRYPT
#else
    #define NO_AES_CBC
#endif

#if defined(WOLF_CONF_TPM) && WOLF_CONF_TPM == 1
    #define WOLFSSL_AES_CFB
#endif

#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if defined(WOLF_CONF_CHAPOLY) && WOLF_CONF_CHAPOLY == 1
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

#undef HAVE_CURVE25519
#undef HAVE_ED25519
/* Tropic01 pairing (libtropic CAL) needs X25519; Ed25519 stays optional. */
#define HAVE_CURVE25519
#define CURVED25519_SMALL
#if defined(WOLF_CONF_EDCURVE25519) && WOLF_CONF_EDCURVE25519 == 1
    #define HAVE_ED25519
#endif

/* =========================================================================
 * Hashing
 * ========================================================================= */
#undef NO_SHA
#if defined(WOLF_CONF_SHA1) && WOLF_CONF_SHA1 == 1
    /* enabled */
#else
    #define NO_SHA
#endif

#undef NO_SHA256
#if defined(WOLF_CONF_SHA2_256) && WOLF_CONF_SHA2_256 == 1
    #if defined(WOLF_CONF_SHA2_224) && WOLF_CONF_SHA2_224 == 1
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

#undef WOLFSSL_SHA512
#if defined(WOLF_CONF_SHA2_512) && WOLF_CONF_SHA2_512 == 1
    #define WOLFSSL_SHA512
    #define HAVE_SHA512
#endif

#undef WOLFSSL_SHA384
#if defined(WOLF_CONF_SHA2_384) && WOLF_CONF_SHA2_384 == 1
    #define WOLFSSL_SHA384
#endif

#undef WOLFSSL_SHA3
#if defined(WOLF_CONF_SHA3) && WOLF_CONF_SHA3 == 1
    #define WOLFSSL_SHA3
#endif

#if defined(WOLF_CONF_MD5) && WOLF_CONF_MD5 == 1
    /* enabled */
#else
    #define NO_MD5
#endif

/* =========================================================================
 * Post-Quantum Crypto
 * ========================================================================= */
/* ML-KEM (Kyber) */
#if defined(WOLF_CONF_KYBER) && WOLF_CONF_KYBER == 1
    #undef  WOLFSSL_EXPERIMENTAL_SETTINGS
    #define WOLFSSL_EXPERIMENTAL_SETTINGS
    #undef  WOLFSSL_HAVE_MLKEM
    #define WOLFSSL_HAVE_MLKEM
    #undef  WOLFSSL_NO_SHAKE128
    #undef  WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE128
    #undef  WOLFSSL_NO_SHAKE256
    #undef  WOLFSSL_SHAKE256
    #define WOLFSSL_SHAKE256
    #undef  WOLFSSL_SHA3
    #define WOLFSSL_SHA3
#endif

/* ML-DSA-44 (FIPS 204) — smallest parameter set only */
#define WOLFSSL_HAVE_MLDSA
#define HAVE_DILITHIUM
#define WOLFSSL_NO_ML_DSA_65
#define WOLFSSL_NO_ML_DSA_87
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_NO_ML_KEM_1024

/* =========================================================================
 * Crypto Acceleration
 * ========================================================================= */
#if defined(WOLF_CONF_ARMASM) && WOLF_CONF_ARMASM == 1
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO
    #define WOLFSSL_ARMASM_NO_NEON
    #define WOLFSSL_ARMASM_THUMB2
    #define WOLFSSL_ARM_ARCH 7
    #undef  NO_STM32_HASH
    #define NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define NO_STM32_CRYPTO
#endif

/* =========================================================================
 * Benchmark / Test
 * ========================================================================= */
#define BENCH_EMBEDDED

/* ML-KEM / ML-DSA TLS client size cuts */
#define WOLFSSL_SHA3_SMALL
#define WOLFSSL_MLKEM_SMALL
#define WOLFSSL_MLKEM_NO_ENCAPSULATE
#define WOLFSSL_MLDSA_SMALL
#define USE_SLOW_SHA512           /* SHA-384 via sha512.c — smaller, slower */

/* =========================================================================
 * Debugging
 * ========================================================================= */
#if defined(WOLF_CONF_DEBUG) && WOLF_CONF_DEBUG == 1
    #define DEBUG_WOLFSSL
#endif

/* =========================================================================
 * Port / Time
 * ========================================================================= */
#include <time.h>
#define TIME_OVERRIDES
#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE
#define WOLFSSL_USER_CURRTIME

/* =========================================================================
 * RNG
 * ========================================================================= */
#define NO_OLD_RNGNAME
#if !defined(WOLF_CONF_RNG) || WOLF_CONF_RNG == 1
    #define HAVE_HASHDRBG
#else
    #define WC_NO_HASHDRBG
    #define WC_NO_RNG
#endif

/* =========================================================================
 * Disable Features
 * ========================================================================= */
#if defined(WOLF_CONF_TLS12) && WOLF_CONF_TLS12 == 0
    #define WOLFSSL_NO_TLS12
#endif
#if defined(WOLF_CONF_WOLFCRYPT_ONLY) && WOLF_CONF_WOLFCRYPT_ONLY == 1
    #define WOLFCRYPT_ONLY
#endif

#if defined(WOLF_CONF_TEST) && WOLF_CONF_TEST == 0
    #define NO_CRYPT_TEST
    #define NO_CRYPT_BENCHMARK
#endif

#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_OLD_TLS
#define NO_SERVER

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_ERROR_STRINGS          /* drop wolfCrypt error strings — saves flash */
#define WOLFSSL_NO_PEM            /* certs/keys are DER; drop PEM banners */
#define NO_CODING                 /* Base64 only served PEM conversion */

#ifndef WOLFSSL_SHAKE128
#define WOLFSSL_NO_SHAKE128
#endif
#ifndef WOLFSSL_SHAKE256
#define WOLFSSL_NO_SHAKE256
#endif

#ifdef __cplusplus
}
#endif
#endif /* USER_SETTINGS_H */
