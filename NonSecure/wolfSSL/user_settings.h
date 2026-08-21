/**
 ******************************************************************************
 * @file    NonSecure/wolfSSL/user_settings.h
 * @brief   wolfSSL configuration for the NonSecure world (STM32U535, TrustZone)
 *
 * This file is the durable wolfSSL configuration for the NonSecure world.
 * It is a copy of the CubeMX-generated wolfSSL.I-CUBE-wolfSSL_conf.h with the
 * deltas listed below applied. CubeMX may regenerate wolfSSL.I-CUBE-wolfSSL_conf.h
 * at any time; this file is never touched by the code generator.
 *
 * Activate with -DWOLFSSL_USER_SETTINGS in the NonSecure .cproject preprocessor
 * list. wolfSSL's settings.h includes this file instead of the Cube conf when
 * that macro is defined.
 *
 * ============================================================================
 * DELTAS vs wolfSSL.I-CUBE-wolfSSL_conf.h (NonSecure)
 * ============================================================================
 *
 * 1. WOLF_CONF_TPM changed from 0 -> 1
 *    Enables WOLF_CRYPTO_CB, WOLFSSL_PUBLIC_MP, WOLFSSL_AES_CFB.
 *    No wolfTPM driver is added; these flags prepare the build for a future
 *    TPM integration in Secure and are required by the PKCS#11 crypto-callback
 *    path today (WOLF_CRYPTO_CB must be defined).
 *
 * 2. HAVE_PKCS11 + HAVE_PKCS11_STATIC added
 *    Enables wc_Pkcs11_CryptoDevCb() and the static (no-dlopen) PKCS#11 path.
 *    The NonSecure C_*() stubs (pkcs11_stub.c) forward each call to the
 *    corresponding C_*_nsc_call() veneer in the Secure image.
 *
 * 3. WC_USE_DEVID added (value 0x53454300 = 'SEC\0')
 *    All wolfCrypt contexts (Aes, ecc_key, wc_MlKemKey, Hmac, WC_RNG …) default
 *    to this device ID so wc_Pkcs11_CryptoDevCb routes them to Secure wolfCrypt
 *    without explicit devId passing in application code.
 *
 * 4. WOLF_CRYPTO_CB_ONLY_AES + WOLF_CRYPTO_CB_ONLY_ECC added
 *    Removes the NonSecure software AES and ECC implementations.  Any AES or
 *    ECC operation that cannot reach the registered device callback will fail
 *    with NO_VALID_DEVID rather than silently falling back to software.
 *
 * 5. WOLF_CRYPTO_CB_AES_SETKEY + WOLF_CRYPTO_CB_COPY + WOLF_CRYPTO_CB_FREE added
 *    Required by the PKCS#11 crypto-callback internals for AES key import,
 *    algorithm-context copying (TLS handshake transcript hash copy) and
 *    object teardown.
 *
 * 6. NO_STM32_RNG added
 *    The hardware RNG peripheral is owned by the Secure world (GTZC).  The
 *    NonSecure build must not attempt to access it directly; RNG operations
 *    are serviced by the Secure PKCS#11 token via C_GenerateRandom_nsc_call.
 *
 * 7. ML-DSA-44 enabled: WOLFSSL_HAVE_MLDSA + WOLFSSL_NO_ML_DSA_65 + WOLFSSL_NO_ML_DSA_87
 *    Activates the FIPS 204 ML-DSA-44 parameter set only (smallest, 1312 B pub,
 *    2560 B priv, 2420 B sig).  ML-DSA-65 and ML-DSA-87 are explicitly disabled
 *    to keep flash usage manageable on the 256 KB STM32U535.
 *    wc_mldsa.c is already in the project link list but was compiled out; these
 *    defines enable it.  Keygen/sign/verify are offloaded via C_GenerateKeyPair /
 *    C_Sign / C_Verify (WOLFSSL_HAVE_MLDSA path in wc_Pkcs11_CryptoDevCb).
 *
 * 8. Platform: STM32U535xx added next to STM32U575xx
 *    STM32U535xx was not listed in the CubeMX #elif chain, causing both builds
 *    to fall into the #else branch (WOLFSSL_STM32F4 + #warning).
 *    U535 follows U575: WOLFSSL_STM32U5 + STM32_HAL_V2, correct HAL header
 *    (stm32u5xx_hal.h), no HASH/CRYP/PKA acceleration (those are kept off via
 *    NO_STM32_HASH / NO_STM32_CRYPTO which the new branch does not undef).
 *
 * NOTE: WOLF_CRYPTO_CB_ONLY_SHA256 is intentionally NOT set here.
 *       TLS 1.3 transcript hashing (SHA-256/384) still runs in NonSecure
 *       software with the stock callback because wc_Pkcs11_CryptoDevCb does
 *       not handle WC_ALGO_TYPE_HASH.  Enabling ONLY_SHA256 now would cause
 *       wc_Sha256Update/Final to return NO_VALID_DEVID during the handshake.
 *
 * 9. WOLF_CONF_MATH 4 -> 3
 *    NonSecure does not run SP ECC/RSA (WOLF_CRYPTO_CB_ONLY_ECC).  Drop
 *    WOLFSSL_SP_ARM_CORTEX_M_ASM so sp_cortexm.c is compiled out.
 *
 * 10. WOLF_CONF_TEST 1 -> 0, plus NO_ERROR_STRINGS and WOLFSSL_SHA3_SMALL
 *     CubeMX left crypt-test enabled.  SHA-3 is pulled in by ML-KEM/SHAKE;
 *     the small Keccak is enough on NS.
 *
 * 11. TIME_OVERRIDES: XTIME/XGMTIME in wc_port_time.c (Secure RTC via NSC).
 *     Do not define wc_Time() — asn.c already exports it.
 *
 * 12. Flash: drop unused TLS 1.2 extras, test cert buffers, AES-CFB,
 *     extra ML-KEM sizes.  Enable WOLFSSL_MLKEM_SMALL, WOLFSSL_MLDSA_SMALL,
 *     WOLFSSL_MLDSA_NO_MAKE_KEY, WOLFSSL_MLKEM_NO_ENCAPSULATE.
 *     TLS client uses ML-KEM-768 only (no hybrid ECC/X25519 groups).
 * ============================================================================
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
 * WOLF_CONF_* values — same as CubeMX except where noted by [DELTA]
 * ========================================================================= */

#define WOLF_CONF_DEBUG           0
#define WOLF_CONF_WOLFCRYPT_ONLY  0
#define WOLF_CONF_TLS13           1
#define WOLF_CONF_TLS12           0
#define WOLF_CONF_DTLS            0
#define WOLF_CONF_MATH            3   /* [DELTA 9] was 4 — SP C, no Cortex-M ASM (crypto is in Secure) */
#define WOLF_CONF_RTOS            1
#define WOLF_CONF_RNG             1
#define WOLF_CONF_RSA             0
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
#define WOLF_CONF_SHA3            0
#define WOLF_CONF_PSK             0
#define WOLF_CONF_PWDBASED        0
#define WOLF_CONF_KEEP_PEER_CERT  0
#define WOLF_CONF_BASE64_ENCODE   0
#define WOLF_CONF_OPENSSL_EXTRA   0
#define WOLF_CONF_TEST            0   /* [DELTA 10] was 1 — no wolfcrypt test/benchmark in NS image */
#define WOLF_CONF_KYBER           1
#define WOLF_CONF_ARMASM          0
#define WOLF_CONF_IO              1
#define WOLF_CONF_RESUMPTION      0
#define WOLF_CONF_TPM             1   /* [DELTA 1] was 0 — enables WOLF_CRYPTO_CB */
#define WOLF_CONF_PK              0

/* =========================================================================
 * [DELTA 2] PKCS#11 static path
 * ========================================================================= */
#define HAVE_PKCS11
#define HAVE_PKCS11_STATIC
#define WOLFPKCS11_NO_ENV   /* no getenv/setenv on bare metal */

/* =========================================================================
 * [DELTA 3] Default device ID = Secure PKCS#11 token
 * ========================================================================= */
#define WC_USE_DEVID   0x53454300   /* 'SEC\0' */

/* =========================================================================
 * [DELTA 4] No NonSecure software AES / ECC — force everything through the
 * registered PKCS#11 crypto callback.
 * ========================================================================= */
#define WOLF_CRYPTO_CB_ONLY_AES
#define WOLF_CRYPTO_CB_ONLY_ECC

/* =========================================================================
 * [DELTA 5] Crypto-callback extensions required by PKCS#11 objects
 * ========================================================================= */
#define WOLF_CRYPTO_CB_AES_SETKEY
#define WOLF_CRYPTO_CB_COPY
#define WOLF_CRYPTO_CB_FREE

/* =========================================================================
 * Hardware platform
 * =========================================================================
 * Defaults (no HW acceleration, no TLS UART test) — applied before the
 * per-chip branch so each branch can selectively undef.
 */
#define NO_STM32_HASH
#define NO_STM32_CRYPTO
#define NO_TLS_UART_TEST
/* [DELTA 6] HAL RNG is owned by Secure world — NonSecure must not touch it */
#define NO_STM32_RNG

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
    /* NO_STM32_RNG already set above for NonSecure; keep it */
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart4
    #endif
#elif defined(STM32F401xE)
    #define WOLFSSL_STM32F4
    #define WOLFSSL_GENSEED_FORTEST /* no HW RNG is available use test seed */
    #ifndef HAL_CONSOLE_UART
    #define HAL_CONSOLE_UART huart2
    #endif
#elif defined(STM32G071xx)
    #define WOLFSSL_STM32G0
    #define WOLFSSL_GENSEED_FORTEST /* no HW RNG is available use test seed */
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
/* [DELTA 8] STM32U535xx added alongside STM32U575xx.
 * Maps to WOLFSSL_STM32U5 + STM32_HAL_V2 (correct HAL header: stm32u5xx_hal.h).
 * NO_STM32_HASH / NO_STM32_CRYPTO are NOT undef'd here — U535 has no HASH/CRYP
 * peripheral enabled in this project.  NO_STM32_RNG stays defined (set above)
 * because RNG is owned by Secure world. */
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
    //#define STM32_HAL_V2
    //#define WOLFSSL_STM32_PKA
    //#define WOLFSSL_GENSEED_FORTEST
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
 * Network stack: 1=User IO (custom)
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
 * Operating System: 1=Bare-metal/Single threaded
 * ========================================================================= */
#if defined(WOLF_CONF_RTOS) && WOLF_CONF_RTOS == 2
    #define FREERTOS
    #define WOLFSSL_NO_REALLOC
#else
    #define SINGLE_THREADED
#endif

/* =========================================================================
 * Math Configuration (WOLF_CONF_MATH=4: SP ASM Cortex-M3+)
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
#define WOLFSSL_ASN_TEMPLATE

#if defined(WOLF_CONF_TLS13) && WOLF_CONF_TLS13 == 1
    #define WOLFSSL_TLS13
    #define HAVE_HKDF
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

/* TPM / WOLF_CRYPTO_CB (WOLF_CONF_TPM=1 set above) */
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
/* RSA */
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

/* ECC */
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

/* DH */
#undef NO_DH
#if defined(WOLF_CONF_DH) && WOLF_CONF_DH == 1
    #define HAVE_DH
    #define HAVE_FFDHE_2048
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

/* AES */
#if defined(WOLF_CONF_AESGCM) && WOLF_CONF_AESGCM >= 1
    #define HAVE_AESGCM
    #define HAVE_AES_DECRYPT
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

/* AES CFB is a wolfTPM need; NonSecure has no TPM parameter encryption. */

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if defined(WOLF_CONF_CHAPOLY) && WOLF_CONF_CHAPOLY == 1
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if defined(WOLF_CONF_EDCURVE25519) && WOLF_CONF_EDCURVE25519 == 1
    #define HAVE_CURVE25519
    #define HAVE_ED25519
    #define CURVED25519_SMALL
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
    #define WOLFSSL_SHA3_SMALL     /* [DELTA 10] compact Keccak for SHAKE/ML-KEM */
    #define WOLFSSL_MLKEM_SMALL
    #define WOLFSSL_MLKEM_NO_ENCAPSULATE  /* TLS client decapsulates only */
#endif

/* [DELTA 7] ML-DSA-44 (FIPS 204) — only the smallest parameter set */
#define WOLFSSL_HAVE_MLDSA
#define HAVE_DILITHIUM         /* legacy alias required by some code paths */
#define WOLFSSL_NO_ML_DSA_65   /* disable ML-DSA-65 to save flash */
#define WOLFSSL_NO_ML_DSA_87   /* disable ML-DSA-87 to save flash */
#define WOLFSSL_MLDSA_SMALL
#define WOLFSSL_MLDSA_NO_MAKE_KEY  /* keygen lives in Secure PKCS#11 */

/* =========================================================================
 * Crypto Acceleration (disabled)
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

#if 0 /* client auth required for Java mTLS */
#define WOLFSSL_NO_CLIENT_AUTH
#endif

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_ERROR_STRINGS          /* [DELTA 10] drop wolfCrypt error strings */

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
