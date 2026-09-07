/* Libtropic compiled into se_tropic_port_stm32.o (CubeIDE makefile does not
 * emit these objects). Host CMake links libtropic separately. Do not add this
 * file as its own translation unit.
 *
 * HAL SPI is CubeMX-owned (stm32u5xx_hal_spi*.c in Secure/.project). Do not
 * compile those sources here or the link gets two HAL_SPI_* definitions.
 *
 * wc_ForceZero is wolfSSL's guaranteed-wipe helper; libtropic otherwise
 * #warning's on a volatile-pointer fallback (newlib-nano has no explicit_bzero).
 */
#include <wolfssl/wolfcrypt/memory.h>
#ifndef LT_HAVE_EXPLICIT_BZERO
#define LT_HAVE_EXPLICIT_BZERO
#define explicit_bzero(p, n) wc_ForceZero((p), (word32)(n))
#endif

#include "../../../libtropic/src/libtropic_secure_memzero.c"
#include "../../../libtropic/src/lt_crc16.c"
#include "../../../libtropic/src/lt_port_wrap.c"
#include "../../../libtropic/src/lt_l1.c"
#include "../../../libtropic/src/lt_l2_frame_check.c"
#include "../../../libtropic/src/libtropic_l2.c"
#include "../../../libtropic/src/lt_l3_process.c"
#include "../../../libtropic/src/libtropic_l3.c"
#include "../../../libtropic/src/lt_hkdf.c"
#include "../../../libtropic/src/lt_asn1_der.c"
#include "../../../libtropic/src/lt_tr01_attrs.c"
#include "../../../libtropic/src/libtropic_default_sh0_keys.c"
#include "../../../libtropic/src/libtropic.c"
#include "../../../libtropic/cal/wolfcrypt/lt_wolfcrypt_common.c"
#include "../../../libtropic/cal/wolfcrypt/lt_wolfcrypt_sha256.c"
#include "../../../libtropic/cal/wolfcrypt/lt_wolfcrypt_hmac_sha256.c"
#include "../../../libtropic/cal/wolfcrypt/lt_wolfcrypt_aesgcm.c"
#include "../../../libtropic/cal/wolfcrypt/lt_wolfcrypt_x25519.c"
#include "../../../libtropic/hal/stm32/stm32u5xx/libtropic_port_stm32u5xx.c"
