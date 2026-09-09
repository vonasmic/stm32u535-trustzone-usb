/**
 * @file    ux_api.h
 * @brief   Host-only USBX stubs so tls_usb_io.c compiles against a PTY
 */
#ifndef UX_API_H
#define UX_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int  UINT;
typedef unsigned long ULONG;
typedef unsigned char UCHAR;
typedef void          VOID;

#define UX_SUCCESS      0u
#define UX_STATE_WAIT   0u
#define UX_STATE_NEXT   1u
#define UX_STATE_EXIT   2u
#define UX_STATE_ERROR  3u

#ifdef __cplusplus
}
#endif

#endif /* UX_API_H */
