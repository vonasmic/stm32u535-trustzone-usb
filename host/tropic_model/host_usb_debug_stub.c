/**
 * @file    host_usb_debug_stub.c
 * @brief   stdout stand-in for se_usb_debug_printf (A–J tests; not se_host)
 */
#include "se_usb_tls.h"
#include <stdarg.h>
#include <stdio.h>

void se_usb_debug_printf(const char *fmt, ...)
{
    va_list ap;

    if (fmt == NULL) {
        return;
    }
    va_start(ap, fmt);
    (void)vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    (void)fflush(stdout);
}

uint32_t se_usb_tls_rx_count(void)
{
    return 0U;
}

int se_usb_tls_rx_take(uint8_t *out, uint32_t max)
{
    (void)out;
    (void)max;
    return 0;
}

uint8_t se_usb_tls_rx_overflow(void)
{
    return 0U;
}

void se_usb_tls_clear_rx(void)
{
}
