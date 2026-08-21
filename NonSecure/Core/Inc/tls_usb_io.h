/**
 * @file    tls_usb_io.h
 * @brief   NonSecure USB CDC: host commands + opaque TLS pipe into Secure
 */
#ifndef TLS_USB_IO_H
#define TLS_USB_IO_H

#include "ux_api.h"
#include "ux_device_class_cdc_acm.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void tls_usb_io_init(void);
void tls_usb_io_reset(void);

void tls_usb_cdc_activate(UX_SLAVE_CLASS_CDC_ACM *cdc);
void tls_usb_cdc_deactivate(void);
void tls_usb_cdc_parameter_change(UX_SLAVE_CLASS_CDC_ACM *cdc);

int  tls_usb_dtr_asserted(void);
int  tls_usb_connected(void);

void tls_usb_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* TLS_USB_IO_H */
