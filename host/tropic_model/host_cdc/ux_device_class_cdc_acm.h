/**
 * @file    ux_device_class_cdc_acm.h
 * @brief   Host-only CDC ACM surface used by tls_usb_io.c
 */
#ifndef UX_DEVICE_CLASS_CDC_ACM_H
#define UX_DEVICE_CLASS_CDC_ACM_H

#include "ux_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct UX_SLAVE_CLASS_CDC_ACM_STRUCT {
    int unused;
} UX_SLAVE_CLASS_CDC_ACM;

typedef struct {
    ULONG ux_slave_class_cdc_acm_parameter_dtr;
    ULONG ux_slave_class_cdc_acm_parameter_rts;
} UX_SLAVE_CLASS_CDC_ACM_LINE_STATE_PARAMETER;

#define UX_SLAVE_CLASS_CDC_ACM_IOCTL_GET_LINE_STATE 1u

UINT ux_device_class_cdc_acm_read_run(UX_SLAVE_CLASS_CDC_ACM *cdc, UCHAR *buffer,
                                      ULONG requested_length, ULONG *actual_length);
UINT ux_device_class_cdc_acm_write_run(UX_SLAVE_CLASS_CDC_ACM *cdc, UCHAR *buffer,
                                       ULONG requested_length, ULONG *actual_length);
UINT ux_device_class_cdc_acm_ioctl(UX_SLAVE_CLASS_CDC_ACM *cdc, ULONG ioctl_function,
                                   VOID *parameter);

#ifdef __cplusplus
}
#endif

#endif /* UX_DEVICE_CLASS_CDC_ACM_H */
