/**
 * @file    se_usb_tls.h
 * @brief   Secure-side USB byte rings for the TLS client
 *
 * Opaque CDC pipe for TLS records only. Host command parsing and TLS arming
 * are done in NonSecure; Secure starts the client after
 * PROVISION / ENCRYPT / DECRYPT / MANAGE <unix>.
 */
#ifndef SE_USB_TLS_H
#define SE_USB_TLS_H

#include <stdint.h>

#define SE_USB_RX_RING_SIZE 16384u
#define SE_USB_TX_RING_SIZE 8192u

/** CDC status frame: DEBUG:<text>:DEBUG followed by CRLF. Host splits TLS at :DEBUG. */
#define SE_USB_DEBUG_PREFIX     "DEBUG:"
#define SE_USB_DEBUG_PREFIX_LEN 6u
#define SE_USB_DEBUG_SUFFIX     ":DEBUG"
#define SE_USB_DEBUG_SUFFIX_LEN 6u

typedef struct {
    uint8_t  buf[SE_USB_RX_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    uint8_t  overflow;
} SeUsbRxRing;

typedef struct {
    uint8_t  buf[SE_USB_TX_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} SeUsbTxRing;

void se_usb_tls_init(void);
void se_usb_tls_reset(void);
void se_usb_tls_clear_rings(void);
void se_usb_tls_clear_rx(void);
/** Clear TX TLS bytes and allow DEBUG status lines again. */
void se_usb_tls_end_tls_wire(void);

void se_usb_tls_set_active(uint8_t active);
void se_usb_tls_set_dtr(uint8_t dtr);

int se_usb_tls_rx_push(const uint8_t *data, uint32_t len);
int se_usb_tls_tx_pop(uint8_t *out, uint32_t max, uint32_t *out_len);
uint32_t se_usb_tls_rx_count(void);
int se_usb_tls_rx_take(uint8_t *out, uint32_t max);
uint8_t se_usb_tls_rx_overflow(void);

/** Queue a framed DEBUG status line on the CDC TX ring for the host bridge. */
void se_usb_debug_printf(const char *fmt, ...);

void se_usb_tls_service_once(void);

#endif /* SE_USB_TLS_H */
