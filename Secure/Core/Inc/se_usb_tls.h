/**
 * @file    se_usb_tls.h
 * @brief   Secure-side USB byte rings for the TLS client
 *
 * Plain console bytes and TLS records share one TX ring but stay separate
 * spans. NonSecure frames each span as type 0x00 or 0x01. Host command
 * parsing and TLS arming live in NonSecure; Secure starts the client after
 * PROVISION / ENCRYPT / DECRYPT / MANAGE <unix>.
 */
#ifndef SE_USB_TLS_H
#define SE_USB_TLS_H

#include <stdint.h>

#define SE_USB_RX_RING_SIZE 8192u
#define SE_USB_TX_RING_SIZE 8192u

/** Largest console hex body: raw ML-DSA-44 pub (CLIENT CSR). */
#define SE_USB_REPLY_BODY_MAX 1312u

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
/** Drop queued TX bytes (abort / link drop). */
void se_usb_tls_end_tls_wire(void);
/**
 * Session is over. TLS bytes already queued (manage reply, close_notify)
 * stay type 0x01 until popped. Plain console bytes stay type 0x00.
 */
void se_usb_tls_release_tls_wire(void);
/** Non-zero while a finished session still has TLS TX bytes to drain. */
int se_usb_tls_tx_draining(void);
/** Drop leftover plain TX before a new ClientHello, when no TLS span is queued. */
void se_usb_tls_discard_idle_tx(void);

void se_usb_tls_set_active(uint8_t active);
void se_usb_tls_set_dtr(uint8_t dtr);

int se_usb_tls_rx_push(const uint8_t *data, uint32_t len);
/**
 * Pop the next span, stopping at a type change.
 * @p out_type is 0x00 plain or 0x01 TLS. 0 data, 1 empty, -1 link down.
 */
int se_usb_tls_tx_pop(uint8_t *out, uint32_t max, uint32_t *out_len, uint8_t *out_type);
uint32_t se_usb_tls_rx_count(void);
int se_usb_tls_rx_take(uint8_t *out, uint32_t max);
uint8_t se_usb_tls_rx_overflow(void);

/** Plain ASCII console line. 0 queued, -1 dropped (link down or TX full). */
int se_usb_debug_puts(const char *msg);
/** Queue ASCII {@code failed}. */
void se_usb_failed(void);

void se_usb_tls_service_once(void);

#endif /* SE_USB_TLS_H */
