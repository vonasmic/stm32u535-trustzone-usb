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

/** Typed dump on CDC TX. Host leftover splits on this magic (not TLS 0x16). */
#define SE_USB_DUMP_MAGIC    0xB1u
#define SE_USB_DUMP_OK       0u
#define SE_USB_DUMP_ERR      1u
#define SE_USB_DUMP_EMPTY    2u
#define SE_USB_DUMP_REFUSED  3u
#define SE_USB_DUMP_HDR_LEN  4u
/** Largest dump body: raw ML-DSA-44 pub (CLIENT CSR). */
#define SE_USB_DUMP_BODY_MAX 1312u

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
/** Clear TX TLS bytes and allow ASCII / dump frames again. */
void se_usb_tls_end_tls_wire(void);

void se_usb_tls_set_active(uint8_t active);
void se_usb_tls_set_dtr(uint8_t dtr);

int se_usb_tls_rx_push(const uint8_t *data, uint32_t len);
int se_usb_tls_tx_pop(uint8_t *out, uint32_t max, uint32_t *out_len);
uint32_t se_usb_tls_rx_count(void);
int se_usb_tls_rx_take(uint8_t *out, uint32_t max);
uint8_t se_usb_tls_rx_overflow(void);

/** Plain ASCII line (HELP / PING / INFO). Not used for errors. */
void se_usb_debug_puts(const char *msg);
/** USB / TLS / Tropic failure: the string {@code failed} only. */
void se_usb_failed(void);
/** Queue {@code 0xB1 | status | u16le len | body}. 0 on success, -1 if the ring is full. */
int se_usb_dump(uint8_t status, const uint8_t *body, uint16_t len);

void se_usb_tls_service_once(void);

#endif /* SE_USB_TLS_H */
