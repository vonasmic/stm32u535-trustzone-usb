/**
 * @file    se_usb_tls.c
 * @brief   Secure USB rings + TLS service (command parsing lives in NonSecure)
 */
#include "se_usb_tls.h"
#include "se_tls_json_client.h"
#include "se_time.h"
#include "wolfssl/ssl.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static SeUsbRxRing s_rx;
static SeUsbTxRing s_tx;
static uint8_t s_active;
static uint8_t s_dtr;
/* After the first TLS record byte is queued, DEBUG must not share the CDC TX. */
static uint8_t s_tls_wire;

static uint32_t rx_free(void)
{
    return SE_USB_RX_RING_SIZE - s_rx.count;
}

static uint32_t tx_free(void)
{
    return SE_USB_TX_RING_SIZE - s_tx.count;
}

static int rx_write(const uint8_t *data, uint32_t len)
{
    uint32_t i;

    if (len == 0U) {
        return 0;
    }
    if (len > rx_free()) {
        s_rx.overflow = 1U;
        return -1;
    }
    for (i = 0U; i < len; i++) {
        s_rx.buf[s_rx.head] = data[i];
        s_rx.head = (s_rx.head + 1U) % SE_USB_RX_RING_SIZE;
        s_rx.count++;
    }
    return (int)len;
}

static int rx_read(uint8_t *out, int max)
{
    int n = 0;

    if (max <= 0) {
        return 0;
    }
    while (n < max && s_rx.count > 0U) {
        out[n++] = s_rx.buf[s_rx.tail];
        s_rx.tail = (s_rx.tail + 1U) % SE_USB_RX_RING_SIZE;
        s_rx.count--;
    }
    return n;
}

static int tx_write(const uint8_t *data, uint32_t len)
{
    uint32_t i;

    if (len == 0U) {
        return 0;
    }
    if (len > tx_free()) {
        return -1;
    }
    for (i = 0U; i < len; i++) {
        s_tx.buf[s_tx.head] = data[i];
        s_tx.head = (s_tx.head + 1U) % SE_USB_TX_RING_SIZE;
        s_tx.count++;
    }
    return (int)len;
}

static int tx_read(uint8_t *out, uint32_t max, uint32_t *got)
{
    uint32_t n = 0U;

    if (got != NULL) {
        *got = 0U;
    }
    if (out == NULL || max == 0U) {
        return -1;
    }
    while (n < max && s_tx.count > 0U) {
        out[n++] = s_tx.buf[s_tx.tail];
        s_tx.tail = (s_tx.tail + 1U) % SE_USB_TX_RING_SIZE;
        s_tx.count--;
    }
    if (got != NULL) {
        *got = n;
    }
    return (n > 0U) ? 0 : 1;
}

static void link_reset_flags(void)
{
    s_tls_wire = 0U;
}

void se_usb_tls_init(void)
{
    se_usb_tls_reset();
}

void se_usb_tls_clear_rings(void)
{
    (void)memset(&s_rx, 0, sizeof(s_rx));
    (void)memset(&s_tx, 0, sizeof(s_tx));
    s_tls_wire = 0U;
}

void se_usb_tls_clear_rx(void)
{
    (void)memset(&s_rx, 0, sizeof(s_rx));
}

void se_usb_tls_end_tls_wire(void)
{
    /* Drop any queued TLS records; allow DEBUG again. */
    (void)memset(&s_tx, 0, sizeof(s_tx));
    s_tls_wire = 0U;
}

void se_usb_tls_reset(void)
{
    se_usb_tls_clear_rings();
    s_active = 0U;
    s_dtr = 0U;
    link_reset_flags();
}

void se_usb_tls_set_active(uint8_t active)
{
    s_active = active ? 1U : 0U;
    if (s_active == 0U) {
        link_reset_flags();
    }
}

void se_usb_tls_set_dtr(uint8_t dtr)
{
    uint8_t prev = s_dtr;
    s_dtr = dtr ? 1U : 0U;
    if (prev != 0U && s_dtr == 0U) {
        se_tls_json_reset_quiet();
        link_reset_flags();
    } else if (prev == 0U && s_dtr != 0U) {
        se_tls_json_reset_quiet();
        link_reset_flags();
        se_usb_tls_clear_rings();
    }
}

int se_usb_tls_rx_push(const uint8_t *data, uint32_t len)
{
    if (s_active == 0U) {
        return -1;
    }
    if (s_rx.overflow != 0U) {
        return -1;
    }
    return rx_write(data, len);
}

int se_usb_tls_tx_pop(uint8_t *out, uint32_t max, uint32_t *out_len)
{
    if (s_active == 0U) {
        return -1;
    }
    return tx_read(out, max, out_len);
}

void se_usb_debug_printf(const char *fmt, ...)
{
    char buf[192];
    va_list ap;
    int body;
    int total;

    /* Never interleave ASCII with TLS records on the same CDC pipe. */
    if ((s_active == 0U) || (fmt == NULL) || (s_tls_wire != 0U)) {
        return;
    }

    (void)memcpy(buf, "DEBUG: ", 7);
    va_start(ap, fmt);
    body = vsnprintf(buf + 7, sizeof(buf) - 9U, fmt, ap);
    va_end(ap);
    if (body < 0) {
        return;
    }
    if ((uint32_t)body >= (sizeof(buf) - 9U)) {
        body = (int)(sizeof(buf) - 10U);
    }
    total = 7 + body;
    buf[total++] = '\r';
    buf[total++] = '\n';

    (void)tx_write((const uint8_t *)buf, (uint32_t)total);
}

int se_tls_embed_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int got;

    (void)ssl;
    (void)ctx;

    if (buf == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (s_rx.overflow != 0U) {
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    if (s_active == 0U || s_dtr == 0U) {
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    got = rx_read((uint8_t *)buf, sz);
    if (got == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return got;
}

int se_tls_embed_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    uint32_t room;
    uint32_t n;

    (void)ssl;
    (void)ctx;

    if (buf == NULL || sz <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (s_active == 0U || s_dtr == 0U) {
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }

    /*
     * Wait until host has drained DEBUG lines so ClientHello is not glued
     * to "DEBUG: ..." in one USB/TCP read (BouncyCastle record_overflow).
     */
    if ((s_tls_wire == 0U) && (s_tx.count > 0U)) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }

    room = tx_free();
    if (room == 0U) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    n = (uint32_t)sz;
    if (n > room) {
        n = room;
    }
    if (tx_write((const uint8_t *)buf, n) < 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    s_tls_wire = 1U;
    return (int)n;
}

void se_usb_tls_service_once(void)
{
    if (s_rx.overflow != 0U) {
        se_tls_json_abort();
        link_reset_flags();
        se_usb_debug_printf("RX overflow, abort");
        return;
    }
    if ((s_active == 0U) || (s_dtr == 0U)) {
        return;
    }
    /* NonSecure arms TLS by setting time; do not start until then. */
    if (se_time_is_synced() == 0) {
        return;
    }

    se_tls_json_service_once();
}
