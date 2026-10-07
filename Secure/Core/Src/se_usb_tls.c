/**
 * @file    se_usb_tls.c
 * @brief   Secure USB rings + TLS service (command parsing lives in NonSecure)
 *
 * TX is one byte ring plus a span queue. Plain console is type 0x00, TLS is
 * type 0x01. Adjacent writes of the same type merge. A pop stops at a type
 * change so the two streams can sit in the ring together.
 */
#include "se_usb_tls.h"
#include "se_tls_client.h"
#include "se_time.h"
#include "wolfssl/ssl.h"
#include <string.h>

/** Same values as USB_FRAME_TYPE_CMD / USB_FRAME_TYPE_SEC. */
#define SE_USB_PLAIN 0x00u
#define SE_USB_TLS   0x01u

#define SE_USB_TX_SPAN_MAX 48u

typedef struct {
    uint32_t len;
    uint8_t type;
} TxSpan;

static SeUsbRxRing s_rx;
static SeUsbTxRing s_tx;
static TxSpan s_span[SE_USB_TX_SPAN_MAX];
static uint16_t s_span_head;
static uint16_t s_span_tail;
static uint16_t s_span_count;
static uint8_t s_active;
static uint8_t s_dtr;
/* 1: TLS bytes are queued. 2: session finished, those TLS bytes still need to leave. */
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
        /* Backpressure: caller retries after wolfSSL drains. Do not stick overflow. */
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

static void tx_clear(void)
{
    (void)memset(&s_tx, 0, sizeof(s_tx));
    s_span_head = 0U;
    s_span_tail = 0U;
    s_span_count = 0U;
}

static int tx_span_has(uint8_t type)
{
    uint16_t i;
    uint16_t idx = s_span_tail;

    for (i = 0U; i < s_span_count; i++) {
        if (s_span[idx].type == type) {
            return 1;
        }
        idx = (uint16_t)((idx + 1U) % SE_USB_TX_SPAN_MAX);
    }
    return 0;
}

static void tx_note_tls_drained(void)
{
    if ((s_tls_wire == 2U) && (tx_span_has(SE_USB_TLS) == 0)) {
        s_tls_wire = 0U;
    }
}

static int tx_write(const uint8_t *data, uint32_t len, uint8_t type)
{
    uint32_t i;

    if (len == 0U) {
        return 0;
    }
    if (len > tx_free()) {
        return -1;
    }
    if (s_span_count > 0U) {
        uint16_t last = (uint16_t)((s_span_head + SE_USB_TX_SPAN_MAX - 1U) % SE_USB_TX_SPAN_MAX);

        if (s_span[last].type == type) {
            s_span[last].len += len;
            goto store;
        }
    }
    if (s_span_count >= SE_USB_TX_SPAN_MAX) {
        return -1;
    }
    s_span[s_span_head].len = len;
    s_span[s_span_head].type = type;
    s_span_head = (uint16_t)((s_span_head + 1U) % SE_USB_TX_SPAN_MAX);
    s_span_count++;
store:
    for (i = 0U; i < len; i++) {
        s_tx.buf[s_tx.head] = data[i];
        s_tx.head = (s_tx.head + 1U) % SE_USB_TX_RING_SIZE;
        s_tx.count++;
    }
    return (int)len;
}

static int tx_read(uint8_t *out, uint32_t max, uint32_t *got, uint8_t *out_type)
{
    TxSpan *span;
    uint32_t n = 0U;

    if (got != NULL) {
        *got = 0U;
    }
    if (out == NULL || max == 0U) {
        return -1;
    }
    if ((s_span_count == 0U) || (s_tx.count == 0U)) {
        tx_note_tls_drained();
        return 1;
    }
    span = &s_span[s_span_tail];
    if (out_type != NULL) {
        *out_type = span->type;
    }
    while ((n < max) && (n < span->len) && (s_tx.count > 0U)) {
        out[n++] = s_tx.buf[s_tx.tail];
        s_tx.tail = (s_tx.tail + 1U) % SE_USB_TX_RING_SIZE;
        s_tx.count--;
    }
    span->len -= n;
    if (span->len == 0U) {
        s_span_tail = (uint16_t)((s_span_tail + 1U) % SE_USB_TX_SPAN_MAX);
        s_span_count--;
    }
    if (got != NULL) {
        *got = n;
    }
    tx_note_tls_drained();
    return 0;
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
    tx_clear();
    s_tls_wire = 0U;
}

void se_usb_tls_clear_rx(void)
{
    (void)memset(&s_rx, 0, sizeof(s_rx));
}

void se_usb_tls_end_tls_wire(void)
{
    /* Abort / link drop: discard a partial record. */
    tx_clear();
    s_tls_wire = 0U;
}

void se_usb_tls_release_tls_wire(void)
{
    /* NonSecure drains only after this NSC returns. Zeroing TX here drops
     * the manage reply and close_notify, and the peer waits forever. */
    if (tx_span_has(SE_USB_TLS) == 0) {
        s_tls_wire = 0U;
    } else {
        s_tls_wire = 2U;
    }
}

int se_usb_tls_tx_draining(void)
{
    return (s_tls_wire == 2U) ? 1 : 0;
}

void se_usb_tls_discard_idle_tx(void)
{
    /* Stale plain text before a new ClientHello. Leave a TLS span alone. */
    if ((s_tls_wire == 0U) && (tx_span_has(SE_USB_TLS) == 0)) {
        tx_clear();
    }
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
        se_tls_reset_quiet();
        link_reset_flags();
    } else if (prev == 0U && s_dtr != 0U) {
        se_tls_reset_quiet();
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

uint32_t se_usb_tls_rx_count(void)
{
    return s_rx.count;
}

int se_usb_tls_rx_take(uint8_t *out, uint32_t max)
{
    if (out == NULL || max == 0U) {
        return 0;
    }
    return rx_read(out, (int)max);
}

uint8_t se_usb_tls_rx_overflow(void)
{
    return s_rx.overflow;
}

int se_usb_tls_tx_pop(uint8_t *out, uint32_t max, uint32_t *out_len, uint8_t *out_type)
{
    if (s_active == 0U) {
        return -1;
    }
    return tx_read(out, max, out_len, out_type);
}

static int usb_ascii_line(const char *msg)
{
    char buf[192];
    uint32_t mlen;
    uint32_t total;

    if ((s_active == 0U) || (msg == NULL)) {
        return -1;
    }
    mlen = (uint32_t)strlen(msg);
    if (mlen > (uint32_t)(sizeof(buf) - 3U)) {
        mlen = (uint32_t)(sizeof(buf) - 3U);
    }
    if (mlen > 0U) {
        (void)memcpy(buf, msg, (size_t)mlen);
    }
    total = mlen;
    buf[total++] = '\r';
    buf[total++] = '\n';
    return (tx_write((const uint8_t *)buf, total, SE_USB_PLAIN) < 0) ? -1 : 0;
}

int se_usb_debug_puts(const char *msg)
{
    return usb_ascii_line(msg);
}

void se_usb_failed(void)
{
    (void)usb_ascii_line("failed");
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
    if (s_tls_wire == 2U) {
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }

    room = tx_free();
    if (room == 0U) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    n = (uint32_t)sz;
    if (n > room) {
        n = room;
    }
    if (tx_write((const uint8_t *)buf, n, SE_USB_TLS) < 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    s_tls_wire = 1U;
    return (int)n;
}

void se_usb_tls_service_once(void)
{
    if (s_rx.overflow != 0U) {
        se_tls_die = 4U;
        se_tls_abort();
        link_reset_flags();
        return;
    }
    if ((s_active == 0U) || (s_dtr == 0U)) {
        return;
    }
    /* Shutdown / TX drain must run even if wall time was cleared mid-session;
     * otherwise CLIENT CSR stays queued forever behind TLS_ST_SHUTDOWN. */
    if ((se_time_is_synced() == 0) && (se_tls_pipe_busy() == 0)) {
        return;
    }

    se_tls_service_once();
}
