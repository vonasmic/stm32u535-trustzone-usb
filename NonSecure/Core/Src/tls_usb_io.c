/**
 * @file    tls_usb_io.c
 * @brief   NonSecure CDC: parse host commands, arm TLS, pump Secure pipe
 *
 * TIME=<unix> is parsed here. On success NonSecure sets Secure time via NSC
 * and arms TLS. Only then are RX bytes forwarded and UsbService polled.
 * Host disconnect / DTR off / TLS exit (IDLE) returns to command mode.
 */
#include "tls_usb_io.h"
#include "se_tls_nsc.h"
#include <stdlib.h>
#include <string.h>

static UX_SLAVE_CLASS_CDC_ACM *s_cdc;
static uint8_t s_dtr;
static uint8_t s_active;
static uint8_t s_tls_armed;
static uint8_t s_wait_time_logged;

static char s_cmd_line[48];
static uint8_t s_cmd_len;

/* USBX write/read_run keep a pointer into the caller's buffer until NEXT.
 * These must stay valid across polls (not stack locals). */
static uint8_t s_tx_pkt[SECURE_USB_PKT_MAX];
static uint32_t s_tx_pkt_len;
static uint8_t s_tx_in_flight;
static uint8_t s_rx_pkt[SECURE_USB_PKT_MAX];

static void ns_log(const char *msg)
{
    if (msg == NULL) {
        return;
    }
    (void)SECURE_UsbLog_nsc_call((const uint8_t *)msg, (uint32_t)strlen(msg));
}

static void tls_disarm(void)
{
    s_tls_armed = 0U;
    s_cmd_len = 0U;
    s_wait_time_logged = 0U;
}

static void tls_usb_xfer_idle(void)
{
    s_tx_pkt_len = 0U;
    s_tx_in_flight = 0U;
}

static void handle_host_command_line(char *line)
{
    char *p = line;
    unsigned long unix_utc;
    char *end = NULL;

    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (strncmp(p, "TIME=", 5) != 0 && strncmp(p, "TIME ", 5) != 0) {
        return;
    }
    p += 5;
    unix_utc = strtoul(p, &end, 10);
    if (end == p || unix_utc == 0UL) {
        ns_log("bad TIME command");
        return;
    }
    if (SECURE_SetUnixTime_nsc_call((uint32_t)unix_utc) != SECURE_USB_OK) {
        ns_log("TIME set failed");
        return;
    }
    s_tls_armed = 1U;
    s_wait_time_logged = 0U;
}

static void process_pre_tls_byte(uint8_t b)
{
    if (b == '\r') {
        return;
    }
    if (b == '\n') {
        s_cmd_line[s_cmd_len] = '\0';
        if (s_cmd_len > 0U) {
            handle_host_command_line(s_cmd_line);
        }
        s_cmd_len = 0U;
        return;
    }
    if (s_cmd_len + 1U < sizeof(s_cmd_line)) {
        s_cmd_line[s_cmd_len++] = (char)b;
    } else {
        s_cmd_len = 0U;
    }
}

/** Consume host RX: parse commands until armed, then forward remainder to Secure. */
static int process_host_rx(const uint8_t *data, uint32_t len)
{
    uint32_t i;

    if (data == NULL || len == 0U) {
        return 0;
    }

    if (s_tls_armed != 0U) {
        return (SECURE_UsbRx_nsc_call(data, len) == SECURE_USB_OK) ? 0 : -1;
    }

    for (i = 0U; i < len; i++) {
        process_pre_tls_byte(data[i]);
        if (s_tls_armed != 0U) {
            i++;
            if (i < len) {
                if (SECURE_UsbRx_nsc_call(data + i, len - i) != SECURE_USB_OK) {
                    return -1;
                }
            }
            break;
        }
    }
    return 0;
}

static void tls_usb_drain_tx(void)
{
    uint32_t out_len = 0U;
    uint32_t st;
    ULONG actual;
    UINT status;

    if (s_cdc == NULL || s_active == 0U) {
        return;
    }

    for (;;) {
        if (s_tx_in_flight == 0U) {
            out_len = 0U;
            st = SECURE_UsbTx_nsc_call(s_tx_pkt, sizeof(s_tx_pkt), &out_len);
            if (st == SECURE_USB_BUSY || out_len == 0U) {
                break;
            }
            if (st != SECURE_USB_OK) {
                break;
            }
            s_tx_pkt_len = out_len;
            s_tx_in_flight = 1U;
        }

        actual = 0U;
        status = ux_device_class_cdc_acm_write_run(s_cdc, s_tx_pkt, s_tx_pkt_len, &actual);
        if (status == UX_STATE_NEXT) {
            s_tx_in_flight = 0U;
            s_tx_pkt_len = 0U;
            continue;
        }
        if (status == UX_STATE_ERROR || status == UX_STATE_EXIT) {
            s_tx_in_flight = 0U;
            s_tx_pkt_len = 0U;
            break;
        }
        break;
    }
}

void tls_usb_io_init(void)
{
    tls_usb_io_reset();
}

void tls_usb_io_reset(void)
{
    s_dtr = 0U;
    s_active = 0U;
    tls_disarm();
    tls_usb_xfer_idle();
}

void tls_usb_cdc_activate(UX_SLAVE_CLASS_CDC_ACM *cdc)
{
    s_cdc = cdc;
    s_active = 1U;
    tls_disarm();
    (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_ACTIVATE);
}

void tls_usb_cdc_deactivate(void)
{
    (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DEACTIVATE);
    s_cdc = NULL;
    s_active = 0U;
    s_dtr = 0U;
    tls_disarm();
    tls_usb_xfer_idle();
}

void tls_usb_cdc_parameter_change(UX_SLAVE_CLASS_CDC_ACM *cdc)
{
    UX_SLAVE_CLASS_CDC_ACM_LINE_STATE_PARAMETER line_state;
    uint8_t prev;

    if (cdc == NULL) {
        return;
    }

    prev = s_dtr;
    (void)ux_device_class_cdc_acm_ioctl(cdc,
            UX_SLAVE_CLASS_CDC_ACM_IOCTL_GET_LINE_STATE, &line_state);
    s_dtr = line_state.ux_slave_class_cdc_acm_parameter_dtr ? 1U : 0U;

    if (prev == 0U && s_dtr != 0U) {
        tls_disarm();
        (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DTR_ON);
    } else if (prev != 0U && s_dtr == 0U) {
        tls_disarm();
        (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DTR_OFF);
    }
}

int tls_usb_dtr_asserted(void)
{
    return (int)s_dtr;
}

int tls_usb_connected(void)
{
    return (s_cdc != NULL && s_active != 0U) ? 1 : 0;
}

void tls_usb_poll(void)
{
    ULONG actual = 0U;
    UINT status;
    uint32_t st;

    if (s_cdc == NULL) {
        return;
    }

    tls_usb_drain_tx();

    do {
        actual = 0U;
        status = ux_device_class_cdc_acm_read_run(s_cdc, s_rx_pkt, sizeof(s_rx_pkt), &actual);
        if (status == UX_STATE_NEXT) {
            if (actual > 0U) {
                if (process_host_rx(s_rx_pkt, (uint32_t)actual) != 0) {
                    tls_disarm();
                    (void)SECURE_UsbService_nsc_call();
                    tls_usb_drain_tx();
                    return;
                }
            }
        } else if (status == UX_STATE_ERROR || status == UX_STATE_EXIT) {
            break;
        } else {
            break;
        }
    } while (status == UX_STATE_NEXT && actual > 0U);

    if ((s_dtr != 0U) && (s_tls_armed == 0U) && (s_wait_time_logged == 0U)) {
        ns_log("waiting TIME=<unix>");
        s_wait_time_logged = 1U;
    }

    if ((s_tls_armed != 0U) && (s_dtr != 0U)) {
        st = SECURE_UsbService_nsc_call();
        if (st == SECURE_USB_IDLE || st == SECURE_USB_ERR) {
            /* Session finished, failed, or link torn down — back to commands. */
            tls_disarm();
        }
    }

    tls_usb_drain_tx();
}
