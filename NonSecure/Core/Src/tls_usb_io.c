/**
 * @file    tls_usb_io.c
 * @brief   NonSecure CDC: parse host commands, arm TLS, pump Secure pipe
 *
 * Host commands live in s_host_cmds (HELP lists that table). Typed replies
 * are 0xB1 dump frames. ASCII errors are the string {@code failed} only.
 * PROVISION / ENCRYPT / DECRYPT / MANAGE <unix> set Secure time and arm TLS
 * with a mode enum. Only then are RX bytes forwarded and UsbService polled.
 * / DTR off / TLS exit (IDLE) returns to command mode.
 */
#include "tls_usb_io.h"
#include "se_tls_nsc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static UX_SLAVE_CLASS_CDC_ACM *s_cdc;
static uint8_t s_dtr;
static uint8_t s_active;
static uint8_t s_tls_armed;
static uint8_t s_bin_armed;

/* Longest ASCII line is a short command name plus unix time. */
#define TLS_CMD_MAX 160

static char s_cmd_line[TLS_CMD_MAX + 1];
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
    s_bin_armed = 0U;
    s_cmd_len = 0U;
}

static int pipe_armed(void)
{
    return ((s_tls_armed != 0U) || (s_bin_armed != 0U)) ? 1 : 0;
}

static void tls_usb_xfer_idle(void)
{
    s_tx_pkt_len = 0U;
    s_tx_in_flight = 0U;
}

static char *trim_line(char *line)
{
    char *end;

    while (*line == ' ' || *line == '\t') {
        line++;
    }
    end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    *end = '\0';
    return line;
}

typedef void (*host_cmd_fn)(char *args);

typedef struct {
    const char *name;
    const char *usage;
    host_cmd_fn handler;
} host_cmd_t;

static void cmd_help(char *args);
static void cmd_provision(char *args);
static void cmd_encrypt(char *args);
static void cmd_decrypt(char *args);
static void cmd_manage(char *args);
static void cmd_tropic_ping(char *args);
static void cmd_tropic_info(char *args);
static void cmd_tropic_pub(char *args);
static void cmd_tropic_kem_pub(char *args);
static void cmd_tropic_otp_left(char *args);
static void cmd_peer_list(char *args);
static void cmd_owner_set(char *args);
static void cmd_client_hash(char *args);
static void cmd_client_csr(char *args);

static const host_cmd_t s_host_cmds[] = {
    { "HELP",            "HELP",                 cmd_help },
    { "?",               NULL,                   cmd_help },
    { "PROVISION",       "PROVISION <unix>",     cmd_provision },
    { "ENCRYPT",         "ENCRYPT <unix>",       cmd_encrypt },
    { "DECRYPT",         "DECRYPT <unix>",       cmd_decrypt },
    { "MANAGE",          "MANAGE <unix>",        cmd_manage },
    { "OWNER SET",       "OWNER SET",            cmd_owner_set },
    { "PEER LIST",       "PEER LIST",            cmd_peer_list },
    { "CLIENT HASH",     "CLIENT HASH",          cmd_client_hash },
    { "CLIENT CSR",      "CLIENT CSR",           cmd_client_csr },
    { "TROPIC PING",     "TROPIC PING",          cmd_tropic_ping },
    { "TROPIC INFO",     "TROPIC INFO",          cmd_tropic_info },
    { "TROPIC PUB",      "TROPIC PUB",           cmd_tropic_pub },
    { "TROPIC KEM PUB",  "TROPIC KEM PUB",       cmd_tropic_kem_pub },
    { "TROPIC OTP LEFT", "TROPIC OTP LEFT",      cmd_tropic_otp_left },
};

static int cmd_match(const char *line, const char *name, char **args_out)
{
    size_t n = strlen(name);
    char c;

    if (strncmp(line, name, n) != 0) {
        return 0;
    }
    c = line[n];
    if (c != '\0' && c != ' ' && c != '\t' && c != '=') {
        return 0;
    }
    *args_out = (char *)(line + n);
    while (**args_out == ' ' || **args_out == '\t' || **args_out == '=') {
        (*args_out)++;
    }
    return 1;
}

static const host_cmd_t *cmd_lookup(const host_cmd_t *table, size_t count,
                                    char *line, char **args_out)
{
    size_t i;

    for (i = 0U; i < count; i++) {
        if (cmd_match(line, table[i].name, args_out) != 0) {
            return &table[i];
        }
    }
    return NULL;
}

static void usb_failed(void)
{
    ns_log("failed");
}

static void usb_dump(uint8_t status, const uint8_t *body, uint32_t len)
{
    (void)SECURE_UsbDump_nsc_call(status, body, len);
}

/** Map collapsed Tropic NSC status: ok / empty occupancy / err. */
static void usb_tropic_dump(uint32_t st, const uint8_t *body, uint32_t len)
{
    if (st == SECURE_TROPIC_OK) {
        usb_dump(SECURE_USB_DUMP_OK, body, len);
        return;
    }
    if (st == SECURE_USB_DUMP_EMPTY) {
        usb_dump(SECURE_USB_DUMP_EMPTY, NULL, 0U);
        return;
    }
    usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
}

static void cmd_help(char *args)
{
    size_t i;

    (void)args;
    ns_log("commands:");
    for (i = 0U; i < sizeof(s_host_cmds) / sizeof(s_host_cmds[0]); i++) {
        if (s_host_cmds[i].usage != NULL) {
            ns_log(s_host_cmds[i].usage);
        }
    }
}

static int parse_unix_arg(char *args, uint32_t *out)
{
    char *p = trim_line(args);
    char *end = NULL;
    unsigned long unix_utc;

    unix_utc = strtoul(p, &end, 10);
    if (end == p || unix_utc == 0UL) {
        return -1;
    }
    p = trim_line(end);
    if (*p != '\0') {
        return -1;
    }
    *out = (uint32_t)unix_utc;
    return 0;
}

static void cmd_tls_start(uint32_t mode, char *args)
{
    uint32_t unix_utc;

    if (parse_unix_arg(args, &unix_utc) != 0) {
        usb_failed();
        return;
    }
    if (SECURE_TlsStart_nsc_call(mode, unix_utc) != SECURE_USB_OK) {
        usb_failed();
        return;
    }
    s_tls_armed = 1U;
}

static void cmd_provision(char *args)
{
    cmd_tls_start(SECURE_TLS_MODE_PROVISION, args);
}

static void cmd_encrypt(char *args)
{
    cmd_tls_start(SECURE_TLS_MODE_ENCRYPT, args);
}

static void cmd_decrypt(char *args)
{
    cmd_tls_start(SECURE_TLS_MODE_DECRYPT, args);
}

static void cmd_manage(char *args)
{
    cmd_tls_start(SECURE_TLS_MODE_MANAGE, args);
}

static void cmd_tropic_ping(char *args)
{
    (void)args;
    if (SECURE_TropicPing_nsc_call() != SECURE_TROPIC_OK) {
        usb_failed();
    }
}

static void cmd_tropic_info(char *args)
{
    (void)args;
    if (SECURE_TropicInfo_nsc_call() != SECURE_TROPIC_OK) {
        usb_failed();
    }
}

static void cmd_tropic_pub(char *args)
{
    uint8_t xy64[64];

    (void)args;
    (void)memset(xy64, 0, sizeof(xy64));
    usb_tropic_dump(SECURE_TropicPub_nsc_call(xy64), xy64, 64U);
}

static void cmd_tropic_kem_pub(char *args)
{
    uint8_t pk[SECURE_USB_DUMP_BODY_MAX];
    uint32_t n = SE_TROPIC_MLKEM_PK_LEN;

    (void)args;
    if (n > SECURE_USB_DUMP_BODY_MAX) {
        usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    usb_tropic_dump(SECURE_TropicKemPub_nsc_call(pk, &n), pk, n);
}

static void cmd_tropic_otp_left(char *args)
{
    uint32_t q[4];
    uint8_t body[16];
    uint32_t i;

    (void)args;
    if (SECURE_TropicOtpLeft_nsc_call(q) != SECURE_TROPIC_OK) {
        usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    for (i = 0U; i < 4U; i++) {
        body[i * 4U] = (uint8_t)(q[i] & 0xffu);
        body[(i * 4U) + 1U] = (uint8_t)((q[i] >> 8) & 0xffu);
        body[(i * 4U) + 2U] = (uint8_t)((q[i] >> 16) & 0xffu);
        body[(i * 4U) + 3U] = (uint8_t)((q[i] >> 24) & 0xffu);
    }
    usb_dump(SECURE_USB_DUMP_OK, body, 16U);
}

static void cmd_peer_list(char *args)
{
    uint8_t body[1U + (SECURE_PEER_MAX * (1U + SECURE_PEER_NAME_MAX + SECURE_PEER_HASH_LEN))];
    uint32_t off = 1U;
    uint32_t i;
    uint8_t nrec = 0U;

    (void)args;
    for (i = 0U; i < SECURE_PEER_MAX; i++) {
        uint8_t name[SECURE_PEER_NAME_MAX];
        uint8_t hash48[SECURE_PEER_HASH_LEN];
        uint32_t nlen = SECURE_PEER_NAME_MAX;
        uint32_t st;

        (void)memset(name, 0, sizeof(name));
        st = SECURE_PeerGet_nsc_call(i, name, &nlen, hash48);
        if (st == SECURE_PEER_NOT_FOUND) {
            break;
        }
        if (st != SECURE_PEER_OK) {
            usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
            return;
        }
        if (nlen > SECURE_PEER_NAME_MAX) {
            usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
            return;
        }
        body[off++] = (uint8_t)nlen;
        (void)memcpy(body + off, name, nlen);
        off += nlen;
        (void)memcpy(body + off, hash48, SECURE_PEER_HASH_LEN);
        off += SECURE_PEER_HASH_LEN;
        nrec++;
    }
    body[0] = nrec;
    usb_dump(SECURE_USB_DUMP_OK, body, off);
}

static void cmd_owner_set(char *args)
{
    if (*trim_line(args) != '\0') {
        usb_failed();
        return;
    }
    if (SECURE_OwnerBegin_nsc_call() != SECURE_USB_OK) {
        usb_dump(SECURE_USB_DUMP_REFUSED, NULL, 0U);
        return;
    }
    usb_dump(SECURE_USB_DUMP_OK, NULL, 0U);
    s_bin_armed = 1U;
}

static void cmd_client_hash(char *args)
{
    uint8_t h[48];

    (void)args;
    if (SECURE_TropicClientHash_nsc_call(h) != SECURE_TROPIC_OK) {
        usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    usb_dump(SECURE_USB_DUMP_OK, h, 48U);
}

static void cmd_client_csr(char *args)
{
    uint8_t pub[SECURE_USB_DUMP_BODY_MAX];
    uint32_t n = SECURE_USB_DUMP_BODY_MAX;

    (void)args;
    if (SECURE_ClientCsr_nsc_call(pub, &n) != SECURE_TROPIC_OK) {
        usb_dump(SECURE_USB_DUMP_ERR, NULL, 0U);
        return;
    }
    usb_dump(SECURE_USB_DUMP_OK, pub, n);
}

static void handle_host_command_line(char *line)
{
    char *p = trim_line(line);
    char *args = NULL;
    const host_cmd_t *cmd;

    cmd = cmd_lookup(s_host_cmds, sizeof(s_host_cmds) / sizeof(s_host_cmds[0]),
                     p, &args);
    if (cmd == NULL) {
        usb_failed();
        return;
    }
    cmd->handler(args);
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
    if (s_cmd_len < TLS_CMD_MAX) {
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

    if (pipe_armed() != 0) {
        return (SECURE_UsbRx_nsc_call(data, len) == SECURE_USB_OK) ? 0 : -1;
    }

    for (i = 0U; i < len; i++) {
        process_pre_tls_byte(data[i]);
        if (pipe_armed() != 0) {
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
                /* Let wolfSSL drain the Secure RX ring before the next push.
                 * A TLS 1.3 PQC server flight can exceed the ring if we only
                 * service after the CDC read loop. */
                if (pipe_armed() != 0) {
                    st = SECURE_UsbService_nsc_call();
                    tls_usb_drain_tx();
                    if (st == SECURE_USB_IDLE || st == SECURE_USB_ERR) {
                        tls_disarm();
                        return;
                    }
                }
            }
        } else if (status == UX_STATE_ERROR || status == UX_STATE_EXIT) {
            break;
        } else {
            break;
        }
    } while (status == UX_STATE_NEXT && actual > 0U);

    if ((pipe_armed() != 0) && (s_dtr != 0U)) {
        st = SECURE_UsbService_nsc_call();
        if (st == SECURE_USB_IDLE || st == SECURE_USB_ERR) {
            /* Session finished, failed, or link torn down — back to commands. */
            tls_disarm();
        }
    }

    tls_usb_drain_tx();
}

#ifndef SE_HOST_MODEL
#include "se_ns_usbx_sources.inc"
#endif
