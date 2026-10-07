/**
 * @file    tls_usb_io.c
 * @brief   NonSecure CDC: frame host bytes, parse commands, pump Secure pipe
 *
 * Every CDC packet is a frame: magic 0x6767, type (0x00 plain / 0x01 TLS),
 * length, payload. The type belongs to the bytes, not to whether TLS is armed.
 * Plain and TLS may sit in the TX ring together and leave as their own frames.
 * Commands stay here. Type 0x01 is copied into the Secure ring (TLS or the
 * OWNER SET blob). A command that arrives while the pipe is armed is queued
 * and run after IDLE. Host commands live in s_host_cmds. Console replies are
 * ASCII in type 0x00 frames (hex for binary payloads). Errors are {@code failed}
 * only. PROVISION / ENCRYPT / DECRYPT / MANAGE <unix> arm TLS; OWNER SET then
 * takes a type 0x01 blob. DTR off / TLS exit (IDLE) returns to the command parser.
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

#define TLS_CMD_MAX 160
#define USB_FRAME_BUF (USB_FRAME_HDR_LEN + USB_FRAME_MAX)

static int pipe_armed(void);
static void tls_usb_drain_tx(void);
static void run_cmd_queue(void);

/* USBX write/read_run keep a pointer into the caller's buffer until NEXT. */
static uint8_t s_tx_pkt[USB_FRAME_BUF];
static uint32_t s_tx_pkt_len;
static uint8_t s_tx_in_flight;
static uint8_t s_rx_pkt[SECURE_USB_PKT_MAX];
static uint32_t s_rx_hold_len;
static uint32_t s_rx_hold_off;

static uint8_t s_rx_frame[USB_FRAME_BUF];
static uint32_t s_rx_frame_len;
static uint32_t s_sec_off;
static uint32_t s_sec_len;

static char s_cmd_q[USB_CMD_QUEUE_MAX][TLS_CMD_MAX + 1];
static uint8_t s_cmd_q_n;

static int ns_log(const char *msg)
{
    if (msg == NULL) {
        return -1;
    }
    return (SECURE_UsbLog_nsc_call((const uint8_t *)msg, (uint32_t)strlen(msg)) == SECURE_USB_OK)
        ? 0 : -1;
}

static void tls_disarm(void)
{
    s_tls_armed = 0U;
    s_bin_armed = 0U;
    s_rx_hold_len = 0U;
    s_rx_hold_off = 0U;
}

static int pipe_armed(void)
{
    return ((s_tls_armed != 0U) || (s_bin_armed != 0U)) ? 1 : 0;
}

static void frame_reset(void)
{
    s_rx_frame_len = 0U;
    s_sec_off = 0U;
    s_sec_len = 0U;
    s_cmd_q_n = 0U;
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
    { "TROPIC OTP STATUS", "TROPIC OTP STATUS",  cmd_tropic_otp_left },
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

static void ns_log_hex(const uint8_t *data, uint32_t len)
{
    char line[97];
    uint32_t i;
    uint32_t pos = 0U;

    if (data == NULL || len == 0U) {
        return;
    }
    for (i = 0U; i < len; i++) {
        if (pos + 2U >= sizeof(line)) {
            line[pos] = '\0';
            ns_log(line);
            pos = 0U;
        }
        line[pos++] = (char)("0123456789abcdef"[(data[i] >> 4) & 0x0FU]);
        line[pos++] = (char)("0123456789abcdef"[data[i] & 0x0FU]);
    }
    if (pos > 0U) {
        line[pos] = '\0';
        ns_log(line);
    }
}

/** Tropic NSC → ASCII: ok[+hex] / empty / failed. */
static void usb_tropic_ascii(uint32_t st, const uint8_t *body, uint32_t len)
{
    if (st == SECURE_TROPIC_OK) {
        if ((body != NULL) && (len > 0U)) {
            ns_log_hex(body, len);
        } else {
            ns_log("ok");
        }
        return;
    }
    if (st == SECURE_USB_DUMP_EMPTY) {
        ns_log("empty");
        return;
    }
    usb_failed();
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
    /* Send queued plain text before ClientHello. Its frame type stays 0x00. */
    tls_usb_drain_tx();
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
    usb_tropic_ascii(SECURE_TropicPub_nsc_call(xy64), xy64, 64U);
}

static void cmd_tropic_kem_pub(char *args)
{
    uint32_t st;

    (void)args;
    st = SECURE_TropicKemPub_nsc_call();
    if (st == SECURE_USB_DUMP_EMPTY) {
        ns_log("empty");
        return;
    }
    if (st != SECURE_TROPIC_OK) {
        usb_failed();
    }
}

static void cmd_tropic_otp_left(char *args)
{
    uint32_t q[4];
    char line[96];

    (void)args;
    if (SECURE_TropicOtpLeft_nsc_call(q) != SECURE_TROPIC_OK) {
        usb_failed();
        return;
    }
    (void)snprintf(line, sizeof(line), "enc=%lu/%lu kb dec=%lu/%lu kb",
                   (unsigned long)q[0], (unsigned long)q[1],
                   (unsigned long)q[2], (unsigned long)q[3]);
    ns_log(line);
}

static void cmd_peer_list(char *args)
{
    uint32_t i;
    uint8_t nrec = 0U;
    char line[1U + SECURE_PEER_NAME_MAX + 1U + (SECURE_PEER_HASH_LEN * 2U) + 1U];

    (void)args;
    for (i = 0U; i < SECURE_PEER_MAX; i++) {
        uint8_t name[SECURE_PEER_NAME_MAX + 1U];
        uint8_t hash48[SECURE_PEER_HASH_LEN];
        uint32_t nlen = SECURE_PEER_NAME_MAX;
        uint32_t st;
        uint32_t j;
        uint32_t pos;

        (void)memset(name, 0, sizeof(name));
        st = SECURE_PeerGet_nsc_call(i, name, &nlen, hash48);
        if (st == SECURE_PEER_NOT_FOUND) {
            break;
        }
        if (st != SECURE_PEER_OK || nlen > SECURE_PEER_NAME_MAX) {
            usb_failed();
            return;
        }
        name[nlen] = '\0';
        pos = 0U;
        for (j = 0U; j < nlen; j++) {
            line[pos++] = (char)name[j];
        }
        line[pos++] = ' ';
        for (j = 0U; j < SECURE_PEER_HASH_LEN; j++) {
            line[pos++] = (char)("0123456789abcdef"[(hash48[j] >> 4) & 0x0FU]);
            line[pos++] = (char)("0123456789abcdef"[hash48[j] & 0x0FU]);
        }
        line[pos] = '\0';
        ns_log(line);
        nrec++;
    }
    if (nrec == 0U) {
        ns_log("empty");
    }
}

static void cmd_owner_set(char *args)
{
    if (*trim_line(args) != '\0') {
        usb_failed();
        return;
    }
    if (SECURE_OwnerBegin_nsc_call() != SECURE_USB_OK) {
        ns_log("refused");
        return;
    }
    /* Accept the blob before begin "ok" leaves USB, or the host's 0x01 is dropped. */
    s_bin_armed = 1U;
    ns_log("ok");
    tls_usb_drain_tx();
}

static void cmd_client_hash(char *args)
{
    uint8_t h[48];

    (void)args;
    if (SECURE_TropicClientHash_nsc_call(h) != SECURE_TROPIC_OK) {
        usb_failed();
        return;
    }
    ns_log_hex(h, 48U);
}

static void cmd_client_csr(char *args)
{
    (void)args;
    if (SECURE_ClientCsr_nsc_call() != SECURE_TROPIC_OK) {
        usb_failed();
    }
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

static void queue_command(const char *line)
{
    if ((line == NULL) || (line[0] == '\0') || (s_cmd_q_n >= USB_CMD_QUEUE_MAX)) {
        return;
    }
    (void)strncpy(s_cmd_q[s_cmd_q_n], line, TLS_CMD_MAX);
    s_cmd_q[s_cmd_q_n][TLS_CMD_MAX] = '\0';
    s_cmd_q_n++;
}

static void run_cmd_queue(void)
{
    while ((s_cmd_q_n > 0U) && (pipe_armed() == 0)) {
        char line[TLS_CMD_MAX + 1];
        uint8_t i;

        (void)memcpy(line, s_cmd_q[0], sizeof(line));
        for (i = 0U; i + 1U < s_cmd_q_n; i++) {
            (void)memcpy(s_cmd_q[i], s_cmd_q[i + 1U], sizeof(s_cmd_q[i]));
        }
        s_cmd_q_n--;
        handle_host_command_line(line);
    }
}

static void dispatch_command_payload(const uint8_t *data, uint32_t len)
{
    char line[TLS_CMD_MAX + 1];
    uint32_t n = len;
    uint32_t i;

    if (n > TLS_CMD_MAX) {
        n = TLS_CMD_MAX;
    }
    for (i = 0U; i < n; i++) {
        char c = (char)data[i];

        if ((c == '\r') || (c == '\n')) {
            n = i;
            break;
        }
        line[i] = c;
    }
    line[n] = '\0';
    if (n == 0U) {
        return;
    }
    if (pipe_armed() != 0) {
        queue_command(line);
        return;
    }
    handle_host_command_line(line);
}

static int push_secure(const uint8_t *data, uint32_t len)
{
    while (s_sec_off < len) {
        uint32_t chunk = len - s_sec_off;
        uint32_t st;

        if (chunk > SECURE_USB_PKT_MAX) {
            chunk = SECURE_USB_PKT_MAX;
        }
        st = SECURE_UsbRx_nsc_call(data + s_sec_off, chunk);
        if (st == SECURE_USB_BUSY) {
            return 1;
        }
        if (st != SECURE_USB_OK) {
            return -1;
        }
        s_sec_off += chunk;
    }
    return 0;
}

static int frame_drop_byte(void)
{
    if (s_rx_frame_len == 0U) {
        return 0;
    }
    (void)memmove(s_rx_frame, s_rx_frame + 1U, s_rx_frame_len - 1U);
    s_rx_frame_len--;
    return 1;
}

static int consume_frame(uint32_t total)
{
    if (total > s_rx_frame_len) {
        return -1;
    }
    if (total < s_rx_frame_len) {
        (void)memmove(s_rx_frame, s_rx_frame + total, s_rx_frame_len - total);
    }
    s_rx_frame_len -= total;
    return 0;
}

/** 0 need more / done, 1 Secure ring full, -1 error. */
static int process_frames(void)
{
    for (;;) {
        uint16_t magic;
        uint8_t type;
        uint16_t plen;
        uint32_t total;
        int pr;

        if (s_sec_len > 0U) {
            uint32_t framed = USB_FRAME_HDR_LEN + s_sec_len;

            if (pipe_armed() == 0) {
                (void)consume_frame(framed);
                s_sec_off = 0U;
                s_sec_len = 0U;
                continue;
            }
            pr = push_secure(s_rx_frame + USB_FRAME_HDR_LEN, s_sec_len);
            if (pr != 0) {
                return pr;
            }
            (void)consume_frame(framed);
            s_sec_off = 0U;
            s_sec_len = 0U;
            continue;
        }

        if (s_rx_frame_len < 2U) {
            return 0;
        }
        magic = (uint16_t)s_rx_frame[0] | ((uint16_t)s_rx_frame[1] << 8);
        if (magic != USB_FRAME_MAGIC) {
            (void)frame_drop_byte();
            continue;
        }
        if (s_rx_frame_len < USB_FRAME_HDR_LEN) {
            return 0;
        }
        type = s_rx_frame[2];
        plen = (uint16_t)s_rx_frame[3] | ((uint16_t)s_rx_frame[4] << 8);
        if ((type != USB_FRAME_TYPE_CMD) && (type != USB_FRAME_TYPE_SEC)) {
            (void)frame_drop_byte();
            continue;
        }
        if (plen > USB_FRAME_MAX) {
            (void)frame_drop_byte();
            continue;
        }
        total = USB_FRAME_HDR_LEN + (uint32_t)plen;
        if (s_rx_frame_len < total) {
            return 0;
        }
        if (type == USB_FRAME_TYPE_CMD) {
            dispatch_command_payload(s_rx_frame + USB_FRAME_HDR_LEN, (uint32_t)plen);
            (void)consume_frame(total);
            continue;
        }
        if (pipe_armed() == 0) {
            (void)consume_frame(total);
            continue;
        }
        s_sec_off = 0U;
        s_sec_len = (uint32_t)plen;
        pr = push_secure(s_rx_frame + USB_FRAME_HDR_LEN, s_sec_len);
        if (pr != 0) {
            return pr;
        }
        (void)consume_frame(total);
        s_sec_off = 0U;
        s_sec_len = 0U;
    }
}

/**
 * Copy host bytes into the frame buffer.
 *
 * The buffer holds one max frame (1029 bytes). A full Secure frame is
 * 16 * 64 + 5. On the board the last 5 bytes are a USB short packet, so they
 * fit. A PTY read is not short-packet bounded: the next read is 64 bytes and
 * spills into the following frame. Dropping the front of the partial frame to
 * make that read fit shifts the magic and OWNER SET returns "failed parse".
 * Copy only what fits, finish the frame, then keep the spill. *used is how
 * many bytes of @p data were taken. 0 done, 1 Secure ring full, -1 error.
 */
static int append_host_rx(const uint8_t *data, uint32_t len, uint32_t *used)
{
    uint32_t off = 0U;
    int pr;

    if (used != NULL) {
        *used = 0U;
    }
    pr = process_frames();
    if (pr != 0) {
        return pr;
    }
    if ((data == NULL) || (len == 0U)) {
        return 0;
    }
    while (off < len) {
        uint32_t space;
        uint32_t n;

        if (s_rx_frame_len >= USB_FRAME_BUF) {
            pr = process_frames();
            if (pr != 0) {
                break;
            }
            if (s_rx_frame_len >= USB_FRAME_BUF) {
                (void)frame_drop_byte();
            }
            continue;
        }
        space = USB_FRAME_BUF - s_rx_frame_len;
        n = len - off;
        if (n > space) {
            n = space;
        }
        (void)memcpy(s_rx_frame + s_rx_frame_len, data + off, (size_t)n);
        s_rx_frame_len += n;
        off += n;
        pr = process_frames();
        if (pr != 0) {
            break;
        }
    }
    if (used != NULL) {
        *used = off;
    }
    return pr;
}

static void tls_usb_drain_tx(void)
{
    uint32_t out_len = 0U;
    uint32_t st;
    ULONG actual;
    UINT status;
    uint8_t type;

    if (s_cdc == NULL || s_active == 0U) {
        return;
    }

    for (;;) {
        if (s_tx_in_flight == 0U) {
            uint32_t out_type = USB_FRAME_TYPE_CMD;

            out_len = 0U;
            st = SECURE_UsbTx_nsc_call(s_tx_pkt + USB_FRAME_HDR_LEN, USB_FRAME_MAX, &out_len,
                                       &out_type);
            if (st == SECURE_USB_BUSY || out_len == 0U) {
                break;
            }
            if (st != SECURE_USB_OK) {
                break;
            }
            if ((out_type != USB_FRAME_TYPE_CMD) && (out_type != USB_FRAME_TYPE_SEC)) {
                break;
            }
            type = (uint8_t)out_type;
            s_tx_pkt[0] = (uint8_t)(USB_FRAME_MAGIC & 0xFFU);
            s_tx_pkt[1] = (uint8_t)((USB_FRAME_MAGIC >> 8) & 0xFFU);
            s_tx_pkt[2] = type;
            s_tx_pkt[3] = (uint8_t)(out_len & 0xFFU);
            s_tx_pkt[4] = (uint8_t)((out_len >> 8) & 0xFFU);
            s_tx_pkt_len = USB_FRAME_HDR_LEN + out_len;
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
    frame_reset();
    tls_usb_xfer_idle();
}

void tls_usb_cdc_activate(UX_SLAVE_CLASS_CDC_ACM *cdc)
{
    s_cdc = cdc;
    s_active = 1U;
    tls_disarm();
    frame_reset();
    (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_ACTIVATE);
}

void tls_usb_cdc_deactivate(void)
{
    (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DEACTIVATE);
    s_cdc = NULL;
    s_active = 0U;
    s_dtr = 0U;
    tls_disarm();
    frame_reset();
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
        frame_reset();
        (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DTR_ON);
    } else if (prev != 0U && s_dtr == 0U) {
        tls_disarm();
        frame_reset();
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
    if (pipe_armed() == 0) {
        run_cmd_queue();
        tls_usb_drain_tx();
    }

    /*
     * Copy every OUT packet the host has already queued, then enter Secure
     * once. wolfSSL_connect verifies ML-DSA before it returns, and the OUT
     * endpoint is not re-armed during that call. Servicing Secure after each
     * 64-byte packet left the rest of the provision server flight NAKing until
     * the cable was pulled.
     */
    for (;;) {
        int pr;
        uint32_t used = 0U;

        if (s_rx_hold_len == 0U) {
            actual = 0U;
            status = ux_device_class_cdc_acm_read_run(s_cdc, s_rx_pkt, sizeof(s_rx_pkt), &actual);
            if (status == UX_STATE_NEXT) {
                if (actual == 0U) {
                    break;
                }
                s_rx_hold_len = (uint32_t)actual;
                s_rx_hold_off = 0U;
            } else if (status == UX_STATE_ERROR || status == UX_STATE_EXIT) {
                break;
            } else {
                break;
            }
        }

        pr = append_host_rx(s_rx_pkt + s_rx_hold_off, s_rx_hold_len - s_rx_hold_off, &used);
        s_rx_hold_off += used;
        if (s_rx_hold_off >= s_rx_hold_len) {
            s_rx_hold_len = 0U;
            s_rx_hold_off = 0U;
        }
        if (pr < 0) {
            s_rx_hold_len = 0U;
            s_rx_hold_off = 0U;
            tls_disarm();
            frame_reset();
            /* Drop a half-parsed host frame without leaving Secure in SHUTDOWN. */
            (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DTR_OFF);
            if (s_dtr != 0U) {
                (void)SECURE_UsbEvent_nsc_call(SECURE_USB_EVT_DTR_ON);
            }
            (void)SECURE_UsbService_nsc_call();
            tls_usb_drain_tx();
            return;
        }
        if (pr > 0) {
            /* Secure ring full: run wolfSSL so the held tail can be copied. */
            if (pipe_armed() != 0) {
                st = SECURE_UsbService_nsc_call();
                tls_usb_drain_tx();
                if (st == SECURE_USB_IDLE || st == SECURE_USB_ERR) {
                    s_rx_hold_len = 0U;
                    s_rx_hold_off = 0U;
                    tls_disarm();
                    run_cmd_queue();
                    tls_usb_drain_tx();
                    return;
                }
            }
            continue;
        }
    }

    /* Always pump Secure: SHUTDOWN must finish even if NS already disarmed. */
    if (s_dtr != 0U) {
        st = SECURE_UsbService_nsc_call();
        tls_usb_drain_tx();
        if (st == SECURE_USB_IDLE || st == SECURE_USB_ERR) {
            tls_disarm();
            run_cmd_queue();
        }
    }

    if (pipe_armed() == 0) {
        run_cmd_queue();
    }
    tls_usb_drain_tx();
}

