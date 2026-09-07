/**
 * @file    tls_usb_io.c
 * @brief   NonSecure CDC: parse host commands, arm TLS, pump Secure pipe
 *
 * Host commands live in s_host_cmds / s_tropic_cmds (HELP lists those tables).
 * PROVISION / ENCRYPT / DECRYPT <unix> set Secure time and arm TLS with a mode
 * enum. Only then are RX bytes forwarded and UsbService polled. Host disconnect
 * / DTR off / TLS exit (IDLE) returns to command mode.
 */
#include "tls_usb_io.h"
#include "se_tls_nsc.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static UX_SLAVE_CLASS_CDC_ACM *s_cdc;
static uint8_t s_dtr;
static uint8_t s_active;
static uint8_t s_tls_armed;
static uint8_t s_wait_time_logged;

#define TLS_CMD_MAX 96

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
    s_cmd_len = 0U;
    s_wait_time_logged = 0U;
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

static int parse_hex_nibbles(const char *hex, uint32_t hex_len, uint8_t *out, uint32_t out_len)
{
    uint32_t i;

    if (hex == NULL || out == NULL || (hex_len & 1U) != 0U || (hex_len / 2U) != out_len) {
        return -1;
    }
    for (i = 0U; i < out_len; i++) {
        unsigned long byte;
        char tmp[3];

        if (!isxdigit((unsigned char)hex[i * 2U]) ||
            !isxdigit((unsigned char)hex[i * 2U + 1U])) {
            return -1;
        }
        tmp[0] = hex[i * 2U];
        tmp[1] = hex[i * 2U + 1U];
        tmp[2] = '\0';
        byte = strtoul(tmp, NULL, 16);
        out[i] = (uint8_t)byte;
    }
    return 0;
}

typedef void (*host_cmd_fn)(char *args);

typedef struct {
    const char *name;   /* token matched at start of line */
    const char *usage;  /* listed by HELP; NULL = alias, not listed */
    host_cmd_fn handler;
} host_cmd_t;

static void cmd_help(char *args);
static void cmd_provision(char *args);
static void cmd_encrypt(char *args);
static void cmd_decrypt(char *args);
static void cmd_tropic(char *args);
static void cmd_tropic_ping(char *args);
static void cmd_tropic_info(char *args);
static void cmd_tropic_pub(char *args);
static void cmd_tropic_keygen(char *args);
static void cmd_tropic_sign(char *args);
static void cmd_tropic_kem(char *args);
static void cmd_tropic_kem_init(char *args);
static void cmd_tropic_kem_pub(char *args);
static void cmd_tropic_pairing(char *args);
static void cmd_peer(char *args);
static void cmd_peer_add(char *args);
static void cmd_peer_remove(char *args);
static void cmd_peer_list(char *args);
static int parse_pin_digits(const char *dec, uint8_t *out, uint32_t *out_len);

static const host_cmd_t s_kem_cmds[] = {
    { "INIT",  "TROPIC KEM INIT <pin> [CONFIRM]", cmd_tropic_kem_init },
    { "PUB",   "TROPIC KEM PUB",                      cmd_tropic_kem_pub },
};

static const host_cmd_t s_peer_cmds[] = {
    { "ADD",    "PEER ADD <name> <64-hex>", cmd_peer_add },
    { "REMOVE", "PEER REMOVE <name>",       cmd_peer_remove },
    { "LIST",   "PEER LIST",                cmd_peer_list },
};

static const host_cmd_t s_tropic_cmds[] = {
    { "PING",   "TROPIC PING",                         cmd_tropic_ping },
    { "INFO",   "TROPIC INFO",                         cmd_tropic_info },
    { "PUB",    "TROPIC PUB",                          cmd_tropic_pub },
    { "KEYGEN", "TROPIC KEYGEN [<pin>]",               cmd_tropic_keygen },
    { "SIGN",   "TROPIC SIGN <64-hex>",                cmd_tropic_sign },
    { "KEM",    NULL,                                  cmd_tropic_kem },
    { "PAIRING", "TROPIC PAIRING <1-3> [y]",            cmd_tropic_pairing },
};

/* Add/remove rows here; HELP walks the same tables used for dispatch. */
static const host_cmd_t s_host_cmds[] = {
    { "HELP",      "HELP",                         cmd_help },
    { "?",         NULL,                           cmd_help },
    { "PROVISION", "PROVISION <unix>",             cmd_provision },
    { "ENCRYPT",   "ENCRYPT <unix>",               cmd_encrypt },
    { "DECRYPT",   "DECRYPT <unix>",               cmd_decrypt },
    { "PEER",      NULL,                           cmd_peer },
    { "TROPIC",    NULL,                           cmd_tropic },
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

static void cmd_list_usage(const host_cmd_t *table, size_t count)
{
    size_t i;

    for (i = 0U; i < count; i++) {
        if (table[i].usage != NULL) {
            ns_log(table[i].usage);
        }
    }
}

static void tropic_log_status(uint32_t st)
{
    if (st == SECURE_TROPIC_OK) {
        return;
    }
    if (st == SECURE_TROPIC_SLOT_OCC) {
        ns_log("TROPIC slot occupied");
        return;
    }
    if (st == SECURE_TROPIC_NOT_READY) {
        ns_log("TROPIC not ready");
        return;
    }
    if (st == SECURE_TROPIC_TAMPERED) {
        ns_log("DEVICE_TAMPERED");
        return;
    }
    ns_log("TROPIC command failed");
}

static void cmd_help(char *args)
{
    (void)args;
    ns_log("commands:");
    cmd_list_usage(s_host_cmds, sizeof(s_host_cmds) / sizeof(s_host_cmds[0]));
    cmd_list_usage(s_peer_cmds, sizeof(s_peer_cmds) / sizeof(s_peer_cmds[0]));
    cmd_list_usage(s_tropic_cmds, sizeof(s_tropic_cmds) / sizeof(s_tropic_cmds[0]));
    cmd_list_usage(s_kem_cmds, sizeof(s_kem_cmds) / sizeof(s_kem_cmds[0]));
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
        ns_log("bad unix time");
        return;
    }
    if (SECURE_TlsStart_nsc_call(mode, unix_utc) != SECURE_USB_OK) {
        ns_log("TLS start failed");
        return;
    }
    s_tls_armed = 1U;
    s_wait_time_logged = 0U;
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

static void cmd_tropic_ping(char *args)
{
    (void)args;
    tropic_log_status(SECURE_TropicPing_nsc_call());
}

static void cmd_tropic_info(char *args)
{
    (void)args;
    tropic_log_status(SECURE_TropicInfo_nsc_call());
}

static void cmd_tropic_pub(char *args)
{
    uint8_t xy64[64];

    (void)args;
    tropic_log_status(SECURE_TropicPub_nsc_call(xy64));
}

static void cmd_tropic_keygen(char *args)
{
    char *p = trim_line(args);
    uint8_t pin[8];
    uint32_t pin_len = 0U;

    if (*p == '\0') {
        tropic_log_status(SECURE_TropicKeygen_nsc_call(NULL, 0U));
        return;
    }
    if (parse_pin_digits(p, pin, &pin_len) != 0) {
        ns_log("bad TROPIC KEYGEN pin");
        return;
    }
    p = trim_line(p + pin_len);
    if (*p != '\0') {
        ns_log("bad TROPIC KEYGEN");
        return;
    }
    tropic_log_status(SECURE_TropicKeygen_nsc_call(pin, pin_len));
}

static void cmd_tropic_sign(char *args)
{
    uint8_t hash32[32];
    uint8_t rs64[64];
    char *p = trim_line(args);

    if (strlen(p) != 64U || parse_hex_nibbles(p, 64U, hash32, 32U) != 0) {
        ns_log("bad TROPIC SIGN hash");
        return;
    }
    tropic_log_status(SECURE_TropicSign_nsc_call(hash32, rs64));
}

/* KEM INIT: 4–8 decimal digits 0-9; each digit becomes one PIN byte. */
static int parse_pin_digits(const char *dec, uint8_t *out, uint32_t *out_len)
{
    size_t n;
    size_t i;

    if (dec == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    n = strlen(dec);
    if (n < 4U || n > 8U) {
        return -1;
    }
    for (i = 0U; i < n; i++) {
        if (dec[i] < '0' || dec[i] > '9') {
            return -1;
        }
        out[i] = (uint8_t)(dec[i] - '0');
    }
    *out_len = (uint32_t)n;
    return 0;
}

static void cmd_tropic_kem(char *args)
{
    char *p = trim_line(args);
    char *sub_args = NULL;
    const host_cmd_t *cmd;

    cmd = cmd_lookup(s_kem_cmds, sizeof(s_kem_cmds) / sizeof(s_kem_cmds[0]), p, &sub_args);
    if (cmd == NULL) {
        ns_log("unknown TROPIC KEM command");
        return;
    }
    cmd->handler(sub_args);
}

static void cmd_tropic_kem_init(char *args)
{
    char *p = trim_line(args);
    char *tail;
    uint8_t pin[8];
    uint32_t pin_len = 0U;
    uint32_t do_confirm = 0U;

    tail = p + strcspn(p, " \t");
    if (*tail != '\0') {
        *tail++ = '\0';
        tail = trim_line(tail);
        if (strcmp(tail, "CONFIRM") == 0) {
            do_confirm = 1U;
        } else {
            ns_log("bad TROPIC KEM INIT (expected CONFIRM)");
            return;
        }
    }
    if (parse_pin_digits(p, pin, &pin_len) != 0) {
        ns_log("bad TROPIC KEM INIT pin");
        return;
    }
    tropic_log_status(SECURE_TropicKemInit_nsc_call(pin, pin_len, do_confirm));
}

static void cmd_tropic_kem_pub(char *args)
{
    (void)args;
    tropic_log_status(SECURE_TropicKemPub_nsc_call());
}

static void pairing_warn(unsigned long slot)
{
    char line[96];

    (void)snprintf(line, sizeof(line),
                   "WARNING: PAIRING writes a new X25519 access key to pairing slot %lu", slot);
    ns_log(line);
    ns_log("WARNING: factory SH0 (pairing slot 0) will be INVALIDATED");
    ns_log("WARNING: irreversible on real silicon; resend with y to continue");
    (void)snprintf(line, sizeof(line), "TROPIC PAIRING %lu y", slot);
    ns_log(line);
}

static void cmd_tropic_pairing(char *args)
{
    char *p = trim_line(args);
    char *end = NULL;
    unsigned long slot;
    uint32_t do_confirm = 0U;

    slot = strtoul(p, &end, 10);
    if (end == p) {
        ns_log("bad TROPIC PAIRING slot");
        return;
    }
    p = trim_line(end);
    if (*p != '\0') {
        if ((p[0] == 'y' || p[0] == 'Y') && p[1] == '\0') {
            do_confirm = 1U;
        } else {
            ns_log("bad TROPIC PAIRING (expected y)");
            return;
        }
    }
    if ((slot < 1UL) || (slot > 3UL)) {
        ns_log("TROPIC PAIRING slot must be 1-3");
        return;
    }
    if (do_confirm == 0U) {
        pairing_warn(slot);
        return;
    }
    tropic_log_status(SECURE_TropicPairing_nsc_call((uint32_t)slot));
}

static int peer_name_char_ok(unsigned char c)
{
    return ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
           ((c >= '0') && (c <= '9')) || (c == '_') || (c == '.') || (c == '-');
}

static int parse_peer_name(const char *name, uint32_t *out_len)
{
    size_t n;
    size_t i;

    if ((name == NULL) || (out_len == NULL)) {
        return -1;
    }
    n = strlen(name);
    if ((n < 1U) || (n > SECURE_PEER_NAME_MAX)) {
        return -1;
    }
    for (i = 0U; i < n; i++) {
        if (peer_name_char_ok((unsigned char)name[i]) == 0) {
            return -1;
        }
    }
    *out_len = (uint32_t)n;
    return 0;
}

static void hex_lower(char *dst, const uint8_t *src, uint32_t src_len)
{
    static const char *const digits = "0123456789abcdef";
    uint32_t i;

    for (i = 0U; i < src_len; i++) {
        dst[i * 2U] = digits[(src[i] >> 4) & 0x0fu];
        dst[(i * 2U) + 1U] = digits[src[i] & 0x0fu];
    }
    dst[src_len * 2U] = '\0';
}

static void peer_log_status(uint32_t st, const char *ok_msg)
{
    if (st == SECURE_PEER_OK) {
        ns_log(ok_msg);
        return;
    }
    if (st == SECURE_PEER_EXISTS) {
        ns_log("PEER nickname exists");
        return;
    }
    if (st == SECURE_PEER_NOT_FOUND) {
        ns_log("PEER not found");
        return;
    }
    if (st == SECURE_PEER_FULL) {
        ns_log("PEER list full");
        return;
    }
    if (st == SECURE_TROPIC_TAMPERED) {
        ns_log("DEVICE_TAMPERED");
        return;
    }
    ns_log("PEER command failed");
}

static void cmd_peer_add(char *args)
{
    char *p = trim_line(args);
    char *hash_tok;
    uint8_t hash32[32];
    uint32_t name_len = 0U;

    hash_tok = p + strcspn(p, " \t");
    if (*hash_tok == '\0') {
        ns_log("bad PEER ADD");
        return;
    }
    *hash_tok++ = '\0';
    hash_tok = trim_line(hash_tok);
    if ((parse_peer_name(p, &name_len) != 0) || (strlen(hash_tok) != 64U) ||
        (parse_hex_nibbles(hash_tok, 64U, hash32, 32U) != 0)) {
        ns_log("bad PEER ADD");
        return;
    }
    peer_log_status(SECURE_PeerAdd_nsc_call((const uint8_t *)p, name_len, hash32),
                    "PEER ADD ok");
}

static void cmd_peer_remove(char *args)
{
    char *p = trim_line(args);
    uint32_t name_len = 0U;

    if ((parse_peer_name(p, &name_len) != 0) || (p[name_len] != '\0')) {
        ns_log("bad PEER REMOVE");
        return;
    }
    peer_log_status(SECURE_PeerRemove_nsc_call((const uint8_t *)p, name_len),
                    "PEER REMOVE ok");
}

static void cmd_peer_list(char *args)
{
    uint8_t name[SECURE_PEER_NAME_MAX];
    uint8_t hash32[32];
    char hex[65];
    char line[SECURE_PEER_NAME_MAX + 1U + 64U + 1U];
    uint32_t i;
    uint32_t printed = 0U;

    (void)args;
    for (i = 0U; i < SECURE_PEER_MAX; i++) {
        uint32_t nlen = SECURE_PEER_NAME_MAX;
        uint32_t st;

        (void)memset(name, 0, sizeof(name));
        st = SECURE_PeerGet_nsc_call(i, name, &nlen, hash32);
        if (st == SECURE_PEER_NOT_FOUND) {
            break;
        }
        if (st != SECURE_PEER_OK) {
            peer_log_status(st, "");
            return;
        }
        hex_lower(hex, hash32, 32U);
        (void)snprintf(line, sizeof(line), "%.*s %s", (int)nlen, (const char *)name, hex);
        ns_log(line);
        printed++;
    }
    if (printed == 0U) {
        ns_log("PEER list empty");
    }
}

static void cmd_peer(char *args)
{
    char *p = trim_line(args);
    char *sub_args = NULL;
    const host_cmd_t *cmd;

    cmd = cmd_lookup(s_peer_cmds, sizeof(s_peer_cmds) / sizeof(s_peer_cmds[0]), p, &sub_args);
    if (cmd == NULL) {
        ns_log("unknown PEER command");
        return;
    }
    cmd->handler(sub_args);
}

static void cmd_tropic(char *args)
{
    char *p = trim_line(args);
    char *sub_args = NULL;
    const host_cmd_t *cmd;

    cmd = cmd_lookup(s_tropic_cmds, sizeof(s_tropic_cmds) / sizeof(s_tropic_cmds[0]),
                     p, &sub_args);
    if (cmd == NULL) {
        ns_log("unknown TROPIC command");
        return;
    }
    cmd->handler(sub_args);
}

static void handle_host_command_line(char *line)
{
    char *p = trim_line(line);
    char *args = NULL;
    const host_cmd_t *cmd;

    cmd = cmd_lookup(s_host_cmds, sizeof(s_host_cmds) / sizeof(s_host_cmds[0]),
                     p, &args);
    if (cmd == NULL) {
        ns_log("unknown command");
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
        ns_log("waiting PROVISION|ENCRYPT|DECRYPT <unix>");
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

#include "se_ns_usbx_sources.inc"
