/**
 * @file    se_host_main.c
 * @brief   Host SE process: Tropic model + firmware-style command console
 *
 * Stdin commands match USB CDC on silicon (HELP lists the same names).
 * PROVISION / ENCRYPT / DECRYPT <unix> run one TLS session against the Java
 * SAE, then return to the prompt. PIN is never a console argument for those
 * three — it arrives on TLS.
 *
 * Typical flow (TROPIC01 model_server already listening on 127.0.0.1:28992):
 *   ./se_host --host 127.0.0.1 --port 11111
 *   TROPIC KEYGEN
 *   TROPIC KEM INIT 9876
 *   TROPIC KEM INIT 9876 CONFIRM
 *   PROVISION <unix>
 *   ENCRYPT <unix>
 *   DECRYPT <unix>
 */
#include "se_host_tls.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_pin.h"
#include "se_tropic_port.h"
#include "test_harness.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 11111u
#define HOST_CMD_MAX 4096u

static const char *s_host = DEFAULT_HOST;
static uint16_t s_port = (uint16_t)DEFAULT_PORT;
static int s_quit;

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --host HOST           Java SAE TLS server (default %s)\n"
            "  --port PORT           NODE_NATIVE_PORT (default %u)\n"
            "  --help\n"
            "Stdin is a firmware-style console (HELP, PROVISION, ENCRYPT, DECRYPT, TROPIC …).\n",
            argv0, DEFAULT_HOST, (unsigned)DEFAULT_PORT);
}

static char *trim_line(char *line)
{
    char *end;

    while (*line == ' ' || *line == '\t') {
        line++;
    }
    end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
                          end[-1] == '\n')) {
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
    const char *name;
    const char *usage;
    host_cmd_fn handler;
} host_cmd_t;

static void cmd_help(char *args);
static void cmd_quit(char *args);
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
static int parse_pin_digits(const char *dec, uint8_t *out, uint32_t *out_len);

static const host_cmd_t s_kem_cmds[] = {
    { "INIT",  "TROPIC KEM INIT <pin> [CONFIRM]", cmd_tropic_kem_init },
    { "PUB",   "TROPIC KEM PUB",                      cmd_tropic_kem_pub },
};

static const host_cmd_t s_tropic_cmds[] = {
    { "PING",    "TROPIC PING",                    cmd_tropic_ping },
    { "INFO",    "TROPIC INFO",                     cmd_tropic_info },
    { "PUB",     "TROPIC PUB",                      cmd_tropic_pub },
    { "KEYGEN",  "TROPIC KEYGEN [<pin>]",           cmd_tropic_keygen },
    { "SIGN",    "TROPIC SIGN <64-hex>",            cmd_tropic_sign },
    { "KEM",     NULL,                             cmd_tropic_kem },
    { "PAIRING", "TROPIC PAIRING <1-3> [y]",       cmd_tropic_pairing },
};

static const host_cmd_t s_host_cmds[] = {
    { "HELP",      "HELP",                         cmd_help },
    { "?",         NULL,                           cmd_help },
    { "PROVISION", "PROVISION <unix>",             cmd_provision },
    { "ENCRYPT",   "ENCRYPT <unix>",               cmd_encrypt },
    { "DECRYPT",   "DECRYPT <unix>",               cmd_decrypt },
    { "TROPIC",    NULL,                           cmd_tropic },
    { "QUIT",      "QUIT",                         cmd_quit },
    { "EXIT",      NULL,                           cmd_quit },
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

static const host_cmd_t *cmd_lookup(const host_cmd_t *table, size_t count, char *line,
                                    char **args_out)
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
            se_tropic_log("%s", table[i].usage);
        }
    }
}

static void tropic_log_status(uint32_t st)
{
    if (st == SE_TROPIC_OK) {
        return;
    }
    if (st == SE_TROPIC_SLOT_OCC) {
        se_tropic_log("TROPIC slot occupied");
        return;
    }
    if (st == SE_TROPIC_NOT_READY) {
        se_tropic_log("TROPIC not ready");
        return;
    }
    if (st == SE_TROPIC_TAMPERED) {
        se_tropic_log("DEVICE_TAMPERED");
        return;
    }
    se_tropic_log("TROPIC command failed");
}

static void cmd_help(char *args)
{
    (void)args;
    se_tropic_log("commands:");
    cmd_list_usage(s_host_cmds, sizeof(s_host_cmds) / sizeof(s_host_cmds[0]));
    cmd_list_usage(s_tropic_cmds, sizeof(s_tropic_cmds) / sizeof(s_tropic_cmds[0]));
    cmd_list_usage(s_kem_cmds, sizeof(s_kem_cmds) / sizeof(s_kem_cmds[0]));
}

static void cmd_quit(char *args)
{
    (void)args;
    s_quit = 1;
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
        se_tropic_log("bad unix time");
        return;
    }
    /* Host wolfSSL uses the process clock; unix is required to match firmware. */
    se_tropic_log("time synced unix=%lu", (unsigned long)unix_utc);
    if (se_host_tls_run(s_host, s_port, mode) != 0) {
        se_tropic_log("TLS start failed");
        return;
    }
    se_tropic_log("waiting PROVISION|ENCRYPT|DECRYPT <unix>");
}

static void cmd_provision(char *args)
{
    cmd_tls_start(SE_HOST_TLS_PROVISION, args);
}

static void cmd_encrypt(char *args)
{
    cmd_tls_start(SE_HOST_TLS_ENCRYPT, args);
}

static void cmd_decrypt(char *args)
{
    cmd_tls_start(SE_HOST_TLS_DECRYPT, args);
}

static void cmd_tropic_ping(char *args)
{
    (void)args;
    tropic_log_status(se_tropic_ping());
}

static void cmd_tropic_info(char *args)
{
    (void)args;
    tropic_log_status(se_tropic_info());
}

static void cmd_tropic_pub(char *args)
{
    uint8_t xy64[64];

    (void)args;
    tropic_log_status(se_tropic_pub_read(xy64));
}

static void cmd_tropic_keygen(char *args)
{
    char *p = trim_line(args);
    uint8_t pin[SE_TROPIC_PIN_SIZE_MAX];
    uint32_t pin_len = 0U;

    if (*p == '\0') {
        tropic_log_status(se_tropic_keygen(NULL, 0U));
        return;
    }
    if (parse_pin_digits(p, pin, &pin_len) != 0) {
        se_tropic_log("bad TROPIC KEYGEN pin");
        return;
    }
    p = trim_line(p + pin_len);
    if (*p != '\0') {
        se_tropic_log("bad TROPIC KEYGEN");
        return;
    }
    tropic_log_status(se_tropic_keygen(pin, (uint8_t)pin_len));
}

static void cmd_tropic_sign(char *args)
{
    uint8_t hash32[32];
    uint8_t rs64[64];
    char *p = trim_line(args);

    if (strlen(p) != 64U || parse_hex_nibbles(p, 64U, hash32, 32U) != 0) {
        se_tropic_log("bad TROPIC SIGN hash");
        return;
    }
    tropic_log_status(se_tropic_sign_hash(hash32, rs64));
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
        se_tropic_log("unknown TROPIC KEM command");
        return;
    }
    cmd->handler(sub_args);
}

static void cmd_tropic_kem_init(char *args)
{
    char *p = trim_line(args);
    char *tail;
    uint8_t pin[SE_TROPIC_PIN_SIZE_MAX];
    uint32_t pin_len = 0U;
    uint32_t do_confirm = 0U;
    uint32_t st;

    tail = p + strcspn(p, " \t");
    if (*tail != '\0') {
        *tail++ = '\0';
        tail = trim_line(tail);
        if (strcmp(tail, "CONFIRM") == 0) {
            do_confirm = 1U;
        } else {
            se_tropic_log("bad TROPIC KEM INIT (expected CONFIRM)");
            return;
        }
    }
    if (parse_pin_digits(p, pin, &pin_len) != 0) {
        se_tropic_log("bad TROPIC KEM INIT pin");
        return;
    }
    if (do_confirm != 0U) {
        st = se_tropic_kem_init_confirm(pin, (uint8_t)pin_len, NULL, 0U);
    } else {
        st = se_tropic_kem_init_probe();
    }
    wc_ForceZero(pin, sizeof(pin));
    tropic_log_status(st);
}

static void cmd_tropic_kem_pub(char *args)
{
    (void)args;
    tropic_log_status(se_tropic_kem_pub_dump());
}

static void cmd_tropic_pairing(char *args)
{
    char *p = trim_line(args);
    char *end = NULL;
    unsigned long slot;
    uint32_t do_confirm = 0U;

    slot = strtoul(p, &end, 10);
    if (end == p) {
        se_tropic_log("bad TROPIC PAIRING slot");
        return;
    }
    p = trim_line(end);
    if (*p != '\0') {
        if ((p[0] == 'y' || p[0] == 'Y') && p[1] == '\0') {
            do_confirm = 1U;
        } else {
            se_tropic_log("bad TROPIC PAIRING (expected y)");
            return;
        }
    }
    if ((slot < 1UL) || (slot > 3UL)) {
        se_tropic_log("TROPIC PAIRING slot must be 1-3");
        return;
    }
    if (do_confirm == 0U) {
        se_tropic_log("WARNING: PAIRING writes a new X25519 access key to pairing slot %lu",
                      slot);
        se_tropic_log("WARNING: factory SH0 (pairing slot 0) will be INVALIDATED");
        se_tropic_log("WARNING: irreversible on real silicon; resend with y to continue");
        se_tropic_log("TROPIC PAIRING %lu y", slot);
        return;
    }
    tropic_log_status(se_create_pairing_key_to_tropic((uint8_t)slot));
}

static void cmd_tropic(char *args)
{
    char *p = trim_line(args);
    char *sub_args = NULL;
    const host_cmd_t *cmd;

    cmd = cmd_lookup(s_tropic_cmds, sizeof(s_tropic_cmds) / sizeof(s_tropic_cmds[0]), p,
                      &sub_args);
    if (cmd == NULL) {
        se_tropic_log("unknown TROPIC command");
        return;
    }
    cmd->handler(sub_args);
}

static void handle_host_command_line(char *line)
{
    char *p = trim_line(line);
    char *args = NULL;
    const host_cmd_t *cmd;

    if (*p == '\0') {
        return;
    }
    cmd = cmd_lookup(s_host_cmds, sizeof(s_host_cmds) / sizeof(s_host_cmds[0]), p, &args);
    if (cmd == NULL) {
        se_tropic_log("unknown command");
        return;
    }
    cmd->handler(args);
}

int main(int argc, char **argv)
{
    char line[HOST_CMD_MAX];
    int i;
    int tty;

    setvbuf(stdout, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if ((strcmp(argv[i], "--host") == 0) && (i + 1 < argc)) {
            s_host = argv[++i];
        } else if ((strcmp(argv[i], "--port") == 0) && (i + 1 < argc)) {
            int p = atoi(argv[++i]);

            if ((p <= 0) || (p > 65535)) {
                fprintf(stderr, "bad --port\n");
                return 1;
            }
            s_port = (uint16_t)p;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (host_crypto_init() != 0) {
        return 1;
    }

    tty = isatty(STDIN_FILENO);
    se_tropic_log("TROPIC01 model 127.0.0.1:28992, SAE %s:%u", s_host, (unsigned)s_port);
    se_tropic_log("waiting PROVISION|ENCRYPT|DECRYPT <unix>");

    while (s_quit == 0) {
        if (tty != 0) {
            fputs("> ", stdout);
            (void)fflush(stdout);
        }
        if (fgets(line, (int)sizeof(line), stdin) == NULL) {
            break;
        }
        handle_host_command_line(line);
    }

    se_tropic_deinit_session();
    host_crypto_deinit();
    return 0;
}
