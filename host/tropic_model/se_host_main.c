/**
 * @file    se_host_main.c
 * @brief   Host SE device: firmware USB console + TLS over a PTY (ttyACM)
 *
 * Publishes --tty (UserApp) and optional --tty-sae (provision relay). Opening
 * the user slave hides the SAE symlink so the relay can stay running.
 */
#include "host_pty.h"
#include "host_tropic.h"
#include "se_time.h"
#include "se_tls_client.h"
#include "se_usb_tls.h"
#include "test_harness.h"
#include "tls_usb_io.h"
#include "wolfssl/ssl.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_TTY "/tmp/ttyACM0"
#define DEFAULT_TTY_SAE "/tmp/ttyACM-sae"

static void on_signal(int sig)
{
    (void)sig;
    host_pty_close();
    _exit(128 + (sig & 127));
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--tty PATH] [--tty-sae PATH] [--tropic-port PORT]\n"
            "  --tty PATH         CDC PTY symlink (default %s)\n"
            "  --tty-sae PATH     extra PTY (default %s; none to disable)\n"
            "  --tropic-port PORT TROPIC01 model_server TCP port (default %u)\n",
            argv0, DEFAULT_TTY, DEFAULT_TTY_SAE, (unsigned)HOST_TROPIC_DEFAULT_PORT);
}

int main(int argc, char **argv)
{
    const char *tty = DEFAULT_TTY;
    const char *tty_sae = DEFAULT_TTY_SAE;
    unsigned tropic_port = HOST_TROPIC_DEFAULT_PORT;
    int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* Model TCP send() and DEBUG fwrite: EPIPE instead of killing the pane. */
    (void)signal(SIGPIPE, SIG_IGN);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if ((strcmp(argv[i], "--tty") == 0) && (i + 1 < argc)) {
            tty = argv[++i];
        } else if ((strcmp(argv[i], "--tty-sae") == 0) && (i + 1 < argc)) {
            tty_sae = argv[++i];
            if (tty_sae[0] == '\0' || strcmp(tty_sae, "none") == 0) {
                tty_sae = NULL;
            }
        } else if ((strcmp(argv[i], "--tropic-port") == 0) && (i + 1 < argc)) {
            tropic_port = (unsigned)atoi(argv[++i]);
            if (tropic_port == 0U || tropic_port > 65535U) {
                fprintf(stderr, "invalid --tropic-port\n");
                return 1;
            }
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    host_tropic_set_port(tropic_port);

    if (host_crypto_init() != 0) {
        return 1;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n");
        host_crypto_deinit();
        return 1;
    }

    if (host_pty_open(tty, tty_sae) != 0) {
        (void)wolfSSL_Cleanup();
        host_crypto_deinit();
        return 1;
    }
    (void)signal(SIGINT, on_signal);
    (void)signal(SIGTERM, on_signal);

    tls_usb_io_init();
    se_time_boot_restore();
    se_usb_tls_init();
    se_tls_init();
    host_pty_poll_link();

    while (host_pty_stdin_eof() == 0) {
        host_pty_poll_link();
        tls_usb_poll();
        host_pty_wait(10);
    }

    host_pty_close();
    (void)wolfSSL_Cleanup();
    host_crypto_deinit();
    return 0;
}
