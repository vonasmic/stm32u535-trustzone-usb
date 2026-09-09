/**
 * @file    host_pty_cdc.c
 * @brief   PTY master implementing USBX CDC read/write/ioctl for tls_usb_io.c
 *
 * User PTY vs optional SAE PTY: user slave attached wins (lab "home PC").
 * That tears down the SAE symlink so a continuous usb-tcp bridge waits and
 * reopens when UserApp DISCONNECTs. Slave attach is DTR. Stdin is extra RX.
 * ASCII TX (DEBUG:<text>:DEBUG) is echoed to stdout; TLS types 0x14–0x17 are not.
 */
#define _GNU_SOURCE
#include "host_pty.h"
#include "tls_usb_io.h"
#include "ux_api.h"
#include "ux_device_class_cdc_acm.h"
#include "main.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define HOST_PTY_DEFAULT_LINK "/tmp/ttyACM0"

typedef struct {
    int master;
    char link[256];
} PtyPort;

static PtyPort s_user;
static PtyPort s_sae;
static PtyPort *s_io;
static int s_have_sae;
static int s_slave_attached;
static uint32_t s_user_gone_ms;
static int s_stdin_eof;
static int s_stdin_got_data;
static int s_stdin_disabled;
static int s_activated;
static UX_SLAVE_CLASS_CDC_ACM s_cdc;
static uint32_t s_write_off;
static uint32_t s_tick_base_ms;
static uint8_t s_tick_inited;

static uint32_t monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0U;
    }
    return (uint32_t)((uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U);
}

uint32_t HAL_GetTick(void)
{
    if (s_tick_inited == 0U) {
        s_tick_base_ms = monotonic_ms();
        s_tick_inited = 1U;
    }
    return monotonic_ms() - s_tick_base_ms;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int slave_is_attached(int master)
{
    struct pollfd p;
    int r;

    if (master < 0) {
        return 0;
    }
    p.fd = master;
    p.events = POLLIN;
    p.revents = 0;
    r = poll(&p, 1, 0);
    if (r < 0) {
        return 0;
    }
    if ((p.revents & POLLHUP) != 0) {
        return 0;
    }
    return 1;
}

static void echo_ascii_tx(const uint8_t *buf, ULONG len)
{
    ULONG n = 0U;

    if (buf == NULL || len == 0U) {
        return;
    }
    /* Stop at the first TLS record byte so DEBUG:<text>:DEBUG plus a glued
     * ClientHello is not dumped as binary on stdout. */
    while (n < len && (buf[n] < 0x14U || buf[n] > 0x17U)) {
        n++;
    }
    if (n == 0U) {
        return;
    }
    (void)fwrite(buf, 1, (size_t)n, stdout);
    (void)fflush(stdout);
}

static void pty_teardown(PtyPort *p)
{
    if (p == NULL) {
        return;
    }
    if (p->link[0] != '\0') {
        (void)unlink(p->link);
    }
    if (p->master >= 0) {
        close(p->master);
        p->master = -1;
    }
}

static int pty_setup(PtyPort *p, const char *link)
{
    char *pts;
    int slave;
    struct termios tio;

    if (p == NULL || link == NULL || link[0] == '\0') {
        return -1;
    }
    if (strlen(link) >= sizeof(p->link)) {
        fprintf(stderr, "tty path too long\n");
        return -1;
    }
    pty_teardown(p);
    (void)memcpy(p->link, link, strlen(link) + 1U);

    p->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (p->master < 0) {
        perror("posix_openpt");
        p->link[0] = '\0';
        return -1;
    }
    if (grantpt(p->master) != 0 || unlockpt(p->master) != 0) {
        perror("grantpt/unlockpt");
        close(p->master);
        p->master = -1;
        p->link[0] = '\0';
        return -1;
    }
    if (set_nonblock(p->master) != 0) {
        perror("fcntl PTY");
        close(p->master);
        p->master = -1;
        p->link[0] = '\0';
        return -1;
    }
    pts = ptsname(p->master);
    if (pts == NULL) {
        perror("ptsname");
        close(p->master);
        p->master = -1;
        p->link[0] = '\0';
        return -1;
    }
    slave = open(pts, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        perror("open PTY slave");
        close(p->master);
        p->master = -1;
        p->link[0] = '\0';
        return -1;
    }
    if (tcgetattr(slave, &tio) == 0) {
        cfmakeraw(&tio);
        (void)tcsetattr(slave, TCSANOW, &tio);
    }
    close(slave);

    (void)unlink(link);
    if (symlink(pts, link) != 0) {
        perror("symlink tty");
        close(p->master);
        p->master = -1;
        p->link[0] = '\0';
        return -1;
    }
    (void)fprintf(stderr, "CDC PTY %s -> %s\n", link, pts);
    return 0;
}

int host_pty_open(const char *link_path, const char *sae_link_path)
{
    const char *user = (link_path != NULL && link_path[0] != '\0') ? link_path
                                                                   : HOST_PTY_DEFAULT_LINK;

    s_user.master = -1;
    s_sae.master = -1;
    s_user.link[0] = '\0';
    s_sae.link[0] = '\0';
    s_io = NULL;
    s_have_sae = 0;

    if (pty_setup(&s_user, user) != 0) {
        return -1;
    }
    if (sae_link_path != NULL && sae_link_path[0] != '\0') {
        if (strcmp(sae_link_path, user) == 0) {
            fprintf(stderr, "--tty-sae must differ from --tty\n");
            pty_teardown(&s_user);
            return -1;
        }
        if (pty_setup(&s_sae, sae_link_path) != 0) {
            pty_teardown(&s_user);
            return -1;
        }
        s_have_sae = 1;
    }

    (void)set_nonblock(STDIN_FILENO);
    s_slave_attached = 0;
    s_stdin_eof = 0;
    s_stdin_got_data = 0;
    s_stdin_disabled = 0;
    s_activated = 0;
    s_write_off = 0U;
    return 0;
}

void host_pty_close(void)
{
    pty_teardown(&s_user);
    pty_teardown(&s_sae);
    s_user.link[0] = '\0';
    s_sae.link[0] = '\0';
    s_io = NULL;
    s_have_sae = 0;
    s_activated = 0;
    s_slave_attached = 0;
}

void host_pty_poll_link(void)
{
    int user_on;
    PtyPort *want;
    int attached;

    if (s_user.master < 0) {
        return;
    }
    if (s_activated == 0) {
        tls_usb_cdc_activate(&s_cdc);
        s_activated = 1;
        tls_usb_cdc_parameter_change(&s_cdc);
    }

    user_on = slave_is_attached(s_user.master);
    if (s_have_sae != 0) {
        if (user_on != 0) {
            s_user_gone_ms = 0U;
            if (s_sae.master >= 0) {
                (void)fprintf(stderr, "CDC switch: user attached, SAE PTY down\n");
                pty_teardown(&s_sae);
            }
        } else if (s_sae.master < 0 && s_sae.link[0] != '\0') {
            /* jSerialComm/DTR can pulse POLLHUP while UserApp still holds the slave.
             * Wait a full second of "user gone" before publishing SAE again. */
            if (s_user_gone_ms == 0U) {
                s_user_gone_ms = monotonic_ms();
                if (s_user_gone_ms == 0U) {
                    s_user_gone_ms = 1U;
                }
            }
            if ((uint32_t)(monotonic_ms() - s_user_gone_ms) >= 1000U) {
                (void)fprintf(stderr, "CDC switch: SAE PTY up\n");
                if (pty_setup(&s_sae, s_sae.link) != 0) {
                    s_sae.link[0] = '\0';
                }
                s_user_gone_ms = 0U;
            }
        }
    }

    want = NULL;
    if (user_on != 0) {
        want = &s_user;
    } else if (s_sae.master >= 0 && slave_is_attached(s_sae.master) != 0) {
        want = &s_sae;
    }
    attached = (want != NULL) ? 1 : 0;

    if (want == s_io && attached == s_slave_attached) {
        return;
    }

    if (s_slave_attached != 0 && (attached == 0 || want != s_io)) {
        s_slave_attached = 0;
        s_io = NULL;
        s_write_off = 0U;
        tls_usb_cdc_parameter_change(&s_cdc);
    }
    s_io = want;
    if (attached != 0 && s_slave_attached == 0) {
        s_slave_attached = 1;
        s_write_off = 0U;
        tls_usb_cdc_parameter_change(&s_cdc);
    }
}

void host_pty_wait(int timeout_ms)
{
    struct pollfd fds[3];
    nfds_t n = 0;

    if (s_user.master >= 0) {
        fds[n].fd = s_user.master;
        fds[n].events = POLLIN;
        n++;
    }
    if (s_sae.master >= 0) {
        fds[n].fd = s_sae.master;
        fds[n].events = POLLIN;
        n++;
    }
    if (s_stdin_eof == 0 && s_stdin_disabled == 0) {
        fds[n].fd = STDIN_FILENO;
        fds[n].events = POLLIN;
        n++;
    }
    if (n == 0) {
        return;
    }
    (void)poll(fds, n, timeout_ms);
}

int host_pty_stdin_eof(void)
{
    return s_stdin_eof;
}

UINT ux_device_class_cdc_acm_read_run(UX_SLAVE_CLASS_CDC_ACM *cdc, UCHAR *buffer,
                                      ULONG requested_length, ULONG *actual_length)
{
    ssize_t n;

    (void)cdc;
    if (actual_length != NULL) {
        *actual_length = 0U;
    }
    if (buffer == NULL || requested_length == 0U) {
        return UX_STATE_ERROR;
    }

    if (s_io != NULL && s_io->master >= 0) {
        n = read(s_io->master, buffer, (size_t)requested_length);
        if (n > 0) {
            if (actual_length != NULL) {
                *actual_length = (ULONG)n;
            }
            return UX_STATE_NEXT;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EIO) {
            return UX_STATE_ERROR;
        }
    }

    if (s_stdin_eof == 0 && s_stdin_disabled == 0) {
        n = read(STDIN_FILENO, buffer, (size_t)requested_length);
        if (n > 0) {
            s_stdin_got_data = 1;
            if (actual_length != NULL) {
                *actual_length = (ULONG)n;
            }
            return UX_STATE_NEXT;
        }
        if (n == 0) {
            if (isatty(STDIN_FILENO) || s_stdin_got_data != 0) {
                s_stdin_eof = 1;
            } else {
                s_stdin_disabled = 1;
            }
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            s_stdin_eof = 1;
        }
    }
    return UX_STATE_WAIT;
}

UINT ux_device_class_cdc_acm_write_run(UX_SLAVE_CLASS_CDC_ACM *cdc, UCHAR *buffer,
                                       ULONG requested_length, ULONG *actual_length)
{
    ssize_t n;

    (void)cdc;
    if (buffer == NULL || requested_length == 0U) {
        return UX_STATE_ERROR;
    }

    if (s_slave_attached == 0 || s_io == NULL || s_io->master < 0) {
        echo_ascii_tx(buffer, requested_length);
        s_write_off = 0U;
        if (actual_length != NULL) {
            *actual_length = requested_length;
        }
        return UX_STATE_NEXT;
    }

    while (s_write_off < requested_length) {
        n = write(s_io->master, buffer + s_write_off,
                  (size_t)(requested_length - s_write_off));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return UX_STATE_WAIT;
            }
            s_write_off = 0U;
            return UX_STATE_ERROR;
        }
        s_write_off += (uint32_t)n;
    }
    echo_ascii_tx(buffer, requested_length);
    s_write_off = 0U;
    if (actual_length != NULL) {
        *actual_length = requested_length;
    }
    return UX_STATE_NEXT;
}

UINT ux_device_class_cdc_acm_ioctl(UX_SLAVE_CLASS_CDC_ACM *cdc, ULONG ioctl_function,
                                   VOID *parameter)
{
    UX_SLAVE_CLASS_CDC_ACM_LINE_STATE_PARAMETER *line;

    (void)cdc;
    if (ioctl_function != UX_SLAVE_CLASS_CDC_ACM_IOCTL_GET_LINE_STATE || parameter == NULL) {
        return UX_SUCCESS;
    }
    line = (UX_SLAVE_CLASS_CDC_ACM_LINE_STATE_PARAMETER *)parameter;
    line->ux_slave_class_cdc_acm_parameter_dtr = s_slave_attached ? 1UL : 0UL;
    line->ux_slave_class_cdc_acm_parameter_rts = s_slave_attached ? 1UL : 0UL;
    return UX_SUCCESS;
}
