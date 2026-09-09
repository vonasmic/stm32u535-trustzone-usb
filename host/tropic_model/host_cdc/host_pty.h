/**
 * @file    host_pty.h
 * @brief   PTY master that stands in for USB CDC ACM
 *
 * Lab switch: @p link_path is the UserApp cable; optional @p sae_link_path is
 * the provision-relay cable. Opening the user slave hides the SAE symlink so
 * a long-running bridge waits and reconnects; closing it restores SAE.
 */
#ifndef HOST_PTY_H
#define HOST_PTY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Open the user PTY (default /tmp/ttyACM0). If @p sae_link_path is non-NULL,
 * also publish a second PTY for the provision relay.
 */
int host_pty_open(const char *link_path, const char *sae_link_path);
void host_pty_close(void);

/** Apply slave-attach/detach and the user-vs-SAE switch. Call before tls_usb_poll. */
void host_pty_poll_link(void);

/** Block up to @p timeout_ms for PTY or stdin activity. */
void host_pty_wait(int timeout_ms);

int host_pty_stdin_eof(void);

#ifdef __cplusplus
}
#endif

#endif /* HOST_PTY_H */
