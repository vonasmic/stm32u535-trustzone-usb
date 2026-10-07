/**
 * @file    se_tls_client.h
 * @brief   Secure TLS 1.3 mTLS client (I/O and session lifecycle)
 *
 * Starts after NonSecure arms a mode with a Unix timestamp. abort/reset clears
 * sync so the next command must include a fresh timestamp. PROVISION verifies
 * the SAE application CA from FLASH_CREDS, then sends the session uplink,
 * erases QKD pads, reports TROPIC_WIPE_FINISHED, and ingest pads.
 * ENCRYPT / DECRYPT are mTLS and pin the peer to the enrolled
 * owner key, then wait for PIN + payload over TLS and reply with OTP. MANAGE
 * pins the same owner without a device client cert and streams one unsigned
 * command.
 */
#ifndef SE_TLS_CLIENT_H
#define SE_TLS_CLIENT_H

#include <stdint.h>

void se_tls_init(void);
void se_tls_abort(void);
/** Tear down TLS without printing a failure (USB DTR / link reset). */
void se_tls_reset_quiet(void);
void se_tls_service_once(void);

/**
 * Arm the next TLS session (PROVISION / ENCRYPT / DECRYPT / MANAGE).
 * @return 0 on success, -1 if already running, time not synced, or bad mode
 */
int se_tls_arm(uint32_t mode);
/** 1 while a TLS mode is armed (handshake / app / shutdown). */
int se_tls_session_active(void);
/** 1 while TLS is armed or post-close TX (reply / close_notify) still drains. */
int se_tls_pipe_busy(void);

/** Last se_tls_abort(): 0 none, 1 connect, 2 wolfSSL_read, 3 manage accum, 4 rx overflow, 5 rx nsc, 6 pin, 8 wolfSSL_write, 11 uplink build, 12 tropic wipe. */
extern volatile uint32_t se_tls_die;
extern volatile int se_tls_die_err;

#endif /* SE_TLS_CLIENT_H */
