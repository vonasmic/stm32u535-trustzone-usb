/**
 * @file    se_tls_client.h
 * @brief   Secure TLS 1.3 mTLS client (I/O and session lifecycle)
 *
 * Starts after NonSecure arms a mode with a Unix timestamp. abort/reset clears
 * sync so the next command must include a fresh timestamp. PROVISION verifies
 * the SAE application CA, then sends the session uplink and ingest pads.
 * ENCRYPT / DECRYPT verify the client CA, then wait for PIN + payload over TLS
 * and reply with OTP.
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
 * Arm the next TLS session (PROVISION / ENCRYPT / DECRYPT).
 * @return 0 on success, -1 if already running, time not synced, or bad mode
 */
int se_tls_arm(uint32_t mode);
/** 1 while a mode is armed or a handshake/session is in progress. */
int se_tls_session_active(void);

#endif /* SE_TLS_CLIENT_H */
