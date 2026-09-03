/**
 * @file    se_host_tls.h
 * @brief   Host TLS 1.3 client (POSIX) for the Java SAE command port
 */
#ifndef SE_HOST_TLS_H
#define SE_HOST_TLS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Must match SECURE_TLS_MODE_* in se_tls_nsc.h */
#define SE_HOST_TLS_PROVISION 1u
#define SE_HOST_TLS_ENCRYPT   2u
#define SE_HOST_TLS_DECRYPT   3u

/**
 * Connect as TLS 1.3 mTLS client for one armed console command. PROVISION
 * verifies the SAE application CA, then streams se_tropic_session_uplink
 * and ingest pads. ENCRYPT / DECRYPT verify the client CA, wait for PIN+payload,
 * OTP-consume, and reply. PIN is never an argument here — it arrives on TLS.
 * Safe to call again after return (next console command).
 * @return 0 on success, -1 on failure
 */
int se_host_tls_run(const char *host, uint16_t port, uint32_t mode);

#ifdef __cplusplus
}
#endif

#endif /* SE_HOST_TLS_H */
