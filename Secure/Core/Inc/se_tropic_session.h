/**
 * @file    se_tropic_session.h
 * @brief   TROPIC01 session binding and LV uplink for the TLS client
 *
 * After handshake, the TLS client derives RFC 9266 tls-exporter
 * (label EXPORTER-Channel-Binding) and hands it here. This module signs
 * SHA384(client_hash || exporter) with the TROPIC01 P-256 key and streams the
 * LV uplink (see secure_lv.h). A MitM that terminates TLS gets a different
 * exporter, so a forwarded uplink fails verification.
 */
#ifndef SE_TROPIC_SESSION_H
#define SE_TROPIC_SESSION_H

#include <stdint.h>
#include "secure_stream.h"

/* RFC 9266 tls-exporter: both sides derive this independently from TLS. */
#define SE_TROPIC_EXPORTER_LABEL     "EXPORTER-Channel-Binding"
#define SE_TROPIC_EXPORTER_LABEL_LEN 24u
#define SE_TROPIC_EXPORTER_LEN       32u
#define SE_TROPIC_CLIENT_HASH_LEN    48u

/**
 * Print SHA384(device_cert_spki || tropic_p256_pub), the same 48-byte client_hash
 * sent as provision uplink item 2.
 */
uint32_t se_tropic_client_hash_dump(void);

/**
 * Sign the session binding and stream the v4 uplink through @p write.
 * @p write receives the same @p ctx on each call.
 * @p exporter is wiped after it is hashed into the signed digest.
 * @return 0 on success, -1 on failure.
 */
int se_tropic_session_uplink(uint8_t exporter[SE_TROPIC_EXPORTER_LEN],
                             secure_stream_write_fn write, void *ctx);

/** Hex-dump the embedded TROPIC01 certificate; non-zero if none is embedded. */
uint32_t se_tropic_cert_dump(void);

#endif /* SE_TROPIC_SESSION_H */
