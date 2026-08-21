/**
 * @file    se_tls_json_client.h
 * @brief   Secure TLS 1.3 JSON client state machine
 *
 * Starts only while se_time_is_synced(); abort/reset clears sync so NonSecure
 * must send a new TIME= before another session.
 */
#ifndef SE_TLS_JSON_CLIENT_H
#define SE_TLS_JSON_CLIENT_H

void se_tls_json_init(void);
void se_tls_json_abort(void);
/** Tear down TLS without printing a failure (USB DTR / link reset). */
void se_tls_json_reset_quiet(void);
void se_tls_json_service_once(void);

#endif /* SE_TLS_JSON_CLIENT_H */
