/**
 * @file    tls_json_client.h
 * @brief   TLS 1.3 JSON client state machine (NonSecure)
 */
#ifndef TLS_JSON_CLIENT_H
#define TLS_JSON_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

void tls_json_client_init(void);
void tls_json_client_poll(void);
void tls_json_client_abort(void);

#ifdef __cplusplus
}
#endif

#endif /* TLS_JSON_CLIENT_H */
