/**
 * @file    se_tls_user.h
 * @brief   Pin ENCRYPT/DECRYPT TLS peer to the provisioned home-PC user SPKI
 */
#ifndef SE_TLS_USER_H
#define SE_TLS_USER_H

#include "wolfssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * After mTLS: extract the peer leaf SPKI and compare to embedded fw_user_spki.
 * @return 0 on match
 */
int se_tls_user_pin_peer(WOLFSSL *ssl);

#ifdef __cplusplus
}
#endif

#endif /* SE_TLS_USER_H */
