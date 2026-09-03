/**
 * @file    secure_client_key.h
 * @brief   Unwrap and load the wrapped ML-DSA client private key
 */
#ifndef SECURE_CLIENT_KEY_H
#define SECURE_CLIENT_KEY_H

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/types.h"

int secure_wrap_unwrap_client_key(byte *out, word32 *outLen, word32 outCap);
int secure_client_key_load(WOLFSSL_CTX *ctx);

#endif /* SECURE_CLIENT_KEY_H */
