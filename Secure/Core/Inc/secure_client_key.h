/**
 * @file    secure_client_key.h
 */
#ifndef SECURE_CLIENT_KEY_H
#define SECURE_CLIENT_KEY_H

#include "wolfssl/ssl.h"

int secure_client_key_load(WOLFSSL_CTX *ctx);

#endif /* SECURE_CLIENT_KEY_H */
