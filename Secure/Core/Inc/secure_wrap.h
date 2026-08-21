/**
 * @file    secure_wrap.h
 */
#ifndef SECURE_WRAP_H
#define SECURE_WRAP_H

#include "wolfssl/wolfcrypt/types.h"

int secure_wrap_unwrap_client_key(byte *out, word32 *outLen, word32 outCap);

#endif /* SECURE_WRAP_H */
