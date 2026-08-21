/**
 * @file    fw_client_key_id.h
 * @brief   Shared PKCS#11 CKA_ID for TLS client private key
 */
#ifndef FW_CLIENT_KEY_ID_H
#define FW_CLIENT_KEY_ID_H

#include <stdint.h>

#ifndef FW_CLIENT_KEY_PKCS11_ID_LEN
#define FW_CLIENT_KEY_PKCS11_ID_LEN 10u
#endif

#ifndef FW_CLIENT_KEY_PKCS11_ID
#define FW_CLIENT_KEY_PKCS11_ID \
    { 0x53, 0x45, 0x5f, 0x74, 0x6c, 0x73, 0x5f, 0x63, 0x6c, 0x69 }
#endif

#endif /* FW_CLIENT_KEY_ID_H */
