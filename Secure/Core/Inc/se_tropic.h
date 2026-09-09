/**
 * @file    se_tropic.h
 * @brief   TROPIC01 secure element service (Secure world)
 */
#ifndef SE_TROPIC_H
#define SE_TROPIC_H

#include <stdint.h>

#define SE_TROPIC_OK          0u
#define SE_TROPIC_ERR         1u
#define SE_TROPIC_BUSY        2u
#define SE_TROPIC_SLOT_OCC    3u
#define SE_TROPIC_NOT_READY   4u
#define SE_TROPIC_TAMPERED    5u

#include "libtropic.h"

void se_tropic_hw_init(void);
uint32_t se_tropic_init_session(void);
void se_tropic_deinit_session(void);
uint32_t se_tropic_ping(void);
uint32_t se_tropic_info(void);
uint32_t se_tropic_pub_read(uint8_t *out_xy64);
/** Empty slot: generate. Occupied: PIN required, then erase+generate. */
uint32_t se_tropic_keygen(const uint8_t *pin, uint8_t pin_len);
uint32_t se_tropic_sign_hash(const uint8_t hash32[32], uint8_t rs64[64]);
uint32_t se_tropic_session_sign(const uint8_t hash32[32], uint8_t rs64[64]);
/** Generate X25519, write pub to slot, persist, invalidate SH0, re-session. */
uint32_t se_create_pairing_key_to_tropic(uint8_t slot);
/** Copy active host pairing public key (32 B). ERR if still on factory SH0. */
uint32_t se_tropic_pairing_pub_read(uint8_t out32[32]);
uint32_t se_tropic_is_session_active(void);
lt_handle_t *se_tropic_handle(void);

/** Erase R-MEM 0–511 and ECC slot 0. Pairing slots unchanged. */
uint32_t se_tropic_user_wipe(void);

#endif /* SE_TROPIC_H */
