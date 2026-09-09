/**
 * @file    se_owner.h
 * @brief   First-wins owner SPKI + reset password (not M&D)
 */
#ifndef SE_OWNER_H
#define SE_OWNER_H

#include <stdint.h>
#include "libtropic.h"
#include "se_nv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SE_OWNER_PW_MIN 8u
#define SE_OWNER_PW_MAX 64u

int se_owner_pw_ok(const uint8_t *pw, uint16_t len);
lt_ret_t se_owner_hash_pw(const uint8_t *pw, uint16_t len, uint8_t out[SE_NV_PW_HASH_LEN]);
lt_ret_t se_owner_verify_pw(const uint8_t *pw, uint16_t len);

/** Empty slot only. */
lt_ret_t se_owner_set(const uint8_t *pw, uint16_t pw_len, const uint8_t *spki, uint16_t spki_len);

/** Password-authorized replace: wipe user state, keep pairing, install new owner. */
lt_ret_t se_owner_replace(const uint8_t *old_pw, uint16_t old_len, const uint8_t *new_pw,
                          uint16_t new_len, const uint8_t *spki, uint16_t spki_len);

#ifdef __cplusplus
}
#endif

#endif /* SE_OWNER_H */
