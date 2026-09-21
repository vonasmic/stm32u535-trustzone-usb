/**
 * @file    se_auth.h
 * @brief   Unsigned first-wins USB OWNER SET ingest
 *
 * Framing is se_manage_owner_set_need / parse. This module arms CDC RX and applies
 * se_owner_set + device keygen + optional SAE CA.
 */
#ifndef SE_AUTH_H
#define SE_AUTH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SE_AUTH_OK   0u
#define SE_AUTH_ERR  1u
#define SE_AUTH_BUSY 2u

int se_auth_active(void);
void se_auth_abort(void);

/** Arm USB ingest of the OWNER SET blob. Refuses if owner is already set. */
uint32_t se_auth_begin_owner(void);

/** Drain USB RX and run OWNER SET when the frame is complete. */
void se_auth_service(void);

#ifdef __cplusplus
}
#endif

#endif /* SE_AUTH_H */
