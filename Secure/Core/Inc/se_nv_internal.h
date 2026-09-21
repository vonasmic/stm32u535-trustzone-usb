/**
 * @file    se_nv_internal.h
 * @brief   NV helpers shared by se_nv.c and se_nv_peer.c
 */
#ifndef SE_NV_INTERNAL_H
#define SE_NV_INTERNAL_H

#include "se_nv.h"

int se_nv_peer_name_ok(const uint8_t *name, uint8_t name_len);

#endif /* SE_NV_INTERNAL_H */
