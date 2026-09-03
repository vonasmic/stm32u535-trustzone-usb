/**
 * @file    host_fw_mlkem.h
 * @brief   Host-model fixture standing in for embedded fw_mlkem_pk
 */
#ifndef HOST_FW_MLKEM_H
#define HOST_FW_MLKEM_H

#include <stdint.h>
#include "se_tropic_mlkem.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t host_fw_mlkem_pk[SE_TROPIC_MLKEM_PK_LEN];
extern unsigned int host_fw_mlkem_pk_len;

#ifdef __cplusplus
}
#endif

#endif /* HOST_FW_MLKEM_H */
