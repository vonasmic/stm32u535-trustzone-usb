/**
 * @file    se_time.h
 * @brief   Wall-clock time for wolfSSL (set via NSC from NonSecure)
 */
#ifndef SE_TIME_H
#define SE_TIME_H

#include <stdint.h>

/** 1 after NonSecure applied a valid Unix time via SECURE_SetUnixTime_nsc_call. */
int se_time_is_synced(void);

/**
 * Clear TLS sync flag (disconnect, TLS abort). The monotonic floor keeps
 * advancing from SysTick. A later PROVISION / ENCRYPT / DECRYPT <unix>
 * restores a valid clock without moving the floor backwards.
 */
void se_time_clear_synced(void);

/**
 * Mark the clock synced from a host Unix UTC seconds value. Out of range is
 * rejected. The clock is updated only if the value is at or ahead of the
 * floor; otherwise the kept floor stays in use. Does not start TLS.
 * @return 0 if the clock was updated, 1 if the kept floor is used, -1 if
 *         out of range.
 */
int se_time_set_unix(uint32_t unix_utc);

/** Current Unix UTC, or 0 if not synced. */
uint32_t se_time_unix_now(void);

/**
 * Restore TIME floor from MCU NV (call once early in Secure boot).
 * Does not mark TLS synced; host must still send a timestamp on
 * PROVISION / ENCRYPT / DECRYPT.
 */
void se_time_boot_restore(void);

#endif /* SE_TIME_H */
