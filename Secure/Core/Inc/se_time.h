/**
 * @file    se_time.h
 * @brief   Wall-clock time for wolfSSL (set via NSC from NonSecure)
 */
#ifndef SE_TIME_H
#define SE_TIME_H

#include <stdint.h>

/** 1 after NonSecure applied a valid Unix time via SECURE_SetUnixTime_nsc_call. */
int se_time_is_synced(void);

/** Clear sync flag (disconnect, TLS exit). RTC contents are left unchanged. */
void se_time_clear_synced(void);

/**
 * Set wall clock from Unix UTC seconds and mark synced (enables TLS start).
 * @return 0 on success, -1 if out of range.
 */
int se_time_set_unix(uint32_t unix_utc);

/** Current Unix UTC, or 0 if not synced. */
uint32_t se_time_unix_now(void);

#endif /* SE_TIME_H */
