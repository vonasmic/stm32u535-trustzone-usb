/**
 * @file    wc_port_time.c
 * @brief   wolfSSL TIME_OVERRIDES — wall clock set via NSC from NonSecure
 *
 * Source of truth is a RAM unix base + HAL tick, with the floor also persisted
 * in MCU NV so reboot cannot roll a later timestamp backward.
 */
#include <time.h>
#include "main.h"
#include "se_time.h"
#include "se_nv.h"

#define SE_TIME_UNIX_MIN  1704067200u  /* 2024-01-01 */
#define SE_TIME_UNIX_MAX  2145916800u  /* 2038-01-01 */

static uint8_t  s_have_floor;
static uint8_t  s_synced;
static uint32_t s_unix_base;
static uint32_t s_tick_base;
static uint8_t  s_boot_done;

static uint32_t se_time_floor_now(void)
{
    uint32_t elapsed_s;
    uint32_t now;

    if (s_have_floor == 0U) {
        return 0U;
    }

    elapsed_s = (HAL_GetTick() - s_tick_base) / 1000U;
    now = s_unix_base + elapsed_s;
    if (now < s_unix_base || now > SE_TIME_UNIX_MAX) {
        return SE_TIME_UNIX_MAX;
    }
    return now;
}

static void se_time_persist_floor(uint32_t unix_utc)
{
    (void)se_nv_set_time_floor(unix_utc);
}

void se_time_boot_restore(void)
{
    uint32_t floor = 0U;
    int present = 0;
    lt_ret_t ret;

    if (s_boot_done != 0U) {
        return;
    }
    s_boot_done = 1U;

    ret = se_nv_get_time_floor(&floor, &present);
    if ((ret == LT_OK) && (present != 0) && (floor >= SE_TIME_UNIX_MIN) &&
        (floor <= SE_TIME_UNIX_MAX)) {
        s_unix_base = floor;
        s_tick_base = HAL_GetTick();
        s_have_floor = 1U;
        /* Still unsynced until host PROVISION / ENCRYPT / DECRYPT <unix>. */
    }
}

int se_time_is_synced(void)
{
    return (s_synced != 0U) ? 1 : 0;
}

void se_time_clear_synced(void)
{
    if (s_have_floor != 0U) {
        uint32_t now = se_time_floor_now();

        se_time_persist_floor(now);
        s_unix_base = now;
        s_tick_base = HAL_GetTick();
    }
    s_synced = 0U;
}

int se_time_set_unix(uint32_t unix_utc)
{
    uint32_t floor;

    se_time_boot_restore();

    if (unix_utc < SE_TIME_UNIX_MIN || unix_utc > SE_TIME_UNIX_MAX) {
        return -1;
    }

    if (s_have_floor != 0U) {
        floor = se_time_floor_now();
        if (unix_utc < floor) {
            s_synced = 1U;
            return 1;
        }
    }

    s_unix_base = unix_utc;
    s_tick_base = HAL_GetTick();
    s_have_floor = 1U;
    s_synced = 1U;
    se_time_persist_floor(unix_utc);
    return 0;
}

uint32_t se_time_unix_now(void)
{
    if (s_synced == 0U) {
        return 0U;
    }
    return se_time_floor_now();
}

#ifndef SE_HOST_MODEL
/* Firmware-only: TIME_OVERRIDES in user_settings.h. Do not include that header
 * here — host compiles this file without it. libc gmtime is not linked. */
#define SE_TIME_YEAR0      1900
#define SE_TIME_EPOCH_YEAR 1970
#define SE_TIME_SECS_DAY   (24L * 60L * 60L)
#define SE_TIME_LEAPYEAR(y) (!((y) % 4) && (((y) % 100) || !((y) % 400)))
#define SE_TIME_YEARSIZE(y) (SE_TIME_LEAPYEAR(y) ? 366 : 365)

time_t XTIME(time_t *t)
{
    time_t now = (time_t)se_time_unix_now();
    if (t != NULL) {
        *t = now;
    }
    return now;
}

struct tm *XGMTIME(const time_t *timer, struct tm *tmp)
{
    static const int ytab[2][12] = {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };
    static struct tm s_gm;
    struct tm *out;
    time_t secs;
    unsigned long dayclock;
    unsigned long dayno;
    int year = SE_TIME_EPOCH_YEAR;

    if (timer == NULL) {
        return NULL;
    }
    out = (tmp != NULL) ? tmp : &s_gm;
    secs = *timer;
    dayclock = (unsigned long)secs % (unsigned long)SE_TIME_SECS_DAY;
    dayno = (unsigned long)secs / (unsigned long)SE_TIME_SECS_DAY;

    out->tm_sec = (int)(dayclock % 60U);
    out->tm_min = (int)((dayclock % 3600U) / 60U);
    out->tm_hour = (int)(dayclock / 3600U);
    out->tm_wday = (int)((dayno + 4U) % 7U);

    while (dayno >= (unsigned long)SE_TIME_YEARSIZE(year)) {
        dayno -= (unsigned long)SE_TIME_YEARSIZE(year);
        year++;
    }

    out->tm_year = year - SE_TIME_YEAR0;
    out->tm_yday = (int)dayno;
    out->tm_mon = 0;
    while (dayno >= (unsigned long)ytab[SE_TIME_LEAPYEAR(year)][out->tm_mon]) {
        dayno -= (unsigned long)ytab[SE_TIME_LEAPYEAR(year)][out->tm_mon];
        out->tm_mon++;
    }
    out->tm_mday = (int)++dayno;
    out->tm_isdst = 0;
    return out;
}
#endif /* !SE_HOST_MODEL */
