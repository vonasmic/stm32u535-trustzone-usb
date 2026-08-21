/**
 * @file    wc_port_time.c
 * @brief   wolfSSL TIME_OVERRIDES — wall clock set via NSC from NonSecure
 *
 * Source of truth is a RAM unix base + HAL tick (no gmtime/RTC required).
 * RTC is updated best-effort only.
 */
#include <time.h>
#include <string.h>
#include "main.h"
#include "se_time.h"

extern RTC_HandleTypeDef hrtc;

#define SE_TIME_UNIX_MIN  1704067200u  /* 2024-01-01 */
#define SE_TIME_UNIX_MAX  2145916800u  /* 2038-01-01 */

static uint8_t  s_synced;
static uint32_t s_unix_base;
static uint32_t s_tick_base;

static int se_is_leap(int year)
{
    return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

/* Best-effort RTC write; wolfSSL does not depend on this. */
static void se_time_try_set_rtc(uint32_t unix_utc)
{
    uint32_t days;
    uint32_t rem;
    int year = 1970;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int dim;
    static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    RTC_TimeTypeDef sTime = {0};
    RTC_DateTypeDef sDate = {0};

    days = unix_utc / 86400u;
    rem  = unix_utc % 86400u;
    hour = (int)(rem / 3600u);
    rem %= 3600u;
    minute = (int)(rem / 60u);
    second = (int)(rem % 60u);

    while (1) {
        int diy = se_is_leap(year) ? 366 : 365;
        if (days < (uint32_t)diy) {
            break;
        }
        days -= (uint32_t)diy;
        year++;
        if (year > 2099) {
            return;
        }
    }

    month = 1;
    while (month <= 12) {
        dim = mdays[month - 1];
        if (month == 2 && se_is_leap(year)) {
            dim++;
        }
        if (days < (uint32_t)dim) {
            break;
        }
        days -= (uint32_t)dim;
        month++;
    }
    day = (int)days + 1;

    if (year < 2000 || year > 2099) {
        return;
    }

    sTime.Hours   = (uint8_t)hour;
    sTime.Minutes = (uint8_t)minute;
    sTime.Seconds = (uint8_t)second;
    sDate.Year    = (uint8_t)(year - 2000);
    sDate.Month   = (uint8_t)month;
    sDate.Date    = (uint8_t)day;
    sDate.WeekDay = RTC_WEEKDAY_MONDAY;
    (void)HAL_RTC_SetTime(&hrtc, &sTime, RTC_FORMAT_BIN);
    (void)HAL_RTC_SetDate(&hrtc, &sDate, RTC_FORMAT_BIN);
}

int se_time_is_synced(void)
{
    return (s_synced != 0U) ? 1 : 0;
}

void se_time_clear_synced(void)
{
    s_synced = 0U;
    s_unix_base = 0U;
    s_tick_base = 0U;
}

int se_time_set_unix(uint32_t unix_utc)
{
    if (unix_utc < SE_TIME_UNIX_MIN || unix_utc > SE_TIME_UNIX_MAX) {
        return -1;
    }

    s_unix_base = unix_utc;
    s_tick_base = HAL_GetTick();
    s_synced = 1U;
    se_time_try_set_rtc(unix_utc);
    return 0;
}

uint32_t se_time_unix_now(void)
{
    uint32_t elapsed_s;

    if (s_synced == 0U) {
        return 0U;
    }
    elapsed_s = (HAL_GetTick() - s_tick_base) / 1000U;
    return s_unix_base + elapsed_s;
}

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
    struct tm *g;

    if (timer == NULL) {
        return NULL;
    }
    g = gmtime(timer);
    if (g != NULL && tmp != NULL) {
        memcpy(tmp, g, sizeof(*tmp));
        return tmp;
    }
    return g;
}
