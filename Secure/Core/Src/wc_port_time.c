/**
 * @file    wc_port_time.c
 * @brief   wolfSSL TIME_OVERRIDES — wall clock set via NSC from NonSecure
 *
 * Source of truth is a RAM unix base + HAL tick, with the floor also persisted
 * in MCU NV so reboot cannot roll a later timestamp backward.
 */
#include <time.h>
#include <string.h>
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
