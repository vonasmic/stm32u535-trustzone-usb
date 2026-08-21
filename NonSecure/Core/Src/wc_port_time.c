/**
 * @file    wc_port_time.c
 * @brief   wolfSSL TIME_OVERRIDES: XTIME/XGMTIME via Secure RTC NSC
 *
 * Do not define wc_Time() here — asn.c already provides it and calls XTIME().
 */
#include <time.h>
#include <string.h>
#include "se_tls_nsc.h"

time_t XTIME(time_t *t)
{
    time_t now = (time_t)SECURE_GetUnixTime_nsc_call();
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
