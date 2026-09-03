/**
 * @file    se_cert_spki.c
 * @brief   Walk an X.509 Certificate DER to the subjectPublicKey BIT STRING
 */
#include "se_cert_spki.h"
#include <stddef.h>

static int der_read_len(const uint8_t *buf, uint32_t len, uint32_t *off, uint32_t *out_len)
{
    uint8_t b;
    uint32_t n;
    uint32_t v;

    if ((off == NULL) || (out_len == NULL) || (*off >= len)) {
        return -1;
    }
    b = buf[(*off)++];
    if ((b & 0x80u) == 0U) {
        *out_len = (uint32_t)b;
        return 0;
    }
    n = (uint32_t)(b & 0x7fu);
    if ((n == 0U) || (n > 4U) || ((*off + n) > len)) {
        return -1;
    }
    v = 0U;
    while (n > 0U) {
        v = (v << 8) | (uint32_t)buf[(*off)++];
        n--;
    }
    *out_len = v;
    return 0;
}

static int der_enter(const uint8_t *buf, uint32_t len, uint32_t *off, uint8_t tag,
                     uint32_t *body_end)
{
    uint32_t body_len;

    if ((off == NULL) || (body_end == NULL) || (*off >= len) || (buf[*off] != tag)) {
        return -1;
    }
    (*off)++;
    if (der_read_len(buf, len, off, &body_len) != 0) {
        return -1;
    }
    if ((*off + body_len) > len) {
        return -1;
    }
    *body_end = *off + body_len;
    return 0;
}

static int der_skip(const uint8_t *buf, uint32_t limit, uint32_t *off)
{
    uint32_t inner;

    if ((off == NULL) || (*off >= limit)) {
        return -1;
    }
    (*off)++;
    if (der_read_len(buf, limit, off, &inner) != 0) {
        return -1;
    }
    if ((*off + inner) > limit) {
        return -1;
    }
    *off += inner;
    return 0;
}

int se_cert_spki_raw(const uint8_t *der, uint32_t der_len, const uint8_t **out, uint32_t *out_len)
{
    uint32_t off = 0U;
    uint32_t cert_end;
    uint32_t tbs_end;
    uint32_t spki_end;
    uint32_t bit_end;
    uint32_t i;

    if ((der == NULL) || (out == NULL) || (out_len == NULL) || (der_len < 16U)) {
        return -1;
    }

    if (der_enter(der, der_len, &off, 0x30u, &cert_end) != 0) {
        return -1;
    }
    if (der_enter(der, cert_end, &off, 0x30u, &tbs_end) != 0) {
        return -1;
    }
    if ((off < tbs_end) && (der[off] == 0xa0u)) {
        if (der_skip(der, tbs_end, &off) != 0) {
            return -1;
        }
    }
    /* serial, signature, issuer, validity, subject */
    for (i = 0U; i < 5U; i++) {
        if (der_skip(der, tbs_end, &off) != 0) {
            return -1;
        }
    }
    if (der_enter(der, tbs_end, &off, 0x30u, &spki_end) != 0) {
        return -1;
    }
    if (der_skip(der, spki_end, &off) != 0) {
        return -1;
    }
    if (der_enter(der, spki_end, &off, 0x03u, &bit_end) != 0) {
        return -1;
    }
    if (off >= bit_end) {
        return -1;
    }
    off++; /* unused-bits count */
    if (off > bit_end) {
        return -1;
    }
    *out = der + off;
    *out_len = bit_end - off;
    return (*out_len > 0U) ? 0 : -1;
}
