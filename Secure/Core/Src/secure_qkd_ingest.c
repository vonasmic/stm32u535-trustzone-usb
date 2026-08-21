/**
 * @file    secure_qkd_ingest.c
 * @brief   Bounded JSON array-of-strings parser (validate + count, no store)
 */
#include "secure_qkd_ingest.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <string.h>

#define QKD_ASM_MAX 8192u

static uint8_t s_asm[QKD_ASM_MAX];
static uint32_t s_asm_len;

static void qkd_wipe(void)
{
    wc_ForceZero(s_asm, sizeof(s_asm));
    s_asm_len = 0U;
}

void secure_qkd_discard(void)
{
    qkd_wipe();
}

static int qkd_skip_ws(const uint8_t *buf, uint32_t len, uint32_t *pos)
{
    while (*pos < len) {
        uint8_t c = buf[*pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            (*pos)++;
            continue;
        }
        break;
    }
    return 0;
}

static int qkd_expect(const uint8_t *buf, uint32_t len, uint32_t *pos, uint8_t ch)
{
    if (*pos >= len || buf[*pos] != ch) {
        return -1;
    }
    (*pos)++;
    return 0;
}

static int qkd_parse_string(const uint8_t *buf, uint32_t len, uint32_t *pos)
{
    if (qkd_expect(buf, len, pos, '"') != 0) {
        return -1;
    }

    while (*pos < len) {
        uint8_t c = buf[*pos];
        if (c == '"') {
            (*pos)++;
            return 0;
        }
        if (c == '\\') {
            (*pos)++;
            if (*pos >= len) {
                return -1;
            }
            (*pos)++;
            continue;
        }
        if (c < 0x20U) {
            return -1;
        }
        (*pos)++;
    }
    return -1;
}

static int qkd_parse_finish(uint32_t *countOut)
{
    uint32_t pos = 0U;
    uint32_t count = 0U;

    if (countOut == NULL) {
        return SECURE_QKD_ERR;
    }

    if (s_asm_len == 0U) {
        *countOut = 0U;
        return SECURE_QKD_OK;
    }

    (void)qkd_skip_ws(s_asm, s_asm_len, &pos);
    if (qkd_expect(s_asm, s_asm_len, &pos, '[') != 0) {
        qkd_wipe();
        return SECURE_QKD_PARSE;
    }
    (void)qkd_skip_ws(s_asm, s_asm_len, &pos);

    if (pos < s_asm_len && s_asm[pos] == ']') {
        *countOut = 0U;
        qkd_wipe();
        return SECURE_QKD_OK;
    }

    for (;;) {
        if (qkd_parse_string(s_asm, s_asm_len, &pos) != 0) {
            qkd_wipe();
            return SECURE_QKD_PARSE;
        }
        count++;
        (void)qkd_skip_ws(s_asm, s_asm_len, &pos);

        if (pos < s_asm_len && s_asm[pos] == ']') {
            pos++;
            (void)qkd_skip_ws(s_asm, s_asm_len, &pos);
            if (pos != s_asm_len) {
                qkd_wipe();
                return SECURE_QKD_PARSE;
            }
            *countOut = count;
            qkd_wipe();
            return SECURE_QKD_OK;
        }
        if (qkd_expect(s_asm, s_asm_len, &pos, ',') != 0) {
            qkd_wipe();
            return SECURE_QKD_PARSE;
        }
        (void)qkd_skip_ws(s_asm, s_asm_len, &pos);
    }
}

uint32_t secure_qkd_ingest(const uint8_t *chunk, uint32_t len, uint32_t flags,
                           uint32_t *countOut)
{
    if (flags == SECURE_QKD_INGEST_DISCARD) {
        qkd_wipe();
        return SECURE_QKD_OK;
    }

    if (flags == SECURE_QKD_INGEST_FINISH) {
        return (uint32_t)qkd_parse_finish(countOut);
    }

    if (chunk == NULL && len > 0U) {
        return SECURE_QKD_ERR;
    }

    if (len > 0U) {
        if ((s_asm_len + len) > QKD_ASM_MAX) {
            qkd_wipe();
            return SECURE_QKD_OVERFLOW;
        }
        (void)memcpy(&s_asm[s_asm_len], chunk, len);
        s_asm_len += len;
    }

    return SECURE_QKD_OK;
}
