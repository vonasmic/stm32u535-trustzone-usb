/**
 * @file    secure_qkd_ingest.c
 * @brief   Streaming LV QKD ingest into TROPIC01 (kem_ct + pad images)
 *
 * Format (LE): [u8 version][u16 count]{ [u16 len][key bytes] } × count
 *
 * Item 0: raw ML-KEM-768 ciphertext -> se_tropic_kem_ct_write
 * Item 1: decrypt_half (1 byte, 0 or 1) -> se_tropic_qkd_arm_halves
 * Items 2..N: finished pad images -> se_tropic_qkd_store(logical = i-2)
 * Zero-length pads are skipped (positional); empty item 0 or 1 is a parse error.
 */
#include "secure_qkd_ingest.h"
#include "se_tropic.h"
#include "se_le.h"
#include <stddef.h>
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

typedef enum {
    QKD_PHASE_VERSION = 0,
    QKD_PHASE_COUNT,
    QKD_PHASE_LEN,
    QKD_PHASE_KEY,
    QKD_PHASE_DONE
} QkdPhase;

static QkdPhase s_phase;
static uint8_t s_hdr[2];
static uint8_t s_hdr_got;
static uint16_t s_count;
static uint16_t s_keys_done;
static uint16_t s_key_remain;
static uint16_t s_item_len;   /* length of current item when KEY started */
static uint16_t s_item_got;   /* bytes copied into s_item so far */
static uint32_t s_key_bytes;  /* payload only; framing not counted */
static uint8_t s_item0_stored;
static uint8_t s_item1_stored;
static uint8_t s_item[SE_TROPIC_KEM_CT_LEN];

static void qkd_wipe(void)
{
    s_phase = QKD_PHASE_VERSION;
    s_hdr[0] = 0U;
    s_hdr[1] = 0U;
    s_hdr_got = 0U;
    s_count = 0U;
    s_keys_done = 0U;
    s_key_remain = 0U;
    s_item_len = 0U;
    s_item_got = 0U;
    s_key_bytes = 0U;
    s_item0_stored = 0U;
    s_item1_stored = 0U;
    wc_ForceZero(s_item, sizeof(s_item));
}

void secure_qkd_discard(void)
{
    qkd_wipe();
}

/**
 * Commit the item at index s_keys_done (0 = kem_ct, 1 = decrypt_half, else pad).
 * Zero-length pads are a no-op. Caller increments s_keys_done after success.
 */
static uint32_t qkd_commit_item(uint16_t item_len)
{
    lt_handle_t *h;
    lt_ret_t ret;

    if (s_keys_done == 0U) {
        if (item_len != SE_TROPIC_KEM_CT_LEN) {
            qkd_wipe();
            return SECURE_QKD_PARSE;
        }
        if (se_tropic_init_session() != SE_TROPIC_OK) {
            qkd_wipe();
            return SECURE_QKD_STORE;
        }
        h = se_tropic_handle();
        if (h == NULL) {
            qkd_wipe();
            return SECURE_QKD_STORE;
        }
        ret = se_tropic_kem_ct_write(h, s_item);
        wc_ForceZero(s_item, sizeof(s_item));
        if (ret != LT_OK) {
            qkd_wipe();
            return SECURE_QKD_STORE;
        }
        s_item0_stored = 1U;
        return SECURE_QKD_OK;
    }

    if (s_keys_done == 1U) {
        if ((item_len != 1U) || (s_item[0] > 1U)) {
            qkd_wipe();
            return SECURE_QKD_PARSE;
        }
        if (se_tropic_init_session() != SE_TROPIC_OK) {
            qkd_wipe();
            return SECURE_QKD_STORE;
        }
        h = se_tropic_handle();
        if (h == NULL) {
            qkd_wipe();
            return SECURE_QKD_STORE;
        }
        ret = se_tropic_qkd_arm_halves(h, s_item[0]);
        wc_ForceZero(s_item, sizeof(s_item));
        if (ret != LT_OK) {
            qkd_wipe();
            return SECURE_QKD_STORE;
        }
        s_item1_stored = 1U;
        return SECURE_QKD_OK;
    }

    if (item_len == 0U) {
        return SECURE_QKD_OK;
    }

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        qkd_wipe();
        return SECURE_QKD_STORE;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        qkd_wipe();
        return SECURE_QKD_STORE;
    }
    ret = se_tropic_qkd_store(h, (uint16_t)(s_keys_done - 2U), s_item, item_len);
    wc_ForceZero(s_item, sizeof(s_item));
    if (ret != LT_OK) {
        qkd_wipe();
        return SECURE_QKD_STORE;
    }
    return SECURE_QKD_OK;
}

/** Advance past a completed item; may transition to DONE or next LEN. */
static uint32_t qkd_item_done(uint16_t item_len)
{
    uint32_t st;

    st = qkd_commit_item(item_len);
    if (st != SECURE_QKD_OK) {
        return st;
    }

    s_keys_done++;
    s_item_got = 0U;
    s_item_len = 0U;
    if (s_keys_done == s_count) {
        s_phase = QKD_PHASE_DONE;
    } else {
        s_phase = QKD_PHASE_LEN;
        s_hdr_got = 0U;
    }
    return SECURE_QKD_OK;
}

static uint32_t qkd_validate_len(uint16_t item_len)
{
    if (s_keys_done == 0U) {
        if (item_len != SE_TROPIC_KEM_CT_LEN) {
            return SECURE_QKD_PARSE;
        }
        return SECURE_QKD_OK;
    }
    if (s_keys_done == 1U) {
        if (item_len != 1U) {
            return SECURE_QKD_PARSE;
        }
        return SECURE_QKD_OK;
    }

    if (item_len == 0U) {
        return SECURE_QKD_OK;
    }
    if ((item_len < SE_TROPIC_RMEM_OVERHEAD) || (item_len > SE_TROPIC_RMEM_BLOB_MAX)) {
        return SECURE_QKD_PARSE;
    }
    return SECURE_QKD_OK;
}

static uint32_t qkd_feed(const uint8_t *chunk, uint32_t len)
{
    uint32_t off = 0U;

    while (off < len) {
        if (s_phase == QKD_PHASE_DONE) {
            qkd_wipe();
            return SECURE_QKD_PARSE;
        }

        if (s_phase == QKD_PHASE_VERSION) {
            /* Gate on version before reading count: an unknown layout parsed as
             * v1 would put every later field at the wrong offset. */
            if (chunk[off++] != (uint8_t)SECURE_LV_DOWNLINK_VERSION) {
                qkd_wipe();
                return SECURE_QKD_WRONG_VERSION;
            }
            s_phase = QKD_PHASE_COUNT;
            s_hdr_got = 0U;
            continue;
        }

        if (s_phase == QKD_PHASE_KEY) {
            uint32_t take = len - off;
            uint32_t st;

            if (take > (uint32_t)s_key_remain) {
                take = (uint32_t)s_key_remain;
            }

            (void)memcpy(s_item + s_item_got, chunk + off, take);
            off += take;
            s_item_got = (uint16_t)(s_item_got + (uint16_t)take);
            s_key_bytes += take;
            s_key_remain = (uint16_t)(s_key_remain - (uint16_t)take);

            if (s_key_remain == 0U) {
                st = qkd_item_done(s_item_len);
                if (st != SECURE_QKD_OK) {
                    return st;
                }
            }
            continue;
        }

        /* COUNT or LEN: accumulate 2-byte LE header */
        s_hdr[s_hdr_got++] = chunk[off++];

        if (s_hdr_got < 2U) {
            continue;
        }

        if (s_phase == QKD_PHASE_COUNT) {
            s_count = se_u16le(s_hdr);
            s_keys_done = 0U;
            if (s_count == 0U) {
                /* Empty list: DONE but item 0 never stored; FINISH will PARSE. */
                s_phase = QKD_PHASE_DONE;
            } else {
                s_phase = QKD_PHASE_LEN;
                s_hdr_got = 0U;
            }
        } else {
            uint32_t st;

            s_key_remain = se_u16le(s_hdr);
            s_hdr_got = 0U;
            st = qkd_validate_len(s_key_remain);
            if (st != SECURE_QKD_OK) {
                qkd_wipe();
                return st;
            }
            if ((s_key_bytes + (uint32_t)s_key_remain) > SECURE_QKD_MAX_BYTES) {
                qkd_wipe();
                return SECURE_QKD_OVERFLOW;
            }
            s_item_len = s_key_remain;
            s_item_got = 0U;
            if (s_key_remain == 0U) {
                st = qkd_item_done(0U);
                if (st != SECURE_QKD_OK) {
                    return st;
                }
            } else {
                s_phase = QKD_PHASE_KEY;
            }
        }
    }

    return SECURE_QKD_OK;
}

static uint32_t qkd_finish(uint32_t *countOut)
{
    uint32_t count;

    if (countOut == NULL) {
        return SECURE_QKD_ERR;
    }

    if ((s_phase != QKD_PHASE_DONE) || (s_item0_stored == 0U) || (s_item1_stored == 0U)) {
        qkd_wipe();
        return SECURE_QKD_PARSE;
    }

    count = (uint32_t)s_count;
    qkd_wipe();
    *countOut = count;
    return SECURE_QKD_OK;
}

uint32_t secure_qkd_ingest(const uint8_t *chunk, uint32_t len, uint32_t flags,
                           uint32_t *countOut)
{
    if (flags == SECURE_QKD_INGEST_DISCARD) {
        qkd_wipe();
        return SECURE_QKD_OK;
    }

    if (flags == SECURE_QKD_INGEST_FINISH) {
        return qkd_finish(countOut);
    }

    if (chunk == NULL && len > 0U) {
        return SECURE_QKD_ERR;
    }

    if (len == 0U) {
        return SECURE_QKD_OK;
    }

    return qkd_feed(chunk, len);
}
