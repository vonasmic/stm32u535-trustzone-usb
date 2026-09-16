/**
 * @file    test_j_peers.c
 * @brief   Group J: PEER NV add/remove/list and provision uplink item count
 */
#include "test_harness.h"
#include "host_fw_mlkem.h"
#include "libtropic.h"
#include "libtropic_user_config.h"
#include "se_creds.h"
#include "se_le.h"
#include "se_nv.h"
#include "se_tropic.h"
#include "se_tropic_session.h"
#include "secure_lv.h"
#include <string.h>

#define HASH_A_FIRST 0xA1u
#define HASH_B_FIRST 0xB2u

typedef struct {
    uint8_t buf[4096];
    uint32_t off;
} uplink_cap_t;

static int cap_write(const uint8_t *data, uint32_t len, void *ctx)
{
    uplink_cap_t *cap = (uplink_cap_t *)ctx;

    if ((cap->off + len) > sizeof(cap->buf)) {
        return -1;
    }
    (void)memcpy(cap->buf + cap->off, data, len);
    cap->off += len;
    return 0;
}

static void fill_hash(uint8_t hash[SE_NV_PEER_HASH_LEN], uint8_t tag)
{
    unsigned int i;

    for (i = 0U; i < SE_NV_PEER_HASH_LEN; i++) {
        hash[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static const uint8_t k_dummy_cert[] = {
    0x30, 0x18, 0x30, 0x16, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
    0x30, 0x09, 0x30, 0x00, 0x03, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd
};

static uint16_t uplink_count(void)
{
    uplink_cap_t cap;
    uint8_t exporter[SE_TROPIC_EXPORTER_LEN];
    unsigned int i;

    (void)memset(&cap, 0, sizeof(cap));
    for (i = 0U; i < sizeof(exporter); i++) {
        exporter[i] = (uint8_t)(0xE0u + (uint8_t)i);
    }
    if (se_tropic_session_uplink(exporter, cap_write, &cap) != 0) {
        return 0xFFFFu;
    }
    if (cap.off < 3U) {
        return 0xFFFFu;
    }
    return se_u16le(cap.buf + 1);
}

int main(void)
{
    uint8_t hash_a[SE_NV_PEER_HASH_LEN];
    uint8_t hash_b[SE_NV_PEER_HASH_LEN];
    uint8_t name[SE_NV_PEER_NAME_MAX];
    uint8_t got_hash[SE_NV_PEER_HASH_LEN];
    uint8_t nlen;
    uint8_t count;
    uint32_t floor;
    int present;
    lt_ret_t ret;
    uint32_t st;
    unsigned int i;
    const uint8_t alice[] = "Alice";
    const uint8_t bob[] = "Bob";
    uint16_t items;
    uint16_t cursor = 0xFFFFu;
    uint8_t fill_id[SE_NV_FILL_ID_LEN];

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== J: peers ===\n");
    fill_hash(hash_a, HASH_A_FIRST);
    fill_hash(hash_b, HASH_B_FIRST);

    ret = se_nv_peer_count(&count);
    TEST_ASSERT_EQ(ret, LT_OK, "count empty page");
    TEST_ASSERT_EQ(count, 0U, "empty count");

    ret = se_nv_peer_add(alice, 5U, hash_a);
    TEST_ASSERT_EQ(ret, LT_OK, "add Alice");
    ret = se_nv_peer_add(alice, 5U, hash_b);
    TEST_ASSERT_EQ(ret, SE_NV_PEER_EXISTS, "dup nickname");
    ret = se_nv_peer_count(&count);
    TEST_ASSERT_EQ(ret, LT_OK, "count after Alice load");
    TEST_ASSERT_EQ(count, 1U, "count after Alice");
    nlen = SE_NV_PEER_NAME_MAX;
    ret = se_nv_peer_get(0U, name, &nlen, got_hash);
    TEST_ASSERT_EQ(ret, LT_OK, "get Alice");
    TEST_ASSERT_EQ(nlen, 5U, "Alice name_len");
    TEST_ASSERT(memcmp(name, alice, 5U) == 0, "Alice name");
    TEST_ASSERT(memcmp(got_hash, hash_a, SE_NV_PEER_HASH_LEN) == 0, "Alice hash");

    ret = se_nv_peer_add(bob, 3U, hash_a);
    TEST_ASSERT_EQ(ret, LT_OK, "same hash other name");
    ret = se_nv_peer_remove(alice, 5U);
    TEST_ASSERT_EQ(ret, LT_OK, "remove Alice");
    ret = se_nv_peer_count(&count);
    TEST_ASSERT_EQ(ret, LT_OK, "count after remove Alice load");
    TEST_ASSERT_EQ(count, 1U, "count after remove Alice");
    nlen = SE_NV_PEER_NAME_MAX;
    ret = se_nv_peer_get(0U, name, &nlen, got_hash);
    TEST_ASSERT_EQ(ret, LT_OK, "get compacted Bob");
    TEST_ASSERT_EQ(nlen, 3U, "Bob compacted to slot 0");
    TEST_ASSERT(memcmp(name, bob, 3U) == 0, "Bob name");
    ret = se_nv_peer_remove(bob, 3U);
    TEST_ASSERT_EQ(ret, LT_OK, "remove Bob");
    ret = se_nv_peer_count(&count);
    TEST_ASSERT_EQ(ret, LT_OK, "count after remove Bob");
    TEST_ASSERT_EQ(count, 0U, "empty after remove");
    ret = se_nv_peer_remove(bob, 3U);
    TEST_ASSERT_EQ(ret, SE_NV_PEER_NOT_FOUND, "remove missing");

    for (i = 0U; i < SE_NV_PEER_MAX; i++) {
        uint8_t nm[2];

        nm[0] = (uint8_t)('A' + (uint8_t)i);
        nm[1] = (uint8_t)('0' + (uint8_t)i);
        ret = se_nv_peer_add(nm, 2U, hash_b);
        TEST_ASSERT_EQ(ret, LT_OK, "add slot");
    }
    ret = se_nv_peer_add(alice, 5U, hash_a);
    TEST_ASSERT_EQ(ret, SE_NV_PEER_FULL, "list full");
    for (i = 0U; i < SE_NV_PEER_MAX; i++) {
        uint8_t nm[2];

        nm[0] = (uint8_t)('A' + (uint8_t)i);
        nm[1] = (uint8_t)('0' + (uint8_t)i);
        ret = se_nv_peer_remove(nm, 2U);
        TEST_ASSERT_EQ(ret, LT_OK, "remove slot");
    }

    ret = se_nv_set_time_floor(1700000000U);
    TEST_ASSERT_EQ(ret, LT_OK, "set time floor");
    ret = se_nv_get_time_floor(&floor, &present);
    TEST_ASSERT_EQ(ret, LT_OK, "load time");
    TEST_ASSERT_EQ(present, 1, "time present");
    TEST_ASSERT_EQ(floor, 1700000000U, "time value");
    ret = se_nv_peer_count(&count);
    TEST_ASSERT_EQ(ret, LT_OK, "count after time");
    TEST_ASSERT_EQ(count, 0U, "time-only has empty peers");
    ret = se_nv_peer_add(alice, 5U, hash_a);
    TEST_ASSERT_EQ(ret, LT_OK, "add after time");
    ret = se_nv_get_time_floor(&floor, &present);
    TEST_ASSERT_EQ(ret, LT_OK, "time after peer store");
    TEST_ASSERT_EQ(present, 1, "time kept on peer store");
    TEST_ASSERT_EQ(floor, 1700000000U, "time value kept");
    ret = se_nv_peer_remove(alice, 5U);
    TEST_ASSERT_EQ(ret, LT_OK, "cleanup Alice");

    (void)memset(fill_id, 0x11, sizeof(fill_id));
    TEST_ASSERT_EQ(se_nv_commit_fill(fill_id), LT_OK, "commit fill");
    TEST_ASSERT_EQ(se_nv_arm_otp_cursors(0U, 253U), LT_OK, "arm otp");
    TEST_ASSERT(se_nv_has_device_sk() == 0, "cursor path needs no device SK");
    TEST_ASSERT_EQ(se_nv_get_cursor(SE_NV_OTP_ENCRYPT, &cursor), LT_OK, "get cursor");
    TEST_ASSERT_EQ(cursor, 0U, "encrypt cursor at base");

    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    st = se_tropic_keygen(NULL, 0U);
    if (st == SE_TROPIC_SLOT_OCC) {
        TEST_ASSERT_EQ(lt_ecc_key_erase(se_tropic_handle(), SE_TROPIC_ECC_SLOT), LT_OK,
                       "erase ecc");
        st = se_tropic_keygen(NULL, 0U);
    }
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "keygen");
    TEST_ASSERT_EQ(se_creds_set_device_cert(k_dummy_cert, (uint16_t)sizeof(k_dummy_cert)), LT_OK,
                   "dummy device cert");
    (void)memset(host_fw_mlkem_pk, 0x5A, sizeof(host_fw_mlkem_pk));
    host_fw_mlkem_pk_len = SE_TROPIC_MLKEM_PK_LEN;

    items = uplink_count();
    TEST_ASSERT_EQ(items, (uint16_t)SECURE_LV_UPLINK_FIXED_ITEMS, "uplink 7 items empty peers");
    ret = se_nv_peer_add(alice, 5U, hash_a);
    TEST_ASSERT_EQ(ret, LT_OK, "add Alice for uplink");
    items = uplink_count();
    TEST_ASSERT_EQ(items, (uint16_t)(SECURE_LV_UPLINK_FIXED_ITEMS + 2u),
                   "uplink 9 items one peer");
    ret = se_nv_peer_add(bob, 3U, hash_b);
    TEST_ASSERT_EQ(ret, LT_OK, "add Bob for uplink");
    items = uplink_count();
    TEST_ASSERT_EQ(items, (uint16_t)(SECURE_LV_UPLINK_FIXED_ITEMS + 4u),
                   "uplink 11 items two peers");

    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS J\n");
    return 0;
}
