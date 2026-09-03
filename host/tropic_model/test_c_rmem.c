/**
 * @file    test_c_rmem.c
 * @brief   Group C: R-MEM device seal and slot map guards
 */
#include "test_harness.h"
#include "se_tropic.h"
#include "se_tropic_rmem.h"
#include "se_tropic_pin.h"
#include "sae_qkd.h"
#include "libtropic.h"
#include <string.h>

int main(void)
{
    lt_handle_t *h;
    uint8_t chunk_a[64];
    uint8_t chunk_b[64];
    uint8_t read_buf[128];
    uint16_t got = 0;
    lt_ret_t ret;
    uint32_t st;
    unsigned i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (host_crypto_init() != 0) {
        return 1;
    }

    printf("=== C: R-MEM ===\n");
    st = se_tropic_init_session();
    TEST_ASSERT_EQ(st, SE_TROPIC_OK, "init_session");
    h = se_tropic_handle();
    TEST_ASSERT(h != NULL, "handle");

    for (i = 0; i < sizeof(chunk_a); i++) {
        chunk_a[i] = (uint8_t)(0x10u + i);
        chunk_b[i] = (uint8_t)(0xA0u + i);
    }

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_QKD_SLOT_BASE, chunk_a, sizeof(chunk_a));
    TEST_ASSERT_EQ(ret, LT_OK, "erase_write slot 0");
    ret = se_tropic_read_and_decrypt_mcu_sealed_from_rmem(h, SE_TROPIC_QKD_SLOT_BASE, read_buf, sizeof(read_buf), &got);
    TEST_ASSERT_EQ(ret, LT_OK, "read slot 0");
    TEST_ASSERT_EQ(got, sizeof(chunk_a), "read len");
    TEST_ASSERT(memcmp(read_buf, chunk_a, sizeof(chunk_a)) == 0, "readback equal");

    {
        uint8_t raw[SE_TROPIC_RMEM_BLOB_MAX];
        uint16_t raw_len = 0;
        ret = lt_r_mem_data_read(h, SE_TROPIC_QKD_SLOT_BASE, raw, sizeof(raw), &raw_len);
        TEST_ASSERT_EQ(ret, LT_OK, "raw SPI/slot read");
        TEST_ASSERT(raw_len > sizeof(chunk_a), "ciphertext longer than plain");
        TEST_ASSERT(raw[0] == SE_TROPIC_RMEM_VER, "GCM version byte");
        TEST_ASSERT(memcmp(raw, chunk_a, sizeof(chunk_a)) != 0, "slot is not plaintext");
    }

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_QKD_SLOT_BASE, chunk_b, sizeof(chunk_b));
    TEST_ASSERT_EQ(ret, LT_OK, "overwrite via erase_write");
    ret = se_tropic_read_and_decrypt_mcu_sealed_from_rmem(h, SE_TROPIC_QKD_SLOT_BASE, read_buf, sizeof(read_buf), &got);
    TEST_ASSERT_EQ(ret, LT_OK, "read after overwrite");
    TEST_ASSERT(memcmp(read_buf, chunk_b, sizeof(chunk_b)) == 0, "overwrite content");

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, 1u, chunk_a, 32u);
    TEST_ASSERT_EQ(ret, LT_OK, "write slot 1");
    ret = se_tropic_qkd_store(h, SE_TROPIC_PIN_NVM_SLOT, chunk_a, 32u);
    TEST_ASSERT(ret == LT_PARAM_ERR, "refuse PIN NVM slot via qkd_store");
    ret = se_tropic_qkd_store(h, SE_TROPIC_MLKEM_SEED_SLOT, chunk_a, 32u);
    TEST_ASSERT(ret == LT_PARAM_ERR, "refuse ML-KEM seed slot via qkd_store");
    {
        uint16_t phys = 0xFFFFu;
        ret = se_tropic_get_phys_from_slot_index(0u, &phys);
        TEST_ASSERT_EQ(ret, LT_OK, "logical 0 maps");
        TEST_ASSERT_EQ(phys, SE_TROPIC_PAD_FIRST, "logical 0 is first pad");
    }

    ret = se_tropic_encrypt_and_write_mcu_sealed_to_rmem(h, SE_TROPIC_QKD_SLOT_LAST, chunk_a, 16u);
    TEST_ASSERT_EQ(ret, LT_OK, "write last QKD slot 509");

    ret = sae_rmem_probe_slot_max(h, 2u);
    TEST_ASSERT_EQ(ret, LT_OK, "full-size slot probe");

    se_tropic_deinit_session();
    host_crypto_deinit();
    printf("PASS C\n");
    return 0;
}
