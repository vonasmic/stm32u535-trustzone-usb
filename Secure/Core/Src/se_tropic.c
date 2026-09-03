/**
 * @file    se_tropic.c
 * @brief   TROPIC01 L3 session and host-command helpers (HAL-agnostic)
 */
#include "se_tropic.h"
#include "se_tropic_port.h"
#include "se_tropic_pin.h"
#include "libtropic_user_config.h"
#include "libtropic.h"
#include "se_nv.h"
#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

#define TROPIC_PING_MSG     "hello"
#define TROPIC_PING_MSG_LEN 5u

/* libtropic CAL; linked via se_libtropic_sources.inc / host tropic lib. */
lt_ret_t lt_X25519_scalarmult(const uint8_t *sk, uint8_t *pk);

static lt_handle_t s_lt;
static uint8_t s_session_active;
static uint8_t s_pkey_valid;
static uint8_t s_pkey_slot;
static uint8_t s_pkey_priv[TR01_SHIPRIV_LEN];
static uint8_t s_pkey_pub[TR01_SHIPUB_LEN];

static int pairing_slot_ok(uint8_t slot)
{
    return ((slot >= (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_1) &&
            (slot <= (uint8_t)TR01_PAIRING_KEY_SLOT_INDEX_3))
               ? 1
               : 0;
}

static void pairing_creds_load(void)
{
    uint8_t slot;
    uint8_t priv[TR01_SHIPRIV_LEN];
    uint8_t pub[TR01_SHIPUB_LEN];
    lt_ret_t ret;

    if (s_pkey_valid != 0U) {
        return;
    }
    ret = se_nv_get_pairing(&slot, priv, pub);
    if (ret != LT_OK) {
        wc_ForceZero(priv, sizeof(priv));
        return;
    }
    s_pkey_slot = slot;
    (void)memcpy(s_pkey_priv, priv, sizeof(s_pkey_priv));
    (void)memcpy(s_pkey_pub, pub, sizeof(s_pkey_pub));
    s_pkey_valid = 1U;
    wc_ForceZero(priv, sizeof(priv));
}

static const uint8_t *session_priv(void)
{
    pairing_creds_load();
    return (s_pkey_valid != 0U) ? s_pkey_priv : SE_TROPIC_SH0_PRIV;
}

static const uint8_t *session_pub(void)
{
    pairing_creds_load();
    return (s_pkey_valid != 0U) ? s_pkey_pub : SE_TROPIC_SH0_PUB;
}

static lt_pkey_index_t session_slot(void)
{
    pairing_creds_load();
    if (s_pkey_valid != 0U) {
        return (lt_pkey_index_t)s_pkey_slot;
    }
    return TR01_PAIRING_KEY_SLOT_INDEX_0;
}

void se_tropic_hw_init(void)
{
    se_tropic_port_hw_init();
}

void se_tropic_log_hex(const char *label, const uint8_t *data, uint32_t len)
{
    char line[96];
    uint32_t i;
    uint32_t pos = 0U;

    if (label != NULL) {
        se_tropic_log("%s", label);
    }
    if (data == NULL) {
        return;
    }
    for (i = 0U; i < len; i++) {
        if (pos + 3U >= sizeof(line)) {
            line[pos] = '\0';
            se_tropic_log("%s", line);
            pos = 0U;
        }
        pos += (uint32_t)snprintf(line + pos, sizeof(line) - pos, "%02x", data[i]);
    }
    if (pos > 0U) {
        line[pos] = '\0';
        se_tropic_log("%s", line);
    }
}

uint32_t se_tropic_init_session(void)
{
    lt_ret_t ret;

    if (s_session_active != 0U) {
        return SE_TROPIC_OK;
    }

    se_tropic_port_hw_init();
    (void)memset(&s_lt, 0, sizeof(s_lt));
    if (se_tropic_port_attach(&s_lt) != SE_TROPIC_OK) {
        se_tropic_log("TROPIC port attach fail");
        return SE_TROPIC_ERR;
    }

    ret = lt_init(&s_lt);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC init fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    ret = lt_reboot(&s_lt, TR01_REBOOT);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC reboot fail %s", lt_ret_verbose(ret));
        (void)lt_deinit(&s_lt);
        return SE_TROPIC_ERR;
    }

    ret = lt_verify_chip_and_start_secure_session(&s_lt, session_priv(), session_pub(),
                                                  session_slot());
    if (ret != LT_OK) {
        se_tropic_log("TROPIC session fail %s", lt_ret_verbose(ret));
        (void)lt_deinit(&s_lt);
        return SE_TROPIC_ERR;
    }

    s_session_active = 1U;
    se_tropic_log("TROPIC session ok (pairing slot %u)", (unsigned)session_slot());
    return SE_TROPIC_OK;
}

void se_tropic_deinit_session(void)
{
    if (s_session_active != 0U) {
        (void)lt_session_abort(&s_lt);
        (void)lt_deinit(&s_lt);
        s_session_active = 0U;
    }
}

uint32_t se_tropic_is_session_active(void)
{
    return s_session_active;
}

uint32_t se_tropic_ping(void)
{
    uint8_t recv[TROPIC_PING_MSG_LEN];
    lt_ret_t ret;

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }

    ret = lt_ping(&s_lt, (const uint8_t *)TROPIC_PING_MSG, recv, TROPIC_PING_MSG_LEN);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC ping fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }
    if (memcmp(recv, TROPIC_PING_MSG, TROPIC_PING_MSG_LEN) != 0) {
        se_tropic_log("TROPIC ping mismatch");
        return SE_TROPIC_ERR;
    }
    se_tropic_log("TROPIC ping ok");
    return SE_TROPIC_OK;
}

static void se_tropic_info_cert_store(void)
{
    static uint8_t s_cert_bufs[LT_NUM_CERTIFICATES][TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE];
    struct lt_cert_store_t store;
    lt_ret_t ret;
    uint32_t i;

    store.certs[0] = s_cert_bufs[0];
    store.certs[1] = s_cert_bufs[1];
    store.certs[2] = s_cert_bufs[2];
    store.certs[3] = s_cert_bufs[3];
    for (i = 0U; i < LT_NUM_CERTIFICATES; i++) {
        store.buf_len[i] = TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE;
    }

    ret = lt_get_info_cert_store(&s_lt, &store);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC cert store fail %s", lt_ret_verbose(ret));
        return;
    }

    for (i = 0U; i < LT_NUM_CERTIFICATES; i++) {
        se_tropic_log("TROPIC cert[%lu] len=%u", (unsigned long)i, store.cert_len[i]);
    }
}

uint32_t se_tropic_info(void)
{
    struct lt_chip_id_t chip_id;
    uint8_t riscv_ver[TR01_L2_GET_INFO_RISCV_FW_SIZE];
    uint8_t spect_ver[TR01_L2_GET_INFO_SPECT_FW_SIZE];
    lt_ret_t ret;

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }

    ret = lt_get_info_chip_id(&s_lt, &chip_id);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC chip_id fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }
    se_tropic_port_print_chip_id(&chip_id);

    ret = lt_get_info_riscv_fw_ver(&s_lt, riscv_ver);
    if (ret == LT_OK) {
        se_tropic_log("TROPIC riscv fw %u.%u.%u", riscv_ver[0], riscv_ver[1], riscv_ver[2]);
    }

    ret = lt_get_info_spect_fw_ver(&s_lt, spect_ver);
    if (ret == LT_OK) {
        se_tropic_log("TROPIC spect fw %u.%u.%u", spect_ver[0], spect_ver[1], spect_ver[2]);
    }

    se_tropic_info_cert_store();
    return SE_TROPIC_OK;
}

uint32_t se_tropic_pub_read(uint8_t *out_xy64)
{
    uint8_t key[64];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    lt_ret_t ret;

    if (out_xy64 == NULL) {
        return SE_TROPIC_ERR;
    }

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }

    ret = lt_ecc_key_read(&s_lt, SE_TROPIC_ECC_SLOT, key, sizeof(key), &curve, &origin);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC pub read fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    (void)memcpy(out_xy64, key, 64U);
    se_tropic_log("TROPIC P-256 pub:");
    se_tropic_log_hex(NULL, out_xy64, 64U);
    return SE_TROPIC_OK;
}

static uint32_t se_tropic_slot_occupied(void)
{
    uint8_t key[64];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    lt_ret_t ret;

    ret = lt_ecc_key_read(&s_lt, SE_TROPIC_ECC_SLOT, key, sizeof(key), &curve, &origin);
    if (ret == LT_OK) {
        return 1U;
    }
    return 0U;
}

uint32_t se_tropic_keygen(const uint8_t *pin, uint8_t pin_len)
{
    lt_handle_t *h;
    uint8_t final_key[32];
    lt_ret_t ret;

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }

    if (se_tropic_slot_occupied() != 0U) {
        if ((pin == NULL) || (pin_len < SE_TROPIC_PIN_SIZE_MIN) ||
            (pin_len > SE_TROPIC_PIN_SIZE_MAX)) {
            se_tropic_log("TROPIC slot occupied; send KEYGEN <pin> to replace");
            return SE_TROPIC_SLOT_OCC;
        }
        h = se_tropic_handle();
        if (h == NULL) {
            return SE_TROPIC_ERR;
        }
        ret = se_tropic_pin_check(h, pin, pin_len, NULL, 0U, final_key);
        wc_ForceZero(final_key, sizeof(final_key));
        if (ret != LT_OK) {
            se_tropic_log("TROPIC KEYGEN PIN fail %s", lt_ret_verbose(ret));
            return SE_TROPIC_ERR;
        }
        ret = lt_ecc_key_erase(&s_lt, SE_TROPIC_ECC_SLOT);
        if (ret != LT_OK) {
            se_tropic_log("TROPIC KEYGEN erase fail %s", lt_ret_verbose(ret));
            return SE_TROPIC_ERR;
        }
        ret = lt_ecc_key_generate(&s_lt, SE_TROPIC_ECC_SLOT, TR01_CURVE_P256);
        if (ret != LT_OK) {
            se_tropic_log("TROPIC keygen fail %s", lt_ret_verbose(ret));
            return SE_TROPIC_ERR;
        }
        se_tropic_log("TROPIC P-256 key replaced slot 0");
        return SE_TROPIC_OK;
    }

    ret = lt_ecc_key_generate(&s_lt, SE_TROPIC_ECC_SLOT, TR01_CURVE_P256);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC keygen fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    se_tropic_log("TROPIC P-256 key generated slot 0");
    return SE_TROPIC_OK;
}

uint32_t se_tropic_sign_hash(const uint8_t hash32[32], uint8_t rs64[64])
{
    lt_ret_t ret;

    if (hash32 == NULL || rs64 == NULL) {
        return SE_TROPIC_ERR;
    }

    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }

    ret = lt_ecc_ecdsa_sign(&s_lt, SE_TROPIC_ECC_SLOT, hash32, 32U, rs64);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC sign fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    se_tropic_log("TROPIC sig:");
    se_tropic_log_hex(NULL, rs64, 64U);
    return SE_TROPIC_OK;
}

uint32_t se_tropic_session_sign(const uint8_t hash32[32], uint8_t rs64[64])
{
    return se_tropic_sign_hash(hash32, rs64);
}

uint32_t se_create_pairing_key_to_tropic(uint8_t slot)
{
    uint8_t priv[TR01_SHIPRIV_LEN];
    uint8_t pub[TR01_SHIPUB_LEN];
    uint8_t read_pub[TR01_SHIPUB_LEN];
    lt_ret_t ret;

    if (pairing_slot_ok(slot) == 0) {
        se_tropic_log("TROPIC PAIRING slot must be 1-3 (0 is factory SH0)");
        return SE_TROPIC_ERR;
    }
    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }

    ret = lt_pairing_key_read(&s_lt, read_pub, (lt_pkey_index_t)slot);
    if (ret == LT_OK) {
        se_tropic_log("TROPIC PAIRING refused: pairing slot %u occupied", (unsigned)slot);
        return SE_TROPIC_SLOT_OCC;
    }
    if (ret != LT_L3_SLOT_EMPTY) {
        se_tropic_log("TROPIC PAIRING slot %u not empty (%s)", (unsigned)slot, lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    ret = se_tropic_port_nv_random(priv, (uint16_t)sizeof(priv));
    if (ret != LT_OK) {
        se_tropic_log("TROPIC PAIRING rng fail %s", lt_ret_verbose(ret));
        wc_ForceZero(priv, sizeof(priv));
        return SE_TROPIC_ERR;
    }
    ret = lt_X25519_scalarmult(priv, pub);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC PAIRING x25519 fail %s", lt_ret_verbose(ret));
        wc_ForceZero(priv, sizeof(priv));
        return SE_TROPIC_ERR;
    }

    ret = lt_pairing_key_write(&s_lt, pub, (lt_pkey_index_t)slot);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC PAIRING write fail %s", lt_ret_verbose(ret));
        wc_ForceZero(priv, sizeof(priv));
        return SE_TROPIC_ERR;
    }

    ret = se_nv_set_pairing(slot, priv, pub);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC PAIRING persist fail %s", lt_ret_verbose(ret));
        wc_ForceZero(priv, sizeof(priv));
        return SE_TROPIC_ERR;
    }

    s_pkey_slot = slot;
    (void)memcpy(s_pkey_priv, priv, sizeof(s_pkey_priv));
    (void)memcpy(s_pkey_pub, pub, sizeof(s_pkey_pub));
    s_pkey_valid = 1U;
    wc_ForceZero(priv, sizeof(priv));

    ret = lt_pairing_key_invalidate(&s_lt, TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (ret != LT_OK) {
        se_tropic_log("TROPIC PAIRING SH0 invalidate fail %s", lt_ret_verbose(ret));
        return SE_TROPIC_ERR;
    }

    se_tropic_log("TROPIC pairing pub slot %u:", (unsigned)slot);
    se_tropic_log_hex(NULL, pub, sizeof(pub));
    se_tropic_log("TROPIC factory SH0 invalidated");

    se_tropic_deinit_session();
    if (se_tropic_init_session() != SE_TROPIC_OK) {
        se_tropic_log("TROPIC PAIRING re-session with new key failed");
        return SE_TROPIC_ERR;
    }
    return SE_TROPIC_OK;
}

uint32_t se_tropic_pairing_pub_read(uint8_t out32[32])
{
    if (out32 == NULL) {
        return SE_TROPIC_ERR;
    }
    pairing_creds_load();
    if (s_pkey_valid == 0U) {
        return SE_TROPIC_ERR;
    }
    (void)memcpy(out32, s_pkey_pub, 32U);
    return SE_TROPIC_OK;
}

lt_handle_t *se_tropic_handle(void)
{
    if (s_session_active == 0U) {
        return NULL;
    }
    return &s_lt;
}
