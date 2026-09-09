/**
 * @file    se_tropic_session.c
 * @brief   TROPIC01 session binding and streamed LV uplink
 */
#include "se_tropic_session.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "se_tropic_port.h"
#include "se_usb_tls.h"
#include "secure_lv.h"
#include "se_le.h"
#include "se_creds.h"
#include "se_cert_spki.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <string.h>

#define SE_TROPIC_ECC_PUB_LEN     64u
#define SE_TROPIC_SESSION_SIG_LEN 64u

/* 1184-byte ML-KEM PK is too large for the TLS task stack. */
static uint8_t s_uplink_kem_pk[SE_TROPIC_MLKEM_PK_LEN];
static uint8_t s_hash_cert[SE_CREDS_DER_MAX];

/** client_hash = SHA384(device_cert_spki || ecc_pub). Same value as uplink item 2. */
static int client_hash_from_pub(const uint8_t ecc_pub[SE_TROPIC_ECC_PUB_LEN],
                                uint8_t client_hash[SE_TROPIC_CLIENT_HASH_LEN])
{
    wc_Sha384 sha;
    const uint8_t *spki = NULL;
    uint32_t spki_len = 0U;
    uint16_t cert_len = 0U;
    int rc = -1;

    if ((ecc_pub == NULL) || (client_hash == NULL)) {
        return -1;
    }
    if (se_creds_get_device_cert(s_hash_cert, &cert_len, (uint16_t)sizeof(s_hash_cert)) != LT_OK) {
        return -1;
    }
    if (se_cert_spki_raw(s_hash_cert, cert_len, &spki, &spki_len) != 0) {
        wc_ForceZero(s_hash_cert, sizeof(s_hash_cert));
        return -1;
    }
    if (wc_InitSha384(&sha) != 0) {
        wc_ForceZero(s_hash_cert, sizeof(s_hash_cert));
        return -1;
    }
    if ((wc_Sha384Update(&sha, spki, spki_len) == 0) &&
        (wc_Sha384Update(&sha, ecc_pub, SE_TROPIC_ECC_PUB_LEN) == 0) &&
        (wc_Sha384Final(&sha, client_hash) == 0)) {
        rc = 0;
    }
    wc_Sha384Free(&sha);
    wc_ForceZero(s_hash_cert, sizeof(s_hash_cert));
    return rc;
}

uint32_t se_tropic_client_hash_dump(void)
{
    uint8_t ecc_pub[SE_TROPIC_ECC_PUB_LEN];
    uint8_t client_hash[SE_TROPIC_CLIENT_HASH_LEN];

    if (se_tropic_pub_read(ecc_pub) != SE_TROPIC_OK) {
        return SE_TROPIC_ERR;
    }
    if (client_hash_from_pub(ecc_pub, client_hash) != 0) {
        wc_ForceZero(ecc_pub, sizeof(ecc_pub));
        return SE_TROPIC_ERR;
    }
    se_tropic_log("client hash:");
    se_tropic_log_hex(NULL, client_hash, SE_TROPIC_CLIENT_HASH_LEN);
    wc_ForceZero(ecc_pub, sizeof(ecc_pub));
    wc_ForceZero(client_hash, sizeof(client_hash));
    return SE_TROPIC_OK;
}

/**
 * Bind this TLS session to the device identity.
 * to_sign = SHA384(SHA384(mldsa_spki || ecc_pub) || exporter)
 */
static int session_sign(uint8_t exporter[SE_TROPIC_EXPORTER_LEN],
                        uint8_t ecc_pub[SE_TROPIC_ECC_PUB_LEN],
                        uint8_t client_hash[SE_TROPIC_CLIENT_HASH_LEN],
                        uint8_t sig[SE_TROPIC_SESSION_SIG_LEN])
{
    uint8_t to_sign[WC_SHA384_DIGEST_SIZE];
    wc_Sha384 sha;
    int rc = -1;

    if (se_tropic_pub_read(ecc_pub) != SE_TROPIC_OK) {
        se_usb_debug_printf("session: TROPIC pub read failed");
        return -1;
    }

    if (client_hash_from_pub(ecc_pub, client_hash) != 0) {
        return -1;
    }

    rc = -1;
    if (wc_InitSha384(&sha) != 0) {
        return -1;
    }
    if ((wc_Sha384Update(&sha, client_hash, SE_TROPIC_CLIENT_HASH_LEN) == 0) &&
        (wc_Sha384Update(&sha, exporter, SE_TROPIC_EXPORTER_LEN) == 0) &&
        (wc_Sha384Final(&sha, to_sign) == 0)) {
        rc = 0;
    }
    wc_Sha384Free(&sha);
    wc_ForceZero(exporter, SE_TROPIC_EXPORTER_LEN);
    if (rc != 0) {
        return -1;
    }

    /* TROPIC01 signs a 32-byte digest. P-256 ECDSA takes the leftmost 256 bits of
     * the digest (FIPS 186-4 §6.4), so handing it the first 32 bytes of the SHA-384
     * value is what a verifier computes from the full 48 bytes. */
    if (se_tropic_sign_hash(to_sign, sig) != SE_TROPIC_OK) {
        se_usb_debug_printf("session: TROPIC sign failed");
        wc_ForceZero(to_sign, sizeof(to_sign));
        return -1;
    }
    wc_ForceZero(to_sign, sizeof(to_sign));
    return 0;
}

int se_tropic_session_uplink(uint8_t exporter[SE_TROPIC_EXPORTER_LEN],
                             secure_stream_write_fn write, void *ctx)
{
    uint8_t ecc_pub[SE_TROPIC_ECC_PUB_LEN];
    uint8_t client_hash[SE_TROPIC_CLIENT_HASH_LEN];
    uint8_t sig[SE_TROPIC_SESSION_SIG_LEN];
    uint8_t slot_size_le[2];
    uint8_t pad_count_le[2];
    uint8_t pending_fill[SE_NV_FILL_ID_LEN];
    const uint8_t version = (uint8_t)SECURE_LV_UPLINK_VERSION;
    uint16_t slot_size;
    uint16_t pad_count = SE_TROPIC_PAD_COUNT;
    uint16_t kem_pk_len = 0U;
    uint16_t count;
    unsigned int i;
    uint8_t peer_n;
    int rc = -1;
    lt_ret_t ret;

    if ((exporter == NULL) || (write == NULL)) {
        return -1;
    }

    if (session_sign(exporter, ecc_pub, client_hash, sig) != 0) {
        return -1;
    }

    if (se_tropic_mlkem_pub_read(s_uplink_kem_pk, sizeof(s_uplink_kem_pk), &kem_pk_len) !=
        SE_TROPIC_OK) {
        se_usb_debug_printf("session: ML-KEM pk not available");
        return -1;
    }

    ret = se_tropic_port_nv_random(pending_fill, sizeof(pending_fill));
    if (ret != LT_OK) {
        se_usb_debug_printf("session: pending fill_id RNG failed");
        return -1;
    }
    se_nv_pending_fill_set(pending_fill);

    slot_size = se_tropic_get_rmem_slot_max_size(se_tropic_handle());
    se_put_u16le(slot_size_le, slot_size);
    se_put_u16le(pad_count_le, pad_count);

    peer_n = 0U;
    ret = se_nv_peer_count(&peer_n);
    if (ret != LT_OK) {
        se_usb_debug_printf("session: peer list NV failed");
        return -1;
    }
    count = (uint16_t)(SECURE_LV_UPLINK_FIXED_ITEMS + (2u * (unsigned int)peer_n));

    if ((write(&version, 1U, ctx) == 0) &&
        (secure_lv_write_u16(count, write, ctx) == 0) &&
        (secure_lv_write_item(sig, SE_TROPIC_SESSION_SIG_LEN, write, ctx) == 0) &&
        (secure_lv_write_item(ecc_pub, SE_TROPIC_ECC_PUB_LEN, write, ctx) == 0) &&
        (secure_lv_write_item(client_hash, SE_TROPIC_CLIENT_HASH_LEN, write, ctx) == 0) &&
        (secure_lv_write_item(slot_size_le, (uint16_t)sizeof(slot_size_le), write, ctx) == 0) &&
        (secure_lv_write_item(pad_count_le, (uint16_t)sizeof(pad_count_le), write, ctx) == 0) &&
        (secure_lv_write_item(pending_fill, SE_NV_FILL_ID_LEN, write, ctx) == 0) &&
        (secure_lv_write_item(s_uplink_kem_pk, kem_pk_len, write, ctx) == 0)) {
        rc = 0;
    }

    for (i = 0U; (rc == 0) && (i < (unsigned int)peer_n); i++) {
        uint8_t name[SE_NV_PEER_NAME_MAX];
        uint8_t hash48[SE_NV_PEER_HASH_LEN];
        uint8_t name_len = SE_NV_PEER_NAME_MAX;

        ret = se_nv_peer_get((uint8_t)i, name, &name_len, hash48);
        if (ret != LT_OK) {
            rc = -1;
            break;
        }
        if (secure_lv_write_item(hash48, SE_NV_PEER_HASH_LEN, write, ctx) != 0) {
            rc = -1;
            break;
        }
        if (secure_lv_write_item(name, (uint16_t)name_len, write, ctx) != 0) {
            rc = -1;
        }
    }

    wc_ForceZero(sig, sizeof(sig));
    wc_ForceZero(client_hash, sizeof(client_hash));
    wc_ForceZero(pending_fill, sizeof(pending_fill));
    wc_ForceZero(s_uplink_kem_pk, sizeof(s_uplink_kem_pk));
    return rc;
}

uint32_t se_tropic_cert_dump(void)
{
    se_usb_debug_printf("TROPIC cert not used (identity key lives on TROPIC01)");
    return 1U;
}
