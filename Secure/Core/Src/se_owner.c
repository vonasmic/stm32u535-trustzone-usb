/**
 * @file    se_owner.c
 * @brief   Owner SPKI + ASCII reset password
 */
#include "se_owner.h"
#include "se_creds.h"
#include "se_tropic.h"
#include "se_tropic_port.h"
#include <string.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/memory.h>

int se_owner_pw_ok(const uint8_t *pw, uint16_t len)
{
    uint16_t i;

    if ((pw == NULL) || (len < SE_OWNER_PW_MIN) || (len > SE_OWNER_PW_MAX)) {
        return 0;
    }
    for (i = 0U; i < len; i++) {
        if ((pw[i] < 0x20u) || (pw[i] > 0x7eu)) {
            return 0;
        }
    }
    return 1;
}

lt_ret_t se_owner_hash_pw(const uint8_t *pw, uint16_t len, uint8_t out[SE_NV_PW_HASH_LEN])
{
    uint8_t dwk[SE_NV_DWK_LEN];
    wc_Sha384 sha;
    int rc;
    lt_ret_t ret;

    if ((out == NULL) || (se_owner_pw_ok(pw, len) == 0)) {
        return LT_PARAM_ERR;
    }
    ret = se_tropic_port_dwk(dwk);
    if (ret != LT_OK) {
        return ret;
    }
    rc = wc_InitSha384(&sha);
    if (rc == 0) {
        rc = wc_Sha384Update(&sha, dwk, SE_NV_DWK_LEN);
    }
    if (rc == 0) {
        rc = wc_Sha384Update(&sha, pw, len);
    }
    if (rc == 0) {
        rc = wc_Sha384Final(&sha, out);
    }
    wc_Sha384Free(&sha);
    wc_ForceZero(dwk, sizeof(dwk));
    return (rc == 0) ? LT_OK : LT_CRYPTO_ERR;
}

lt_ret_t se_owner_verify_pw(const uint8_t *pw, uint16_t len)
{
    uint8_t got[SE_NV_PW_HASH_LEN];
    uint8_t expect[SE_NV_PW_HASH_LEN];
    uint8_t diff = 0U;
    uint16_t i;
    lt_ret_t ret;

    ret = se_owner_hash_pw(pw, len, got);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_nv_get_pw_hash(expect);
    if (ret != LT_OK) {
        wc_ForceZero(got, sizeof(got));
        return ret;
    }
    for (i = 0U; i < SE_NV_PW_HASH_LEN; i++) {
        diff = (uint8_t)(diff | (got[i] ^ expect[i]));
    }
    wc_ForceZero(got, sizeof(got));
    wc_ForceZero(expect, sizeof(expect));
    return (diff == 0U) ? LT_OK : LT_FAIL;
}

lt_ret_t se_owner_set(const uint8_t *pw, uint16_t pw_len, const uint8_t *spki, uint16_t spki_len)
{
    uint8_t hash[SE_NV_PW_HASH_LEN];
    lt_ret_t ret;

    if ((spki == NULL) || (spki_len == 0U) || (spki_len > SE_NV_OWNER_SPKI_MAX) ||
        (se_owner_pw_ok(pw, pw_len) == 0)) {
        return LT_PARAM_ERR;
    }
    if (se_nv_has_owner() != 0) {
        return LT_FAIL;
    }
    ret = se_owner_hash_pw(pw, pw_len, hash);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_nv_set_owner(spki, spki_len, hash);
    wc_ForceZero(hash, sizeof(hash));
    return ret;
}

lt_ret_t se_owner_replace(const uint8_t *old_pw, uint16_t old_len, const uint8_t *new_pw,
                          uint16_t new_len, const uint8_t *spki, uint16_t spki_len)
{
    uint8_t hash[SE_NV_PW_HASH_LEN];
    lt_ret_t ret;

    if ((spki == NULL) || (spki_len == 0U) || (spki_len > SE_NV_OWNER_SPKI_MAX) ||
        (se_owner_pw_ok(new_pw, new_len) == 0)) {
        return LT_PARAM_ERR;
    }
    if (se_nv_has_owner() == 0) {
        return LT_FAIL;
    }
    ret = se_owner_verify_pw(old_pw, old_len);
    if (ret != LT_OK) {
        return ret;
    }
    if (se_tropic_user_wipe() != SE_TROPIC_OK) {
        return LT_FAIL;
    }
    ret = se_creds_clear();
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_nv_clear_except_pairing();
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_owner_hash_pw(new_pw, new_len, hash);
    if (ret != LT_OK) {
        return ret;
    }
    ret = se_nv_set_owner(spki, spki_len, hash);
    wc_ForceZero(hash, sizeof(hash));
    return ret;
}
