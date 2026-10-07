/**
 * @file    se_creds.c
 * @brief   Packed SAE CA + device cert on the Secure creds page
 */
#include "se_creds.h"
#include "se_le.h"
#include "se_nv.h"
#include "se_tropic_port.h"
#include "se_ram.h"
#include <string.h>
#include <wolfssl/wolfcrypt/memory.h>

#define SE_CREDS_MAGIC 0x53454344u /* SECD */

static uint8_t *s_page;
static uint8_t *s_keep;

static lt_ret_t creds_hold(int with_keep)
{
    size_t n = SE_CREDS_PAGE_SIZE;
    uint8_t *p;

    if (with_keep != 0) {
        n += SE_CREDS_DER_MAX;
    }
    p = se_workspace_acquire(n);
    if (p == NULL) {
        return LT_FAIL;
    }
    s_page = p;
    s_keep = (with_keep != 0) ? (p + SE_CREDS_PAGE_SIZE) : NULL;
    return LT_OK;
}

static void creds_drop(void)
{
    s_page = NULL;
    s_keep = NULL;
    se_workspace_release();
}

static int page_erased(void)
{
    uint16_t i;

    for (i = 0U; i < 16U; i++) {
        if (s_page[i] != 0xffu) {
            return 0;
        }
    }
    return 1;
}

static lt_ret_t creds_load(uint16_t *sae_len, uint16_t *cert_len, uint32_t *sae_off,
                           uint32_t *cert_off)
{
    uint16_t sl;
    uint16_t cl;
    lt_ret_t ret;

    ret = se_tropic_port_creds_page_read(s_page);
    if (ret != LT_OK) {
        return ret;
    }
    if (page_erased() != 0) {
        *sae_len = 0U;
        *cert_len = 0U;
        *sae_off = 8U;
        *cert_off = 8U;
        return LT_OK;
    }
    if (se_u32le(s_page) != SE_CREDS_MAGIC) {
        return SE_TROPIC_LT_TAMPERED;
    }
    sl = se_u16le(s_page + 4);
    cl = se_u16le(s_page + 6);
    if ((sl > SE_CREDS_DER_MAX) || (cl > SE_CREDS_DER_MAX) ||
        ((uint32_t)8U + sl + cl > SE_CREDS_PAGE_SIZE)) {
        return SE_TROPIC_LT_TAMPERED;
    }
    *sae_len = sl;
    *cert_len = cl;
    *sae_off = 8U;
    *cert_off = 8U + sl;
    return LT_OK;
}

static lt_ret_t creds_save(const uint8_t *sae, uint16_t sl, const uint8_t *cert, uint16_t cl)
{
    if (((uint32_t)8U + sl + cl) > SE_CREDS_PAGE_SIZE) {
        return LT_PARAM_ERR;
    }
    (void)memset(s_page, 0xff, SE_CREDS_PAGE_SIZE);
    se_put_u32le(s_page, SE_CREDS_MAGIC);
    se_put_u16le(s_page + 4, sl);
    se_put_u16le(s_page + 6, cl);
    if ((sae != NULL) && (sl > 0U)) {
        (void)memcpy(s_page + 8, sae, sl);
    }
    if ((cert != NULL) && (cl > 0U)) {
        (void)memcpy(s_page + 8U + sl, cert, cl);
    }
    return se_tropic_port_creds_page_write(s_page);
}

int se_creds_has_sae_ca(void)
{
    uint16_t sl = 0U;
    uint16_t cl = 0U;
    uint32_t so = 0U;
    uint32_t co = 0U;
    int ok = 0;

    if (creds_hold(0) != LT_OK) {
        return 0;
    }
    if (creds_load(&sl, &cl, &so, &co) == LT_OK) {
        ok = (sl > 0U) ? 1 : 0;
    }
    creds_drop();
    return ok;
}

int se_creds_has_device_cert(void)
{
    uint16_t sl = 0U;
    uint16_t cl = 0U;
    uint32_t so = 0U;
    uint32_t co = 0U;
    int ok = 0;

    if (creds_hold(0) != LT_OK) {
        return 0;
    }
    if (creds_load(&sl, &cl, &so, &co) == LT_OK) {
        ok = (cl > 0U) ? 1 : 0;
    }
    creds_drop();
    return ok;
}

lt_ret_t se_creds_get_sae_ca(uint8_t *out, uint16_t *len, uint16_t cap)
{
    uint16_t sl = 0U;
    uint16_t cl = 0U;
    uint32_t so = 0U;
    uint32_t co = 0U;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = creds_hold(0);
    if (ret != LT_OK) {
        return ret;
    }
    ret = creds_load(&sl, &cl, &so, &co);
    if (ret != LT_OK) {
        creds_drop();
        return ret;
    }
    if (sl == 0U) {
        *len = 0U;
        creds_drop();
        return LT_FAIL;
    }
    if (cap < sl) {
        creds_drop();
        return LT_PARAM_ERR;
    }
    (void)memcpy(out, s_page + so, sl);
    *len = sl;
    creds_drop();
    return LT_OK;
}

lt_ret_t se_creds_get_device_cert(uint8_t *out, uint16_t *len, uint16_t cap)
{
    uint16_t sl = 0U;
    uint16_t cl = 0U;
    uint32_t so = 0U;
    uint32_t co = 0U;
    lt_ret_t ret;

    if ((out == NULL) || (len == NULL)) {
        return LT_PARAM_ERR;
    }
    ret = creds_hold(0);
    if (ret != LT_OK) {
        return ret;
    }
    ret = creds_load(&sl, &cl, &so, &co);
    if (ret != LT_OK) {
        creds_drop();
        return ret;
    }
    if (cl == 0U) {
        *len = 0U;
        creds_drop();
        return LT_FAIL;
    }
    if (cap < cl) {
        creds_drop();
        return LT_PARAM_ERR;
    }
    (void)memcpy(out, s_page + co, cl);
    *len = cl;
    creds_drop();
    return LT_OK;
}

lt_ret_t se_creds_set_sae_ca(const uint8_t *der, uint16_t len)
{
    uint16_t sl = 0U;
    uint16_t cl = 0U;
    uint32_t so = 0U;
    uint32_t co = 0U;
    lt_ret_t ret;

    if ((der == NULL) || (len == 0U) || (len > SE_CREDS_DER_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = creds_hold(1);
    if (ret != LT_OK) {
        return ret;
    }
    ret = creds_load(&sl, &cl, &so, &co);
    if (ret != LT_OK) {
        creds_drop();
        return ret;
    }
    if (cl > 0U) {
        (void)memcpy(s_keep, s_page + co, cl);
    }
    ret = creds_save(der, len, (cl > 0U) ? s_keep : NULL, cl);
    creds_drop();
    return ret;
}

lt_ret_t se_creds_set_device_cert(const uint8_t *der, uint16_t len)
{
    uint16_t sl = 0U;
    uint16_t cl = 0U;
    uint32_t so = 0U;
    uint32_t co = 0U;
    lt_ret_t ret;

    if ((der == NULL) || (len == 0U) || (len > SE_CREDS_DER_MAX)) {
        return LT_PARAM_ERR;
    }
    ret = creds_hold(1);
    if (ret != LT_OK) {
        return ret;
    }
    ret = creds_load(&sl, &cl, &so, &co);
    if (ret != LT_OK) {
        creds_drop();
        return ret;
    }
    if (sl > 0U) {
        (void)memcpy(s_keep, s_page + so, sl);
    }
    ret = creds_save((sl > 0U) ? s_keep : NULL, sl, der, len);
    creds_drop();
    return ret;
}

lt_ret_t se_creds_clear(void)
{
    lt_ret_t ret;

    ret = creds_hold(0);
    if (ret != LT_OK) {
        return ret;
    }
    (void)memset(s_page, 0xff, SE_CREDS_PAGE_SIZE);
    ret = se_tropic_port_creds_page_write(s_page);
    creds_drop();
    return ret;
}

int se_ready_encrypt(void)
{
    return (se_nv_has_owner() != 0) && (se_creds_has_device_cert() != 0) &&
           (se_nv_has_device_sk() != 0);
}

int se_ready_provision(void)
{
    if (se_ready_encrypt() == 0) {
        return 0;
    }
    if (se_creds_has_sae_ca() == 0) {
        return 0;
    }
    return se_nv_has_mlkem();
}
