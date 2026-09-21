/**
 * @file    se_nv_peer.c
 * @brief   Peer list in MCU NV (load/store via se_nv.c)
 */
#include "se_nv.h"
#include "se_nv_internal.h"
#include <string.h>

static int peer_name_char_ok(uint8_t c)
{
    return ((c >= (uint8_t)'A') && (c <= (uint8_t)'Z')) ||
           ((c >= (uint8_t)'a') && (c <= (uint8_t)'z')) ||
           ((c >= (uint8_t)'0') && (c <= (uint8_t)'9')) || (c == (uint8_t)'_') ||
           (c == (uint8_t)'.') || (c == (uint8_t)'-');
}

int se_nv_peer_name_ok(const uint8_t *name, uint8_t name_len)
{
    uint8_t i;

    if ((name == NULL) || (name_len < 1u) || (name_len > SE_NV_PEER_NAME_MAX)) {
        return 0;
    }
    for (i = 0U; i < name_len; i++) {
        if (peer_name_char_ok(name[i]) == 0) {
            return 0;
        }
    }
    return 1;
}

static int peer_names_equal(const uint8_t *a, uint8_t a_len, const uint8_t *b, uint8_t b_len)
{
    if (a_len != b_len) {
        return 0;
    }
    return (memcmp(a, b, a_len) == 0) ? 1 : 0;
}

lt_ret_t se_nv_peer_add(const uint8_t *name, uint8_t name_len,
                        const uint8_t hash48[SE_NV_PEER_HASH_LEN])
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t i;

    if ((hash48 == NULL) || (se_nv_peer_name_ok(name, name_len) == 0)) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    for (i = 0U; i < st.peer_count; i++) {
        if (peer_names_equal(st.peers[i].name, st.peers[i].name_len, name, name_len) != 0) {
            return SE_NV_PEER_EXISTS;
        }
    }
    if (st.peer_count >= SE_NV_PEER_MAX) {
        return SE_NV_PEER_FULL;
    }
    i = st.peer_count;
    st.peers[i].name_len = name_len;
    (void)memset(st.peers[i].name, 0, SE_NV_PEER_NAME_MAX);
    (void)memcpy(st.peers[i].name, name, name_len);
    (void)memcpy(st.peers[i].hash, hash48, SE_NV_PEER_HASH_LEN);
    st.peer_count = (uint8_t)(st.peer_count + 1u);
    return se_nv_store(&st);
}

lt_ret_t se_nv_peer_remove(const uint8_t *name, uint8_t name_len)
{
    se_nv_state_t st;
    lt_ret_t ret;
    uint8_t i;
    uint8_t found = SE_NV_PEER_MAX;

    if (se_nv_peer_name_ok(name, name_len) == 0) {
        return LT_PARAM_ERR;
    }
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    for (i = 0U; i < st.peer_count; i++) {
        if (peer_names_equal(st.peers[i].name, st.peers[i].name_len, name, name_len) != 0) {
            found = i;
            break;
        }
    }
    if (found >= SE_NV_PEER_MAX) {
        return SE_NV_PEER_NOT_FOUND;
    }
    for (i = found; i + 1u < st.peer_count; i++) {
        st.peers[i] = st.peers[i + 1u];
    }
    st.peer_count = (uint8_t)(st.peer_count - 1u);
    (void)memset(&st.peers[st.peer_count], 0, sizeof(st.peers[0]));
    return se_nv_store(&st);
}

lt_ret_t se_nv_peer_count(uint8_t *count)
{
    se_nv_state_t st;
    lt_ret_t ret;

    if (count == NULL) {
        return LT_PARAM_ERR;
    }
    *count = 0U;
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    *count = st.peer_count;
    return LT_OK;
}

lt_ret_t se_nv_peer_get(uint8_t index, uint8_t *name, uint8_t *name_len,
                        uint8_t hash48[SE_NV_PEER_HASH_LEN])
{
    se_nv_state_t st;
    uint8_t nlen;
    uint8_t cap;
    lt_ret_t ret;

    if ((name == NULL) || (name_len == NULL) || (hash48 == NULL)) {
        return LT_PARAM_ERR;
    }
    cap = *name_len;
    ret = se_nv_load(&st);
    if (ret != LT_OK) {
        return ret;
    }
    if (index >= st.peer_count) {
        return SE_NV_PEER_NOT_FOUND;
    }
    nlen = st.peers[index].name_len;
    if (cap < nlen) {
        return LT_PARAM_ERR;
    }
    (void)memcpy(name, st.peers[index].name, nlen);
    (void)memcpy(hash48, st.peers[index].hash, SE_NV_PEER_HASH_LEN);
    *name_len = nlen;
    return LT_OK;
}
