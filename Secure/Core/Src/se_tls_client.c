/**
 * @file    se_tls_client.c
 * @brief   TLS 1.3 mTLS client I/O and session state machine
 *
 * NonSecure arms a mode (with Unix time) before handshake. Provision verifies the
 * SAE application CA and streams the session-bound uplink then feeds downlink
 * to secure_qkd_ingest. Encrypt/decrypt verify the client CA; encrypt waits for
 * PIN+plaintext and decrypt for PIN plus the encrypt OTP stream
 * (n_pads then slot/chunk records). Encrypt/decrypt also pin the TLS peer
 * SPKI to the home-PC user key embedded from certs/user/user-cert.pem.
 * Encrypt replies include slots. Decrypt replies are n_pads then plaintext
 * chunks only. OTP-consume uses separate cursors. After the last application
 * record the client sends close_notify and stays in TLS until the peer's
 * close_notify (SAE or UserApp), then returns to ASCII.
 */
#include "se_tls_client.h"
#include "se_tls_nsc.h"
#include "se_tropic_session.h"
#include "se_tropic.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "se_usb_tls.h"
#include "se_time.h"
#include "secure_client_key.h"
#include "secure_qkd_ingest.h"
#include "secure_otp.h"
#include "se_tls_user.h"
#include "se_creds.h"
#include "se_auth.h"
#include "se_manage.h"
#include "se_le.h"
#include "main.h"
#include <string.h>
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_port.h"

#define TLS_APP_READ_CHUNK 512
#define TLS_WRITE_CHUNK    1024
#define TLS_SHUTDOWN_MS    3000u

extern int se_tls_embed_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
extern int se_tls_embed_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

typedef enum {
    TLS_ST_IDLE = 0,
    TLS_ST_HANDSHAKE,
    TLS_ST_WRITE_UPLINK,
    TLS_ST_READ_RESP,
    TLS_ST_WRITE_ACK,
    TLS_ST_READ_OTP,
    TLS_ST_WRITE_OTP,
    TLS_ST_READ_MANAGE,
    TLS_ST_WRITE_MANAGE,
    TLS_ST_SHUTDOWN,
    TLS_ST_DONE,
    TLS_ST_ERROR
} TlsState;

static TlsState s_state = TLS_ST_IDLE;
static uint32_t s_mode;
static WOLFSSL_CTX *s_ctx;
static WOLFSSL *s_ssl;
static uint8_t s_exporter[SE_TROPIC_EXPORTER_LEN];
static uint8_t s_otp_rest[TLS_APP_READ_CHUNK];
static uint32_t s_otp_rest_len;
static uint8_t s_otp_tx[4u + 4u + SE_TROPIC_RMEM_PLAIN_MAX];
static uint16_t s_otp_tx_len;
static uint16_t s_otp_tx_off;
static uint8_t s_otp_count_written;
static uint8_t s_otp_err;
static uint8_t s_tls_der[SE_CREDS_DER_MAX];
static uint32_t s_manage_got;
static uint8_t s_manage_tx[SE_MANAGE_RSP_MAX];
static uint16_t s_manage_tx_len;
static uint16_t s_manage_tx_off;
static uint32_t s_shutdown_tick;

static void tls_wipe_otp(void)
{
    wc_ForceZero(s_otp_rest, s_otp_rest_len);
    s_otp_rest_len = 0U;
    wc_ForceZero(s_otp_tx, s_otp_tx_len);
    s_otp_tx_len = 0U;
    s_otp_tx_off = 0U;
    s_otp_count_written = 0U;
    s_otp_err = 0U;
    se_tropic_otp_xor_close();
    secure_otp_reset();
}

static void tls_wipe_mode(void)
{
    s_mode = 0U;
}

static void tls_wipe_manage(void)
{
    s_manage_got = 0U;
    wc_ForceZero(s_manage_tx, sizeof(s_manage_tx));
    s_manage_tx_len = 0U;
    s_manage_tx_off = 0U;
    se_manage_buf_wipe();
}

static void tls_wipe_ssl(void)
{
    if (s_ssl != NULL) {
        wolfSSL_free(s_ssl);
        s_ssl = NULL;
    }
    if (s_ctx != NULL) {
        wolfSSL_CTX_free(s_ctx);
        s_ctx = NULL;
    }
    wc_ForceZero(s_exporter, sizeof(s_exporter));
    tls_wipe_manage();
    s_shutdown_tick = 0U;
}

static void tls_session_close(void)
{
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_usb_debug_puts("TLS session ok");
    tls_wipe_mode();
    s_state = TLS_ST_IDLE;
}

static int tls_shutdown_peer_pending(int ret)
{
    int err;

    if (ret == WOLFSSL_SUCCESS) {
        return 0;
    }
    if (ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
        return 1;
    }
    err = wolfSSL_get_error(s_ssl, ret);
    return (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) ? 1 : 0;
}

static int tls_setup_groups(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
    int groups[] = { WOLFSSL_ML_KEM_768 };
    int i;

    for (i = 0; i < (int)(sizeof(groups) / sizeof(groups[0])); i++) {
        if (wolfSSL_CTX_set_groups(ctx, &groups[i], 1) == WOLFSSL_SUCCESS) {
            if (wolfSSL_UseKeyShare(ssl, groups[i]) == WOLFSSL_SUCCESS) {
                return 0;
            }
        }
    }
    return -1;
}

static int tls_write_all(const uint8_t *data, uint32_t len, void *ctx)
{
    WOLFSSL *ssl = (WOLFSSL *)ctx;
    uint32_t off = 0U;

    if (ssl == NULL) {
        return -1;
    }

    while (off < len) {
        uint32_t chunk = len - off;
        int n;

        if (chunk > TLS_WRITE_CHUNK) {
            chunk = TLS_WRITE_CHUNK;
        }
        n = wolfSSL_write(ssl, data + off, (int)chunk);
        if (n <= 0) {
            return -1;
        }
        off += (uint32_t)n;
    }
    return 0;
}

static int tls_accept_peer_leaf(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    (void)preverify;
    (void)store;
    return 1;
}

static int tls_load_provision_ca(WOLFSSL_CTX *ctx)
{
    uint16_t ca_len = 0U;

    if (se_creds_get_sae_ca(s_tls_der, &ca_len, (uint16_t)sizeof(s_tls_der)) != LT_OK) {
        se_usb_debug_puts("TLS setup: no SAE CA");
        return -1;
    }
    if (wolfSSL_CTX_load_verify_buffer(ctx, s_tls_der, (long)ca_len, WOLFSSL_FILETYPE_ASN1) !=
        WOLFSSL_SUCCESS) {
        se_usb_debug_puts("TLS setup: load CA failed");
        return -1;
    }
    return 0;
}

static int tls_start(void)
{
    uint16_t cert_len = 0U;

    s_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (s_ctx == NULL) {
        se_usb_debug_puts("TLS setup: CTX_new failed");
        return -1;
    }

    wolfSSL_CTX_SetMinVersion(s_ctx, WOLFSSL_TLSV1_3);
    (void)wolfSSL_CTX_set_cipher_list(s_ctx, "TLS13-AES256-GCM-SHA384");

    if (s_mode == SECURE_TLS_MODE_PROVISION) {
        if (tls_load_provision_ca(s_ctx) != 0) {
            return -1;
        }
        wolfSSL_CTX_set_verify(s_ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               NULL);
    } else {
        wolfSSL_CTX_set_verify(s_ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               tls_accept_peer_leaf);
    }
    /* MANAGE is owner-pinned TLS without a device client cert (not mTLS). */
    if (s_mode != SECURE_TLS_MODE_MANAGE) {
        if (se_creds_get_device_cert(s_tls_der, &cert_len, (uint16_t)sizeof(s_tls_der)) !=
            LT_OK) {
            se_usb_debug_puts("TLS setup: no device cert");
            return -1;
        }
        if (wolfSSL_CTX_use_certificate_buffer(s_ctx, s_tls_der, (long)cert_len,
                                               WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            se_usb_debug_puts("TLS setup: load client cert failed");
            return -1;
        }
        if (secure_client_key_load(s_ctx) != 0) {
            se_usb_debug_puts("TLS setup: load key failed");
            return -1;
        }
    }

    wolfSSL_CTX_SetIORecv(s_ctx, se_tls_embed_recv);
    wolfSSL_CTX_SetIOSend(s_ctx, (CallbackIOSend)se_tls_embed_send);

    s_ssl = wolfSSL_new(s_ctx);
    if (s_ssl == NULL) {
        se_usb_debug_puts("TLS setup: SSL_new failed");
        return -1;
    }

    wolfSSL_SetIOReadCtx(s_ssl, NULL);
    wolfSSL_SetIOWriteCtx(s_ssl, NULL);

    if (tls_setup_groups(s_ctx, s_ssl) != 0) {
        se_usb_debug_puts("TLS setup: ML-KEM group failed");
        return -1;
    }

    /* Exporter (provision) refuses unless handshake arrays are retained. */
    if (s_mode != SECURE_TLS_MODE_MANAGE) {
        wolfSSL_KeepArrays(s_ssl);
    }

    s_state = TLS_ST_HANDSHAKE;
    se_usb_debug_puts("sending handshake");
    return 0;
}

int se_tls_arm(uint32_t mode)
{
    if ((s_state != TLS_ST_IDLE) || (s_mode != 0U)) {
        return -1;
    }
    if (se_auth_active() != 0) {
        return -1;
    }
    if (se_time_is_synced() == 0) {
        return -1;
    }
    if ((mode != SECURE_TLS_MODE_PROVISION) && (mode != SECURE_TLS_MODE_ENCRYPT) &&
        (mode != SECURE_TLS_MODE_DECRYPT) && (mode != SECURE_TLS_MODE_MANAGE)) {
        return -1;
    }
    if (mode == SECURE_TLS_MODE_PROVISION) {
        if (se_ready_provision() == 0) {
            se_usb_debug_puts("TLS refused: not provision-ready");
            return -1;
        }
    } else if (mode == SECURE_TLS_MODE_MANAGE) {
        if (se_nv_has_owner() == 0) {
            se_usb_debug_puts("TLS refused: no owner");
            return -1;
        }
    } else if (se_ready_encrypt() == 0) {
        se_usb_debug_puts("TLS refused: not encrypt-ready");
        return -1;
    }
    s_mode = mode;
    return 0;
}

int se_tls_session_active(void)
{
    return (s_mode != 0U) ? 1 : 0;
}

void se_tls_init(void)
{
    s_state = TLS_ST_IDLE;
    tls_wipe_mode();
    secure_otp_reset();
    tls_wipe_otp();
    tls_wipe_ssl();
}

void se_tls_reset_quiet(void)
{
    secure_qkd_discard();
    secure_otp_reset();
    tls_wipe_otp();
    tls_wipe_mode();
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    s_state = TLS_ST_IDLE;
}

void se_tls_abort(void)
{
    int ssl_err = 0;

    if (s_ssl != NULL) {
        ssl_err = wolfSSL_get_error(s_ssl, -1);
    }
    secure_qkd_discard();
    secure_otp_reset();
    tls_wipe_otp();
    tls_wipe_mode();
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    if (ssl_err == ASN_BEFORE_DATE_E) {
        se_usb_debug_puts("TLS failed: cert not yet valid (RTC)");
    } else if (ssl_err == ASN_AFTER_DATE_E) {
        se_usb_debug_puts("TLS failed: cert expired (RTC)");
    } else if (ssl_err == VERSION_ERROR) {
        se_usb_debug_puts("TLS failed: record version (restart bridge)");
    } else if (ssl_err == 0) {
        se_usb_debug_puts("TLS aborted");
    } else {
        se_usb_debug_puts("TLS failed");
    }
    /* Stay idle until NonSecure sends PROVISION / ENCRYPT / DECRYPT <unix>. */
    s_state = TLS_ST_IDLE;
}

static void tls_qkd_status(uint32_t st)
{
    if (st == SECURE_QKD_WRONG_VERSION) {
        se_usb_debug_puts("downlink schema mismatch");
    } else if (st == SECURE_QKD_STORE) {
        se_usb_debug_puts("downlink Tropic store failed");
    } else if (st != SECURE_QKD_OK) {
        se_usb_debug_puts("downlink parse error");
    } else {
        se_usb_debug_puts("response done");
    }
}

static int tls_qkd_finish_and_ack(void)
{
    uint32_t key_bytes = 0U;
    uint32_t st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &key_bytes);

    tls_qkd_status(st);
    if (st != SECURE_QKD_OK) {
        return -1;
    }
    s_state = TLS_ST_WRITE_ACK;
    return 0;
}

static int tls_write_se_ok(void)
{
    static const char line[] = "SE_OK\n";

    return tls_write_all((const uint8_t *)line, sizeof(line) - 1U, s_ssl);
}

static uint32_t tls_otp_map_open_err(lt_ret_t ret)
{
    if (ret == SE_TROPIC_LT_OTP_EXHAUSTED) {
        return SECURE_OTP_ERR_EXHAUSTED;
    }
    if (ret == SE_TROPIC_LT_TAMPERED) {
        return SECURE_OTP_ERR_TAMPERED;
    }
    if (ret == LT_FAIL) {
        return SECURE_OTP_ERR_PIN;
    }
    return SECURE_OTP_ERR_FAIL;
}

static int tls_otp_fail_reply(uint32_t err_code)
{
    if (secure_otp_encode_err(err_code, s_otp_tx) != 0) {
        return -1;
    }
    s_otp_tx_len = 8U;
    s_otp_tx_off = 0U;
    s_otp_err = 1U;
    s_otp_count_written = 1U;
    se_usb_debug_puts("OTP err");
    return 0;
}

static int tls_otp_flush_reply(void)
{
    while (s_otp_tx_off < s_otp_tx_len) {
        uint32_t chunk = (uint32_t)s_otp_tx_len - (uint32_t)s_otp_tx_off;
        int n;

        if (chunk > TLS_WRITE_CHUNK) {
            chunk = TLS_WRITE_CHUNK;
        }
        n = wolfSSL_write(s_ssl, s_otp_tx + s_otp_tx_off, (int)chunk);
        if (n <= 0) {
            int err = wolfSSL_get_error(s_ssl, n);

            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                return 0;
            }
            return -1;
        }
        s_otp_tx_off = (uint16_t)(s_otp_tx_off + (uint16_t)n);
    }
    return 1;
}

static int tls_otp_open_xor(uint32_t *err_out)
{
    const uint8_t *pin;
    uint8_t pin_len = 0U;
    uint32_t msg_len;
    uint32_t n_pads;
    se_nv_otp_dir_t dir;
    lt_handle_t *h;
    lt_ret_t ret;
    uint8_t decrypt;

    if (err_out != NULL) {
        *err_out = SECURE_OTP_ERR_FAIL;
    }
    pin = secure_otp_request_pin(&pin_len);
    decrypt = (s_mode == SECURE_TLS_MODE_DECRYPT) ? 1U : 0U;
    msg_len = secure_otp_encrypt_msg_len();
    n_pads = secure_otp_decrypt_n_pads();
    if ((pin == NULL) || (pin_len == 0U) ||
        ((decrypt == 0U) && (msg_len == 0U)) ||
        ((decrypt != 0U) && (n_pads == 0U))) {
        return -1;
    }
    if (se_tropic_init_session() != SE_TROPIC_OK) {
        return -1;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return -1;
    }
    dir = (decrypt != 0U) ? SE_NV_OTP_DECRYPT : SE_NV_OTP_ENCRYPT;
    if (decrypt != 0U) {
        ret = se_tropic_otp_xor_open(h, pin, pin_len, NULL, 0U, dir, 0U, n_pads);
    } else {
        ret = se_tropic_otp_xor_open(h, pin, pin_len, NULL, 0U, dir, msg_len, 0U);
    }
    if (ret != LT_OK) {
        se_tropic_otp_xor_close();
        if (err_out != NULL) {
            *err_out = tls_otp_map_open_err(ret);
        }
        return -1;
    }
    if (decrypt != 0U) {
        secure_otp_decrypt_begin_ciphertext(se_tropic_otp_xor_pad_max(), n_pads);
    } else {
        secure_otp_encrypt_begin_plaintext(se_tropic_otp_xor_pad_max(), msg_len);
    }
    return 0;
}

/* Keep -Os; do not let GCC rewrite the copy as libc memmove (~50 B FLASH). */
#pragma GCC push_options
#pragma GCC optimize ("Os", "no-tree-loop-distribute-patterns")
static int tls_otp_save_leftover(const uint8_t *chunk, uint32_t len)
{
    uint32_t i;

    if (len == 0U) {
        s_otp_rest_len = 0U;
        return 0;
    }
    if (len > sizeof(s_otp_rest)) {
        s_otp_rest_len = 0U;
        return -1;
    }
    for (i = 0U; i < len; i++) {
        s_otp_rest[i] = chunk[i];
    }
    s_otp_rest_len = len;
    return 0;
}
#pragma GCC pop_options

static int tls_otp_xor_into_reply(void)
{
    uint8_t *chunk;
    uint8_t *out;
    uint16_t take = 0U;
    uint16_t logical = 0U;
    const uint16_t *req = NULL;
    uint16_t req_slot;
    uint32_t written = 0U;
    uint32_t hdr = 0U;
    lt_handle_t *h;
    lt_ret_t ret;

    chunk = secure_otp_pad_payload(&take);
    if ((chunk == NULL) || (take == 0U)) {
        return -1;
    }
    h = se_tropic_handle();
    if (h == NULL) {
        return -1;
    }
    if (s_mode == SECURE_TLS_MODE_DECRYPT) {
        req_slot = secure_otp_decrypt_pad_slot();
        req = &req_slot;
    }
    ret = se_tropic_otp_xor_pad(h, req, chunk, take, chunk, &logical, NULL);
    if (ret != LT_OK) {
        return -1;
    }
    out = s_otp_tx;
    s_otp_tx_len = 0U;
    s_otp_tx_off = 0U;
    if (s_otp_count_written == 0U) {
        if (secure_otp_encode_n_pads(se_tropic_otp_xor_pads_needed(), out) != 0) {
            return -1;
        }
        hdr = 4U;
        s_otp_count_written = 1U;
    }
    if (secure_otp_encode_pad((s_mode == SECURE_TLS_MODE_DECRYPT) ? 1U : 0U, logical, chunk, take,
                              out + hdr, (uint32_t)sizeof(s_otp_tx) - hdr, &written) != 0) {
        return -1;
    }
    s_otp_tx_len = (uint16_t)(hdr + written);
    return 0;
}

/** 0 = need more, 1 = record ready to write, -1 = fail. */
static int tls_otp_parse_incoming(const uint8_t *data, uint32_t len)
{
    uint32_t consumed = 0U;
    uint32_t st;

    if (se_tropic_otp_xor_pad_max() == 0U) {
        if (s_mode == SECURE_TLS_MODE_DECRYPT) {
            st = secure_otp_decrypt_parse_request(data, len, &consumed);
        } else {
            st = secure_otp_encrypt_parse_request(data, len, &consumed);
        }
        if (st == SECURE_OTP_REQ_COMPLETE) {
            uint32_t err = SECURE_OTP_ERR_FAIL;

            if (tls_otp_open_xor(&err) != 0) {
                if (tls_otp_fail_reply(err) != 0) {
                    return -1;
                }
                return 1;
            }
            data += consumed;
            len -= consumed;
            if (len == 0U) {
                return 0;
            }
        } else if (st != SECURE_OTP_REQ_OK) {
            se_usb_debug_puts("OTP parse");
            if (tls_otp_fail_reply(SECURE_OTP_ERR_PARSE) != 0) {
                return -1;
            }
            return 1;
        } else {
            return 0;
        }
    }

    st = secure_otp_read_pad(data, len, &consumed);
    if (st == SECURE_OTP_PAD_READY) {
        if (tls_otp_save_leftover(data + consumed, len - consumed) != 0) {
            return -1;
        }
        if (tls_otp_xor_into_reply() != 0) {
            se_usb_debug_puts("OTP xor fail");
            if (s_otp_count_written == 0U) {
                if (tls_otp_fail_reply(SECURE_OTP_ERR_FAIL) != 0) {
                    return -1;
                }
                return 1;
            }
            return -1;
        }
        return 1;
    }
    if (st != SECURE_OTP_REQ_OK) {
        se_usb_debug_puts("OTP parse");
        if (s_otp_count_written == 0U) {
            if (tls_otp_fail_reply(SECURE_OTP_ERR_PARSE) != 0) {
                return -1;
            }
            return 1;
        }
        return -1;
    }
    wc_ForceZero(s_otp_rest, s_otp_rest_len);
    s_otp_rest_len = 0U;
    return 0;
}

void se_tls_service_once(void)
{
    int err;
    int n;

    if (s_state == TLS_ST_IDLE) {
        if ((s_mode == 0U) || (se_time_is_synced() == 0)) {
            return;
        }
        se_usb_debug_puts("trying TLS");
        if (tls_start() != 0) {
            se_tls_abort();
        }
        return;
    }

    if (s_state == TLS_ST_DONE) {
        se_usb_debug_puts("TLS session ok");
        tls_wipe_mode();
        s_state = TLS_ST_IDLE;
        return;
    }

    if (s_ssl == NULL) {
        se_tls_abort();
        return;
    }

    switch (s_state) {
    case TLS_ST_HANDSHAKE:
        n = wolfSSL_connect(s_ssl);
        if (n == WOLFSSL_SUCCESS) {
            if (s_mode == SECURE_TLS_MODE_MANAGE) {
                if (se_tls_user_pin_peer(s_ssl) != 0) {
                    se_usb_debug_puts("TLS failed: user key mismatch");
                    se_tls_abort();
                    break;
                }
                se_usb_debug_puts("handshake ok, manage");
                s_manage_got = 0U;
                s_state = TLS_ST_READ_MANAGE;
                break;
            }
            {
                int exported = wolfSSL_export_keying_material(s_ssl, s_exporter,
                                                              SE_TROPIC_EXPORTER_LEN,
                                                              SE_TROPIC_EXPORTER_LABEL,
                                                              SE_TROPIC_EXPORTER_LABEL_LEN,
                                                              NULL, 0, 0);
                wolfSSL_FreeArrays(s_ssl);
                if (exported != WOLFSSL_SUCCESS) {
                    se_usb_debug_puts("TLS exporter failed");
                    se_tls_abort();
                    break;
                }
            }
            if ((s_mode != SECURE_TLS_MODE_PROVISION) && (se_tls_user_pin_peer(s_ssl) != 0)) {
                se_usb_debug_puts("TLS failed: user key mismatch");
                se_tls_abort();
                break;
            }
            if (s_mode == SECURE_TLS_MODE_PROVISION) {
                se_usb_debug_puts("handshake ok, provision");
                s_state = TLS_ST_WRITE_UPLINK;
            } else if (s_mode == SECURE_TLS_MODE_ENCRYPT) {
                se_usb_debug_puts("handshake ok, waiting plaintext");
                s_state = TLS_ST_READ_OTP;
            } else if (s_mode == SECURE_TLS_MODE_DECRYPT) {
                se_usb_debug_puts("handshake ok, waiting ciphertext");
                s_state = TLS_ST_READ_OTP;
            } else {
                se_tls_abort();
            }
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            se_tls_abort();
        }
        break;

    case TLS_ST_WRITE_UPLINK:
        if (se_tropic_session_uplink(s_exporter, tls_write_all, s_ssl) != 0) {
            se_tls_abort();
            break;
        }
        se_usb_debug_puts("report sent, reading response");
        s_state = TLS_ST_READ_RESP;
        break;

    case TLS_ST_READ_RESP: {
        uint8_t chunk[TLS_APP_READ_CHUNK];
        uint32_t st;

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            st = secure_qkd_ingest(chunk, (uint32_t)n, SECURE_QKD_INGEST_CHUNK, NULL);
            wc_ForceZero(chunk, sizeof(chunk));
            if (st != SECURE_QKD_OK) {
                tls_qkd_status(st);
                se_tls_abort();
                break;
            }
            if (secure_qkd_ready_to_finish() != 0U) {
                if (tls_qkd_finish_and_ack() != 0) {
                    se_tls_abort();
                }
            }
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            break;
        }
        if (tls_qkd_finish_and_ack() != 0) {
            se_tls_abort();
        }
        break;
    }

    case TLS_ST_WRITE_ACK:
        if (tls_write_se_ok() != 0) {
            se_tls_abort();
            break;
        }
        se_usb_debug_puts("SE_OK sent");
        s_state = TLS_ST_SHUTDOWN;
        break;

    case TLS_ST_READ_OTP: {
        uint8_t chunk[TLS_APP_READ_CHUNK];
        int fed;

        if (s_otp_rest_len > 0U) {
            uint32_t rest_len = s_otp_rest_len;

            s_otp_rest_len = 0U;
            fed = tls_otp_parse_incoming(s_otp_rest, rest_len);
            if (s_otp_rest_len < rest_len) {
                wc_ForceZero(s_otp_rest + s_otp_rest_len, rest_len - s_otp_rest_len);
            }
            if (fed < 0) {
                se_tls_abort();
            } else if (fed > 0) {
                s_state = TLS_ST_WRITE_OTP;
            }
            break;
        }
        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            fed = tls_otp_parse_incoming(chunk, (uint32_t)n);
            wc_ForceZero(chunk, sizeof(chunk));
            if (fed < 0) {
                se_tls_abort();
            } else if (fed > 0) {
                s_state = TLS_ST_WRITE_OTP;
            }
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            break;
        }
        se_usb_debug_puts("OTP closed early");
        se_tls_abort();
        break;
    }

    case TLS_ST_WRITE_OTP: {
        int wr = tls_otp_flush_reply();

        if (wr < 0) {
            se_tls_abort();
            break;
        }
        if (wr == 0) {
            break;
        }
        wc_ForceZero(s_otp_tx, s_otp_tx_len);
        s_otp_tx_len = 0U;
        s_otp_tx_off = 0U;
        secure_otp_pad_done();
        if ((s_otp_err != 0U) || (se_tropic_otp_xor_bytes_left() == 0U)) {
            se_usb_debug_puts((s_otp_err != 0U) ? "otp err sent" : "otp sent");
            tls_wipe_otp();
            s_state = TLS_ST_SHUTDOWN;
        } else {
            s_state = TLS_ST_READ_OTP;
        }
        break;
    }

    case TLS_ST_READ_MANAGE: {
        uint8_t chunk[TLS_APP_READ_CHUNK];
        uint8_t *buf = se_manage_buf();
        uint32_t cap = se_manage_buf_cap();
        uint32_t need;
        uint32_t st;
        char msg[SE_MANAGE_MSG_MAX];
        size_t msg_n;

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            if ((s_manage_got + (uint32_t)n) > cap) {
                wc_ForceZero(chunk, sizeof(chunk));
                se_tls_abort();
                break;
            }
            (void)memcpy(buf + s_manage_got, chunk, (size_t)n);
            s_manage_got += (uint32_t)n;
            wc_ForceZero(chunk, sizeof(chunk));
            need = se_manage_req_need(buf, s_manage_got);
            if (need == 0xffffffffu) {
                se_tls_abort();
                break;
            }
            if ((need == 0U) || (s_manage_got < need)) {
                break;
            }
            if (s_manage_got != need) {
                se_tls_abort();
                break;
            }
            msg[0] = '\0';
            st = se_manage_apply_buf(buf, need, msg, (uint16_t)sizeof(msg));
            msg_n = strlen(msg);
            if (msg_n > (size_t)SE_MANAGE_MSG_MAX - 1U) {
                msg_n = (size_t)SE_MANAGE_MSG_MAX - 1U;
            }
            s_manage_tx[0] = (uint8_t)st;
            se_put_u16le(s_manage_tx + 1U, (uint16_t)msg_n);
            if (msg_n > 0U) {
                (void)memcpy(s_manage_tx + 3U, msg, msg_n);
            }
            s_manage_tx_len = (uint16_t)(3U + msg_n);
            s_manage_tx_off = 0U;
            se_manage_buf_wipe();
            s_manage_got = 0U;
            s_state = TLS_ST_WRITE_MANAGE;
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            break;
        }
        se_tls_abort();
        break;
    }

    case TLS_ST_WRITE_MANAGE:
        if (tls_write_all(s_manage_tx + s_manage_tx_off,
                          (uint32_t)s_manage_tx_len - (uint32_t)s_manage_tx_off, s_ssl) != 0) {
            se_tls_abort();
            break;
        }
        tls_wipe_manage();
        s_state = TLS_ST_SHUTDOWN;
        break;

    case TLS_ST_SHUTDOWN:
        if (s_ssl == NULL) {
            tls_session_close();
            break;
        }
        n = wolfSSL_shutdown(s_ssl);
        if (n == WOLFSSL_SUCCESS) {
            tls_session_close();
            break;
        }
        if (tls_shutdown_peer_pending(n) != 0) {
            uint32_t now = HAL_GetTick();

            if (s_shutdown_tick == 0U) {
                s_shutdown_tick = (now == 0U) ? 1U : now;
                break;
            }
            if ((now - s_shutdown_tick) < TLS_SHUTDOWN_MS) {
                break;
            }
            se_usb_debug_puts("TLS shutdown timeout");
            tls_session_close();
            break;
        }
        se_usb_debug_puts("TLS shutdown failed");
        se_tls_abort();
        break;

    case TLS_ST_ERROR:
    default:
        se_tls_abort();
        break;
    }
}
