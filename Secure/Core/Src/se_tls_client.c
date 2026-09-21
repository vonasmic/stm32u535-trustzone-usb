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
 * chunks only. OTP consume is secure_otp_session_feed (TLS only pumps I/O).
 * After the last application record the client sends close_notify and stays
 * in TLS until the peer's close_notify (SAE or UserApp), then returns to ASCII.
 */
#include "se_tls_client.h"
#include "se_tls_nsc.h"
#include "se_tropic_session.h"
#include "se_tropic.h"
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
    TLS_ST_ERROR
} TlsState;

static TlsState s_state = TLS_ST_IDLE;
static uint32_t s_mode;
static WOLFSSL_CTX *s_ctx;
static WOLFSSL *s_ssl;
static uint8_t s_exporter[SE_TROPIC_EXPORTER_LEN];
static uint8_t s_tls_der[SE_CREDS_DER_MAX];
static uint32_t s_manage_got;
static uint8_t s_manage_tx[SE_MANAGE_RSP_MAX];
static uint16_t s_manage_tx_len;
static uint16_t s_manage_tx_off;
static uint32_t s_shutdown_tick;

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
    secure_otp_session_reset();
    s_shutdown_tick = 0U;
}

static void tls_session_close(void)
{
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
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
        return -1;
    }
    if (wolfSSL_CTX_load_verify_buffer(ctx, s_tls_der, (long)ca_len, WOLFSSL_FILETYPE_ASN1) !=
        WOLFSSL_SUCCESS) {
        return -1;
    }
    return 0;
}

static int tls_start(void)
{
    uint16_t cert_len = 0U;

    s_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (s_ctx == NULL) {
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
            return -1;
        }
        if (wolfSSL_CTX_use_certificate_buffer(s_ctx, s_tls_der, (long)cert_len,
                                               WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            return -1;
        }
        if (secure_client_key_load(s_ctx) != 0) {
            return -1;
        }
    }

    wolfSSL_CTX_SetIORecv(s_ctx, se_tls_embed_recv);
    wolfSSL_CTX_SetIOSend(s_ctx, (CallbackIOSend)se_tls_embed_send);

    s_ssl = wolfSSL_new(s_ctx);
    if (s_ssl == NULL) {
        return -1;
    }

    wolfSSL_SetIOReadCtx(s_ssl, NULL);
    wolfSSL_SetIOWriteCtx(s_ssl, NULL);

    if (tls_setup_groups(s_ctx, s_ssl) != 0) {
        return -1;
    }

    /* Exporter (provision) refuses unless handshake arrays are retained. */
    if (s_mode != SECURE_TLS_MODE_MANAGE) {
        wolfSSL_KeepArrays(s_ssl);
    }

    s_state = TLS_ST_HANDSHAKE;
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
            return -1;
        }
    } else if (mode == SECURE_TLS_MODE_MANAGE) {
        if (se_nv_has_owner() == 0) {
            return -1;
        }
    } else if (se_ready_encrypt() == 0) {
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
    tls_wipe_ssl();
}

void se_tls_reset_quiet(void)
{
    secure_qkd_discard();
    tls_wipe_mode();
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    s_state = TLS_ST_IDLE;
}

void se_tls_abort(void)
{
    secure_qkd_discard();
    tls_wipe_mode();
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    se_usb_failed();
    s_state = TLS_ST_IDLE;
}

static int tls_qkd_finish_and_ack(void)
{
    uint32_t key_bytes = 0U;
    uint32_t st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &key_bytes);

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

static int tls_otp_flush_reply(void)
{
    for (;;) {
        uint16_t left = 0U;
        const uint8_t *p = secure_otp_session_tx(&left);
        uint32_t chunk;
        int n;

        if ((p == NULL) || (left == 0U)) {
            return 1;
        }
        chunk = left;
        if (chunk > TLS_WRITE_CHUNK) {
            chunk = TLS_WRITE_CHUNK;
        }
        n = wolfSSL_write(s_ssl, p, (int)chunk);
        if (n <= 0) {
            int err = wolfSSL_get_error(s_ssl, n);

            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                return 0;
            }
            return -1;
        }
        secure_otp_session_tx_consumed((uint16_t)n);
    }
}

static void tls_app_provision_enter(void)
{
    s_state = TLS_ST_WRITE_UPLINK;
}

static void tls_app_encrypt_enter(void)
{
    if (se_tls_user_pin_peer(s_ssl) != 0) {
        se_tls_abort();
        return;
    }
    secure_otp_session_begin(0U);
    s_state = TLS_ST_READ_OTP;
}

static void tls_app_decrypt_enter(void)
{
    if (se_tls_user_pin_peer(s_ssl) != 0) {
        se_tls_abort();
        return;
    }
    secure_otp_session_begin(1U);
    s_state = TLS_ST_READ_OTP;
}

static void tls_app_manage_enter(void)
{
    if (se_tls_user_pin_peer(s_ssl) != 0) {
        se_tls_abort();
        return;
    }
    s_manage_got = 0U;
    s_state = TLS_ST_READ_MANAGE;
}

static void tls_app_provision_service(void)
{
    int n;
    int err;

    switch (s_state) {
    case TLS_ST_WRITE_UPLINK:
        if (se_tropic_session_uplink(s_exporter, tls_write_all, s_ssl) != 0) {
            se_tls_abort();
            break;
        }
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
        s_state = TLS_ST_SHUTDOWN;
        break;

    default:
        se_tls_abort();
        break;
    }
}

static void tls_app_otp_service(void)
{
    int n;
    int err;

    switch (s_state) {
    case TLS_ST_READ_OTP: {
        uint8_t chunk[TLS_APP_READ_CHUNK];
        int fed;

        if (secure_otp_session_has_in() != 0) {
            fed = secure_otp_session_feed(NULL, 0U);
            if (fed < 0) {
                se_tls_abort();
            } else if (fed == SECURE_OTP_SESSION_REPLY) {
                s_state = TLS_ST_WRITE_OTP;
            }
            break;
        }
        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            fed = secure_otp_session_feed(chunk, (uint32_t)n);
            wc_ForceZero(chunk, sizeof(chunk));
            if (fed < 0) {
                se_tls_abort();
            } else if (fed == SECURE_OTP_SESSION_REPLY) {
                s_state = TLS_ST_WRITE_OTP;
            }
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            break;
        }
        se_tls_abort();
        break;
    }

    case TLS_ST_WRITE_OTP: {
        int wr = tls_otp_flush_reply();
        int done;

        if (wr < 0) {
            se_tls_abort();
            break;
        }
        if (wr == 0) {
            break;
        }
        done = secure_otp_session_tx_complete();
        if (done < 0) {
            se_tls_abort();
            break;
        }
        if (done == SECURE_OTP_SESSION_REPLY) {
            break;
        }
        if (done == SECURE_OTP_SESSION_DONE) {
            secure_otp_session_reset();
            s_state = TLS_ST_SHUTDOWN;
        } else {
            s_state = TLS_ST_READ_OTP;
        }
        break;
    }

    default:
        se_tls_abort();
        break;
    }
}

static void tls_app_manage_service(void)
{
    int n;
    int err;

    switch (s_state) {
    case TLS_ST_READ_MANAGE: {
        uint8_t chunk[TLS_APP_READ_CHUNK];
        int ready;
        uint32_t st;
        char msg[SE_MANAGE_MSG_MAX];

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            ready = se_manage_accum(&s_manage_got, chunk, (uint32_t)n, se_manage_req_need);
            wc_ForceZero(chunk, sizeof(chunk));
            if (ready < 0) {
                se_tls_abort();
                break;
            }
            if (ready != SE_FRAME_COMPLETE) {
                break;
            }
            msg[0] = '\0';
            st = se_manage_apply_buf(se_manage_buf(), s_manage_got, msg, (uint16_t)sizeof(msg));
            s_manage_tx_len = se_manage_rsp_encode(s_manage_tx, (uint16_t)sizeof(s_manage_tx),
                                                   (uint8_t)st, msg);
            if (s_manage_tx_len == 0U) {
                se_tls_abort();
                break;
            }
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

    default:
        se_tls_abort();
        break;
    }
}

typedef struct {
    void (*enter)(void);
    void (*service)(void);
} tls_app_t;

static const tls_app_t tls_app[] = {
    { NULL, NULL },
    { tls_app_provision_enter, tls_app_provision_service },
    { tls_app_encrypt_enter, tls_app_otp_service },
    { tls_app_decrypt_enter, tls_app_otp_service },
    { tls_app_manage_enter, tls_app_manage_service },
};

static const tls_app_t *tls_app_get(void)
{
    if ((s_mode == 0U) || (s_mode >= (uint32_t)(sizeof(tls_app) / sizeof(tls_app[0])))) {
        return NULL;
    }
    if ((tls_app[s_mode].enter == NULL) || (tls_app[s_mode].service == NULL)) {
        return NULL;
    }
    return &tls_app[s_mode];
}

void se_tls_service_once(void)
{
    int err;
    int n;
    const tls_app_t *app;

    if (s_state == TLS_ST_IDLE) {
        if ((s_mode == 0U) || (se_time_is_synced() == 0)) {
            return;
        }
        if (tls_start() != 0) {
            se_tls_abort();
        }
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
            if (s_mode != SECURE_TLS_MODE_MANAGE) {
                int exported = wolfSSL_export_keying_material(s_ssl, s_exporter,
                                                              SE_TROPIC_EXPORTER_LEN,
                                                              SE_TROPIC_EXPORTER_LABEL,
                                                              SE_TROPIC_EXPORTER_LABEL_LEN,
                                                              NULL, 0, 0);
                wolfSSL_FreeArrays(s_ssl);
                if (exported != WOLFSSL_SUCCESS) {
                    se_tls_abort();
                    break;
                }
            }
            app = tls_app_get();
            if (app == NULL) {
                se_tls_abort();
                break;
            }
            app->enter();
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            se_tls_abort();
        }
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
            tls_session_close();
            break;
        }
        se_tls_abort();
        break;

    case TLS_ST_ERROR:
        se_tls_abort();
        break;

    default:
        app = tls_app_get();
        if (app == NULL) {
            se_tls_abort();
            break;
        }
        app->service();
        break;
    }
}
