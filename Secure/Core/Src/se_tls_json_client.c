/**
 * @file    se_tls_json_client.c
 * @brief   TLS 1.3 mTLS JSON client (Secure world, USB rings via se_usb_tls)
 */
#include "se_tls_json_client.h"
#include "se_usb_tls.h"
#include "se_time.h"
#include "secure_client_key.h"
#include "secure_qkd_ingest.h"
#include "fw_creds.h"
#include "main.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"

#define TLS_APP_READ_CHUNK   512
#define TLS_APP_MAX_TOTAL    8192
#define TLS_WRITE_CHUNK      1024

extern int se_tls_embed_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
extern int se_tls_embed_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

typedef enum {
    TLS_JS_IDLE = 0,
    TLS_JS_HANDSHAKE,
    TLS_JS_WRITE_JSON,
    TLS_JS_READ_RESP,
    TLS_JS_SHUTDOWN,
    TLS_JS_DONE,
    TLS_JS_ERROR
} TlsJsonState;

static TlsJsonState s_state = TLS_JS_IDLE;
static WOLFSSL_CTX *s_ctx;
static WOLFSSL *s_ssl;
static uint32_t s_app_total;

static void tls_json_wipe_ssl(void)
{
    if (s_ssl != NULL) {
        wolfSSL_free(s_ssl);
        s_ssl = NULL;
    }
    if (s_ctx != NULL) {
        wolfSSL_CTX_free(s_ctx);
        s_ctx = NULL;
    }
}

static int tls_json_setup_groups(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
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

static int tls_json_write_all(WOLFSSL *ssl, const uint8_t *data, uint32_t len)
{
    uint32_t off = 0U;

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

static int tls_json_start(void)
{
    s_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (s_ctx == NULL) {
        se_usb_debug_printf("TLS setup: CTX_new failed");
        return -1;
    }

    wolfSSL_CTX_SetMinVersion(s_ctx, WOLFSSL_TLSV1_3);
    (void)wolfSSL_CTX_set_cipher_list(s_ctx, "TLS13-AES256-GCM-SHA384");

    if (wolfSSL_CTX_load_verify_buffer(s_ctx, fw_root_ca_der, (long)fw_root_ca_der_len,
                                       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        se_usb_debug_printf("TLS setup: load CA failed");
        return -1;
    }
    if (wolfSSL_CTX_use_certificate_buffer(s_ctx, fw_client_cert_der,
            (long)fw_client_cert_der_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        se_usb_debug_printf("TLS setup: load client cert failed");
        return -1;
    }
    if (secure_client_key_load(s_ctx) != 0) {
        se_usb_debug_printf("TLS setup: unwrap/load key failed");
        return -1;
    }

    wolfSSL_CTX_set_verify(s_ctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    wolfSSL_CTX_SetIORecv(s_ctx, se_tls_embed_recv);
    wolfSSL_CTX_SetIOSend(s_ctx, (CallbackIOSend)se_tls_embed_send);

    s_ssl = wolfSSL_new(s_ctx);
    if (s_ssl == NULL) {
        se_usb_debug_printf("TLS setup: SSL_new failed");
        return -1;
    }

    wolfSSL_SetIOReadCtx(s_ssl, NULL);
    wolfSSL_SetIOWriteCtx(s_ssl, NULL);

    if (tls_json_setup_groups(s_ctx, s_ssl) != 0) {
        se_usb_debug_printf("TLS setup: ML-KEM group failed");
        return -1;
    }

    s_app_total = 0U;
    s_state = TLS_JS_HANDSHAKE;
    se_usb_debug_printf("sending handshake");
    return 0;
}

void se_tls_json_init(void)
{
    s_state = TLS_JS_IDLE;
    tls_json_wipe_ssl();
}

void se_tls_json_reset_quiet(void)
{
    secure_qkd_discard();
    tls_json_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    s_state = TLS_JS_IDLE;
}

void se_tls_json_abort(void)
{
    int ssl_err = 0;

    if (s_ssl != NULL) {
        ssl_err = wolfSSL_get_error(s_ssl, -1);
    }
    secure_qkd_discard();
    tls_json_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    if (ssl_err == ASN_BEFORE_DATE_E) {
        se_usb_debug_printf("TLS failed: cert not yet valid (RTC)");
    } else if (ssl_err == ASN_AFTER_DATE_E) {
        se_usb_debug_printf("TLS failed: cert expired (RTC)");
    } else if (ssl_err == VERSION_ERROR) {
        se_usb_debug_printf("TLS failed: record version (restart bridge)");
    } else if (ssl_err == 0) {
        se_usb_debug_printf("TLS aborted");
    } else {
        se_usb_debug_printf("TLS failed err=%d", ssl_err);
    }
    /* Stay idle until NonSecure sends a new TIME= and calls Service again. */
    s_state = TLS_JS_IDLE;
}

void se_tls_json_service_once(void)
{
    int err;
    int n;

    if (s_state == TLS_JS_IDLE) {
        if (se_time_is_synced() == 0) {
            return;
        }
        se_usb_debug_printf("trying TLS");
        if (tls_json_start() != 0) {
            se_tls_json_abort();
        }
        return;
    }

    if (s_ssl == NULL) {
        se_tls_json_abort();
        return;
    }

    switch (s_state) {
    case TLS_JS_HANDSHAKE:
        n = wolfSSL_connect(s_ssl);
        if (n == WOLFSSL_SUCCESS) {
            se_usb_debug_printf("handshake ok, sending JSON");
            s_state = TLS_JS_WRITE_JSON;
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            se_tls_json_abort();
        }
        break;

    case TLS_JS_WRITE_JSON:
        if (tls_json_write_all(s_ssl, fw_json_payload, fw_json_payload_len) != 0) {
            se_tls_json_abort();
            break;
        }
        se_usb_debug_printf("JSON sent, reading response");
        s_state = TLS_JS_READ_RESP;
        break;

    case TLS_JS_READ_RESP: {
        uint8_t chunk[TLS_APP_READ_CHUNK];

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            if ((s_app_total + (uint32_t)n) > TLS_APP_MAX_TOTAL) {
                secure_qkd_discard();
                se_tls_json_abort();
                wc_ForceZero(chunk, sizeof(chunk));
                break;
            }
            s_app_total += (uint32_t)n;
            if (secure_qkd_ingest(chunk, (uint32_t)n, SECURE_QKD_INGEST_CHUNK,
                                  NULL) != SECURE_QKD_OK) {
                wc_ForceZero(chunk, sizeof(chunk));
                se_tls_json_abort();
                break;
            }
            wc_ForceZero(chunk, sizeof(chunk));
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            break;
        }
        {
            uint32_t count = 0U;
            (void)secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
            se_usb_debug_printf("response done, qkd=%lu", (unsigned long)count);
            s_state = TLS_JS_SHUTDOWN;
        }
        break;
    }

    case TLS_JS_SHUTDOWN:
        (void)wolfSSL_shutdown(s_ssl);
        tls_json_wipe_ssl();
        se_usb_tls_clear_rx();
        se_usb_tls_end_tls_wire();
        s_state = TLS_JS_DONE;
        break;

    case TLS_JS_DONE:
        se_usb_debug_printf("TLS session ok");
        se_time_clear_synced();
        s_state = TLS_JS_IDLE;
        break;

    case TLS_JS_ERROR:
    default:
        se_tls_json_abort();
        break;
    }
}
