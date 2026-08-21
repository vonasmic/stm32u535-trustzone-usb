/**
 * @file    tls_json_client.c
 * @brief   TLS 1.3 mTLS JSON client over USB (mirrors tls_client_json_payload)
 */
#include "tls_json_client.h"
#include "tls_usb_io.h"
#include "fw_creds.h"
#include "se_tls_nsc.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"

#define TLS_APP_READ_CHUNK   512
#define TLS_APP_MAX_TOTAL    8192
#define TLS_WRITE_CHUNK      1024

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
static uint32_t s_json_off;
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
    int groups[] = {
        WOLFSSL_ML_KEM_768
    };
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
    static const unsigned char key_id[] = {
        0x53, 0x45, 0x5f, 0x74, 0x6c, 0x73, 0x5f, 0x63, 0x6c, 0x69
    };

    s_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (s_ctx == NULL) {
        return -1;
    }

    wolfSSL_CTX_SetMinVersion(s_ctx, WOLFSSL_TLSV1_3);
    (void)wolfSSL_CTX_set_cipher_list(s_ctx, "TLS13-AES256-GCM-SHA384");

    if (wolfSSL_CTX_load_verify_buffer(s_ctx, fw_root_ca_der, (long)fw_root_ca_der_len,
                                       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        return -1;
    }
    if (wolfSSL_CTX_use_certificate_buffer(s_ctx, fw_client_cert_der,
            (long)fw_client_cert_der_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        return -1;
    }
    if (wolfSSL_CTX_use_PrivateKey_Id(s_ctx, key_id, (long)sizeof(key_id),
                                      WC_USE_DEVID) != WOLFSSL_SUCCESS) {
        return -1;
    }

    wolfSSL_CTX_set_verify(s_ctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    wolfSSL_CTX_SetIORecv(s_ctx, tls_usb_embed_recv);
    wolfSSL_CTX_SetIOSend(s_ctx, (CallbackIOSend)tls_usb_embed_send);

    s_ssl = wolfSSL_new(s_ctx);
    if (s_ssl == NULL) {
        return -1;
    }

    wolfSSL_SetIOReadCtx(s_ssl, tls_usb_rx_ring());
    wolfSSL_SetIOWriteCtx(s_ssl, NULL);

    if (tls_json_setup_groups(s_ctx, s_ssl) != 0) {
        return -1;
    }

    s_json_off = 0U;
    s_app_total = 0U;
    s_state = TLS_JS_HANDSHAKE;
    return 0;
}

void tls_json_client_init(void)
{
    s_state = TLS_JS_IDLE;
    tls_json_wipe_ssl();
}

void tls_json_client_abort(void)
{
    (void)SECURE_QkdIngest_nsc_call(NULL, 0U, SECURE_QKD_INGEST_DISCARD, NULL);
    tls_json_wipe_ssl();
    tls_usb_io_reset();
    s_state = TLS_JS_IDLE;
}

void tls_json_client_poll(void)
{
    int err;
    int n;

    tls_usb_poll();

    if (s_state == TLS_JS_IDLE) {
        if (tls_usb_connected() && tls_usb_dtr_asserted()) {
            if (tls_json_start() != 0) {
                s_state = TLS_JS_ERROR;
            }
        }
        return;
    }

    if (s_ssl == NULL) {
        s_state = TLS_JS_ERROR;
    }

    switch (s_state) {
    case TLS_JS_HANDSHAKE:
        err = wolfSSL_connect(s_ssl);
        if (err == WOLFSSL_SUCCESS) {
            s_state = TLS_JS_WRITE_JSON;
            break;
        }
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            s_state = TLS_JS_ERROR;
        }
        break;

    case TLS_JS_WRITE_JSON:
        if (tls_json_write_all(s_ssl, fw_json_payload, fw_json_payload_len) != 0) {
            s_state = TLS_JS_ERROR;
            break;
        }
        s_state = TLS_JS_READ_RESP;
        break;

    case TLS_JS_READ_RESP: {
        uint8_t chunk[TLS_APP_READ_CHUNK];

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            if ((s_app_total + (uint32_t)n) > TLS_APP_MAX_TOTAL) {
                (void)SECURE_QkdIngest_nsc_call(NULL, 0U, SECURE_QKD_INGEST_DISCARD, NULL);
                s_state = TLS_JS_ERROR;
                wc_ForceZero(chunk, sizeof(chunk));
                break;
            }
            s_app_total += (uint32_t)n;
            if (SECURE_QkdIngest_nsc_call(chunk, (uint32_t)n, SECURE_QKD_INGEST_CHUNK,
                                          NULL) != SECURE_QKD_OK) {
                wc_ForceZero(chunk, sizeof(chunk));
                s_state = TLS_JS_ERROR;
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
            uint32_t st = SECURE_QkdIngest_nsc_call(NULL, 0U, SECURE_QKD_INGEST_FINISH,
                                                    &count);
            (void)count;
            if (st != SECURE_QKD_OK && st != SECURE_QKD_PARSE) {
                /* empty response is OK (zero strings) */
            }
            s_state = TLS_JS_SHUTDOWN;
        }
        break;
    }

    case TLS_JS_SHUTDOWN:
        (void)wolfSSL_shutdown(s_ssl);
        tls_json_wipe_ssl();
        tls_usb_io_reset();
        s_state = TLS_JS_DONE;
        break;

    case TLS_JS_DONE:
        s_state = TLS_JS_IDLE;
        break;

    case TLS_JS_ERROR:
    default:
        tls_json_client_abort();
        break;
    }
}
