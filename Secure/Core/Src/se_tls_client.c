/**
 * @file    se_tls_client.c
 * @brief   TLS 1.3 mTLS client I/O and session state machine
 *
 * NonSecure arms a mode (with Unix time) before handshake. Provision verifies the
 * SAE application CA, streams the session-bound uplink, erases QKD R-MEM slots
 * while SAE fetches keys, sends TROPIC_WIPE_FINISHED, then feeds downlink to
 * secure_qkd_ingest (KB progress every 10 KiB). Encrypt/decrypt verify the
 * client CA; encrypt waits for PIN+plaintext and decrypt for PIN plus the
 * encrypt OTP stream
 * (n_pads then slot/chunk records). Encrypt/decrypt also pin the TLS peer
 * SPKI to the home-PC user key embedded from certs/user/user-cert.pem.
 * Encrypt replies include slots. Decrypt replies are n_pads then plaintext
 * chunks only. OTP consume is secure_otp_session_feed (TLS only pumps I/O).
 * After the last application record the client flushes close_notify into the
 * USB TX ring, then frees the session. We do not wait for the peer's
 * close_notify — once our outbound records are queued, ASCII commands can run.
 * We only stall on WANT_WRITE (ring full) or the shutdown budget.
 */
#include "se_tls_client.h"
#include "se_tls_nsc.h"
#include "se_tropic_session.h"
#include "se_tropic.h"
#include "se_tropic_mlkem.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "se_usb_tls.h"
#include "se_time.h"
#include "secure_client_key.h"
#include "secure_qkd_ingest.h"
#include "secure_otp.h"
#include "se_tls_user.h"
#include "se_creds.h"
#include "se_ram.h"
#include "se_auth.h"
#include "se_device_id.h"
#include "se_manage.h"
#include "se_ram.h"
#include "main.h"
#include <string.h>
#ifdef SE_HOST_MODEL
#include <stdio.h>
#define SE_HOST_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define SE_HOST_LOG(...) ((void)0)
#endif
#include "wolfssl/ssl.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_port.h"

#define TLS_APP_READ_CHUNK 512
#define TLS_WRITE_CHUNK    1024
#define TLS_DL_PROGRESS_BYTES 10240u
#define TLS_LINE_MAX       32
/* One LV item is u16le length plus the value. Uplink v4 is the header, seven
 * fixed items, then up to SE_NV_PEER_MAX hash/name pairs. Built once: the
 * stream function zeros the exporter, so a WANT_WRITE retry would sign again
 * and emit a second envelope. */
#define TLS_UPLINK_ITEM(n) (2u + (n))
#define TLS_UPLINK_MAX (1u + 2u \
    + TLS_UPLINK_ITEM(64u) \
    + TLS_UPLINK_ITEM(64u) \
    + TLS_UPLINK_ITEM(SE_TROPIC_CLIENT_HASH_LEN) \
    + TLS_UPLINK_ITEM(2u) \
    + TLS_UPLINK_ITEM(2u) \
    + TLS_UPLINK_ITEM(SE_NV_FILL_ID_LEN) \
    + TLS_UPLINK_ITEM(SE_TROPIC_MLKEM_PK_LEN) \
    + (SE_NV_PEER_MAX * (TLS_UPLINK_ITEM(SE_NV_PEER_HASH_LEN) + TLS_UPLINK_ITEM(SE_NV_PEER_NAME_MAX))))
#define TLS_SHUTDOWN_MS    3000u
/* Backup if HAL_GetTick freezes (seen after long flash/Tropic work on U5). */
#define TLS_SHUTDOWN_POLLS_MAX 60000u

extern int se_tls_embed_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
extern int se_tls_embed_send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

typedef enum {
    TLS_ST_IDLE = 0,
    TLS_ST_HANDSHAKE,
    TLS_ST_WRITE_UPLINK,
    TLS_ST_WIPE_TROPIC,
    TLS_ST_WRITE_LINE,
    TLS_ST_READ_RESP,
    TLS_ST_READ_OTP,
    TLS_ST_WRITE_OTP,
    TLS_ST_READ_MANAGE,
    TLS_ST_WRITE_MANAGE,
    TLS_ST_SHUTDOWN,
    TLS_ST_ERROR
} TlsState;

volatile uint32_t se_tls_die;
volatile int se_tls_die_err;

static TlsState s_state = TLS_ST_IDLE;
__attribute__((used)) volatile uint32_t se_tls_state;
static uint32_t s_mode;
static WOLFSSL_CTX *s_ctx;
static WOLFSSL *s_ssl;
static uint8_t s_exporter[SE_TROPIC_EXPORTER_LEN];
static uint32_t s_manage_got;
static uint8_t s_manage_tx[SE_MANAGE_RSP_MAX];
static uint16_t s_manage_tx_len;
static uint16_t s_manage_tx_off;
static uint8_t s_uplink_tx[TLS_UPLINK_MAX];
static uint16_t s_uplink_tx_len;
static uint16_t s_uplink_tx_off;
static uint8_t s_uplink_ready;
static uint8_t s_line_tx[TLS_LINE_MAX];
static uint16_t s_line_tx_len;
static uint16_t s_line_tx_off;
static TlsState s_line_next;
static uint16_t s_wipe_slot;
static uint32_t s_dl_bytes;
static uint32_t s_shutdown_tick;
static uint32_t s_shutdown_polls;

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

static void tls_wipe_uplink(void)
{
    wc_ForceZero(s_uplink_tx, sizeof(s_uplink_tx));
    s_uplink_tx_len = 0U;
    s_uplink_tx_off = 0U;
    s_uplink_ready = 0U;
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
    tls_wipe_uplink();
    wc_ForceZero(s_line_tx, sizeof(s_line_tx));
    s_line_tx_len = 0U;
    s_line_tx_off = 0U;
    s_line_next = TLS_ST_IDLE;
    s_wipe_slot = 0U;
    s_dl_bytes = 0U;
    se_tropic_qkd_set_wiped(0U);
    secure_otp_session_reset();
    s_shutdown_tick = 0U;
    s_shutdown_polls = 0U;
    se_mem_session_end();
}

static void tls_session_close(void)
{
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    /* Keep manage reply / close_notify in TX; ASCII blocked until NS drains. */
    se_usb_tls_release_tls_wire();
    tls_wipe_mode();
    s_state = TLS_ST_IDLE;
    se_tls_state = (uint32_t)s_state;
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

static int tls_shutdown_timed_out(void)
{
    uint32_t now = HAL_GetTick();

    if (s_shutdown_tick == 0U) {
        s_shutdown_tick = (now == 0U) ? 1U : now;
        s_shutdown_polls = 0U;
        return 0;
    }
    if (s_shutdown_polls < 0xFFFFFFFFu) {
        s_shutdown_polls++;
    }
    if ((now - s_shutdown_tick) >= TLS_SHUTDOWN_MS) {
        return 1;
    }
    /* Tick stuck: still release the command pipe after enough service polls. */
    return (s_shutdown_polls >= TLS_SHUTDOWN_POLLS_MAX) ? 1 : 0;
}

static void tls_enter_shutdown(void)
{
    uint32_t now = HAL_GetTick();

    /* Flush our close_notify; do not pin the ASCII pipe on the peer forever. */
    s_shutdown_tick = (now == 0U) ? 1U : now;
    s_shutdown_polls = 0U;
    s_state = TLS_ST_SHUTDOWN;
    se_tls_state = (uint32_t)s_state;
}

/**
 * Unilateral close: flush close_notify (and any still-buffered app reply) into
 * the USB TX ring, then free. Do not wait for the peer's close_notify — that
 * only pinned the command pipe (CLIENT CSR after KEM INIT). Never se_tls_abort
 * here — that zeros TX and drops the manage/OTP reply.
 */
static void tls_shutdown_service(void)
{
    int n;
    int err;

    if (tls_shutdown_timed_out() != 0) {
        tls_session_close();
        return;
    }

    if (s_ssl == NULL) {
        tls_session_close();
        return;
    }

    /* Unread plaintext makes wolfSSL_shutdown skip emitting our close_notify. */
    if (wolfSSL_pending(s_ssl) > 0) {
        uint8_t junk[128];
        int pn = wolfSSL_read(s_ssl, junk, (int)sizeof(junk));

        wc_ForceZero(junk, sizeof(junk));
        if (pn > 0) {
            return;
        }
        if (pn < 0) {
            err = wolfSSL_get_error(s_ssl, pn);
            if (err == WOLFSSL_ERROR_WANT_WRITE) {
                return;
            }
            if (err != WOLFSSL_ERROR_WANT_READ) {
                se_tls_die = 9U;
                se_tls_die_err = err;
                tls_session_close();
                return;
            }
            /* WANT_READ on leftover plaintext: fall through and flush outbound. */
        }
    }

    n = wolfSSL_shutdown(s_ssl);
    if (n == WOLFSSL_SUCCESS) {
        tls_session_close();
        return;
    }
    if (tls_shutdown_peer_pending(n) != 0) {
        err = wolfSSL_get_error(s_ssl, n);
        /* Only block while our alert (or buffered reply) cannot enter the TX ring. */
        if (err == WOLFSSL_ERROR_WANT_WRITE) {
            return;
        }
        /* WANT_READ / NOT_DONE: outbound is queued — free; NS still drains wire==2. */
        tls_session_close();
        return;
    }
    se_tls_die = 10U;
    se_tls_die_err = wolfSSL_get_error(s_ssl, n);
    tls_session_close();
}

static int tls_setup_groups(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
    int groups[] = { WOLFSSL_ML_KEM_768 };

    (void)ctx;
    /* wolfSSL_new() already copied ctx->group while numGroups was still 0.
     * CTX_set_groups after that leaves ssl->numGroups at 0, and wolfSSL then
     * accepts every built-in group, including X25519. */
    if (wolfSSL_set_groups(ssl, groups, 1) != WOLFSSL_SUCCESS) {
        return -1;
    }
    if (wolfSSL_UseKeyShare(ssl, (word16)groups[0]) != WOLFSSL_SUCCESS) {
        return -1;
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
    uint8_t *der = se_der_scratch();
    uint16_t ca_len = 0U;
    int ok;

    if (se_creds_get_sae_ca(der, &ca_len, SE_CREDS_DER_MAX) != LT_OK) {
        return -1;
    }
    ok = (wolfSSL_CTX_load_verify_buffer(ctx, der, (long)ca_len, WOLFSSL_FILETYPE_ASN1) ==
          WOLFSSL_SUCCESS);
    wc_ForceZero(der, SE_DER_SCRATCH_SIZE);
    return ok ? 0 : -1;
}

static int tls_start(void)
{
    uint16_t cert_len = 0U;

    SE_HOST_LOG("tls_start mode=%u\n", (unsigned)s_mode);
    /* wolfSSL_Init holds a global RNG in the arena. Free that first, then
     * drop anything a previous session left behind, then bring wolfSSL back.
     * The next handshake always starts from one full region. */
    (void)wolfSSL_Cleanup();
    se_mem_reset();
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return -1;
    }
    se_mem_session_begin();
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
        uint8_t *der = se_der_scratch();
        int ok;

        if (se_creds_get_device_cert(der, &cert_len, SE_CREDS_DER_MAX) != LT_OK) {
            return -1;
        }
        ok = (wolfSSL_CTX_use_certificate_buffer(s_ctx, der, (long)cert_len, WOLFSSL_FILETYPE_ASN1) ==
              WOLFSSL_SUCCESS);
        wc_ForceZero(der, SE_DER_SCRATCH_SIZE);
        if (!ok) {
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
    SE_HOST_LOG("tls_start ok\n");
    return 0;
}

int se_tls_arm(uint32_t mode)
{
    if ((s_state != TLS_ST_IDLE) || (s_mode != 0U)) {
        SE_HOST_LOG("tls_arm refuse state=%u mode=%u\n", (unsigned)s_state, (unsigned)s_mode);
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
    /* Prior peer is gone; drop undrained close_notify / ASCII so ClientHello
     * is not preceded by garbage on the new TLS socket. */
    if (se_usb_tls_tx_draining() != 0) {
        se_usb_tls_end_tls_wire();
    }
    se_usb_tls_discard_idle_tx();
    se_tls_die = 0U;
    se_tls_die_err = 0;
    s_mode = mode;
    return 0;
}

int se_tls_session_active(void)
{
    return (s_mode != 0U) ? 1 : 0;
}

int se_tls_pipe_busy(void)
{
    return ((s_mode != 0U) || (se_usb_tls_tx_draining() != 0)) ? 1 : 0;
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
    se_tls_state = (uint32_t)s_state;
}

void se_tls_abort(void)
{
    secure_qkd_discard();
    tls_wipe_mode();
    tls_wipe_ssl();
    se_usb_tls_clear_rx();
    se_usb_tls_end_tls_wire();
    se_time_clear_synced();
    /* No USB ASCII: host already sees TLS failure / arm refuse via SECURE_USB_ERR. */
    s_state = TLS_ST_IDLE;
    se_tls_state = (uint32_t)s_state;
}

static void tls_line_begin(const char *s, TlsState next)
{
    uint16_t n = 0U;

    while ((s[n] != '\0') && (n < (uint16_t)(TLS_LINE_MAX - 1U))) {
        s_line_tx[n] = (uint8_t)s[n];
        n++;
    }
    s_line_tx_len = n;
    s_line_tx_off = 0U;
    s_line_next = next;
    s_state = TLS_ST_WRITE_LINE;
}

static void tls_line_u32(uint32_t v, TlsState next)
{
    char tmp[10];
    char line[12];
    uint16_t n = 0U;
    uint16_t i;

    do {
        tmp[n++] = (char)('0' + (uint8_t)(v % 10U));
        v /= 10U;
    } while ((v != 0U) && (n < 10U));
    for (i = 0U; i < n; i++) {
        line[i] = tmp[(uint16_t)(n - 1U - i)];
    }
    line[n] = '\n';
    line[(uint16_t)(n + 1U)] = '\0';
    tls_line_begin(line, next);
}

/** 0 stalled (WANT_READ / WANT_WRITE), 1 finished, -1 fatal. */
static int tls_flush_bytes(const uint8_t *data, uint16_t len, uint16_t *off)
{
    uint32_t left = (uint32_t)len - (uint32_t)*off;
    uint32_t chunk;
    int wr;
    int err;

    if (left == 0U) {
        return 1;
    }
    chunk = left;
    if (chunk > TLS_WRITE_CHUNK) {
        chunk = TLS_WRITE_CHUNK;
    }
    wr = wolfSSL_write(s_ssl, data + *off, (int)chunk);
    if (wr <= 0) {
        err = wolfSSL_get_error(s_ssl, wr);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            return 0;
        }
        se_tls_die = 8U;
        se_tls_die_err = err;
        return -1;
    }
    *off = (uint16_t)((uint32_t)*off + (uint32_t)wr);
    return ((uint32_t)*off >= (uint32_t)len) ? 1 : 0;
}

static int tls_qkd_finish_and_ack(void)
{
    uint32_t key_bytes = 0U;
    uint32_t st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &key_bytes);

    if (st != SECURE_QKD_OK) {
        return -1;
    }
    tls_line_begin("SE_OK\n", TLS_ST_SHUTDOWN);
    return 0;
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

/* Peer identity is already checked. Drop the certificate and handshake keys.
 * Leave wolfSSL's record buffers alone: freeing them from outside the read
 * path corrupts the arena free list. */
static void tls_drop_tunnel_spare(WOLFSSL *ssl)
{
    if (ssl == NULL) {
        return;
    }
    (void)wolfSSL_FreeHandshakeResources(ssl);
    (void)wolfSSL_UnloadCertsKeys(ssl);
#ifdef KEEP_PEER_CERT
    FreeX509(&ssl->peerCert);
    ReinitX509(&ssl->peerCert);
#endif
}

static void tls_app_manage_enter(void)
{
    if (se_tls_user_pin_peer(s_ssl) != 0) {
        se_tls_die = 6U;
        se_tls_abort();
        return;
    }
    tls_drop_tunnel_spare(s_ssl);
    se_ram_sample();
    s_manage_got = 0U;
    s_state = TLS_ST_READ_MANAGE;
}

static int tls_uplink_capture(const uint8_t *data, uint32_t len, void *ctx)
{
    (void)ctx;
    if ((data == NULL) && (len != 0U)) {
        return -1;
    }
    if ((uint32_t)s_uplink_tx_len + len > sizeof(s_uplink_tx)) {
        return -1;
    }
    if (len > 0U) {
        (void)memcpy(s_uplink_tx + s_uplink_tx_len, data, len);
        s_uplink_tx_len = (uint16_t)((uint32_t)s_uplink_tx_len + len);
    }
    return 0;
}

static void tls_app_provision_service(void)
{
    int n;
    int err;

    switch (s_state) {
    case TLS_ST_WRITE_UPLINK:
        if (s_uplink_ready == 0U) {
            tls_wipe_uplink();
            if (se_tropic_session_uplink(s_exporter, tls_uplink_capture, NULL) != 0) {
                se_tls_die = 11U;
                se_tls_die_err = -127;
                tls_wipe_uplink();
                se_tls_abort();
                break;
            }
            s_uplink_ready = 1U;
            s_uplink_tx_off = 0U;
        }
        n = tls_flush_bytes(s_uplink_tx, s_uplink_tx_len, &s_uplink_tx_off);
        if (n < 0) {
            tls_wipe_uplink();
            se_tls_abort();
            break;
        }
        if (n == 0) {
            break;
        }
        tls_wipe_uplink();
        s_wipe_slot = (uint16_t)SE_TROPIC_QKD_SLOT_BASE;
        s_dl_bytes = 0U;
        s_state = TLS_ST_WIPE_TROPIC;
        break;

    case TLS_ST_WIPE_TROPIC: {
        lt_handle_t *h;
        lt_ret_t ret;

        if (se_tropic_init_session() != SE_TROPIC_OK) {
            se_tls_die = 12U;
            se_tls_die_err = se_tropic_die;
            se_tls_abort();
            break;
        }
        h = se_tropic_handle();
        if (h == NULL) {
            se_tls_die = 12U;
            se_tls_abort();
            break;
        }
        ret = lt_r_mem_data_erase(h, s_wipe_slot);
        if (ret != LT_OK) {
            se_tls_die = 12U;
            se_tls_die_err = (int)ret;
            se_tls_abort();
            break;
        }
        if (s_wipe_slot >= (uint16_t)SE_TROPIC_QKD_SLOT_LAST) {
            se_tropic_qkd_set_wiped(1U);
            tls_line_begin("TROPIC_WIPE_FINISHED\n", TLS_ST_READ_RESP);
            break;
        }
        s_wipe_slot++;
        break;
    }

    case TLS_ST_WRITE_LINE:
        n = tls_flush_bytes(s_line_tx, s_line_tx_len, &s_line_tx_off);
        if (n < 0) {
            se_tls_abort();
            break;
        }
        if (n == 0) {
            break;
        }
        s_line_tx_len = 0U;
        s_line_tx_off = 0U;
        if (s_line_next == TLS_ST_SHUTDOWN) {
            tls_enter_shutdown();
            break;
        }
        s_state = s_line_next;
        if ((s_state == TLS_ST_READ_RESP) && (secure_qkd_ready_to_finish() != 0U)) {
            if (tls_qkd_finish_and_ack() != 0) {
                se_tls_abort();
            }
        }
        break;

    case TLS_ST_READ_RESP: {
        uint8_t chunk[TLS_APP_READ_CHUNK];
        uint32_t st;
        uint32_t old_bytes;
        uint32_t new_step;
        uint32_t old_step;

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            st = secure_qkd_ingest(chunk, (uint32_t)n, SECURE_QKD_INGEST_CHUNK, NULL);
            wc_ForceZero(chunk, sizeof(chunk));
            if (st != SECURE_QKD_OK) {
                se_tls_abort();
                break;
            }
            old_bytes = s_dl_bytes;
            s_dl_bytes += (uint32_t)n;
            old_step = old_bytes / TLS_DL_PROGRESS_BYTES;
            new_step = s_dl_bytes / TLS_DL_PROGRESS_BYTES;
            if (new_step > old_step) {
                tls_line_u32(new_step * 10U, TLS_ST_READ_RESP);
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
            tls_enter_shutdown();
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

static int tls_manage_finish(void)
{
    char msg[SE_MANAGE_MSG_MAX];
    uint32_t st;

    msg[0] = '\0';
    st = se_manage_apply_buf(se_manage_buf(), s_manage_got, msg, (uint16_t)sizeof(msg));
    se_ram_sample();
    s_manage_tx_len = se_manage_rsp_encode(s_manage_tx, (uint16_t)sizeof(s_manage_tx),
                                           (uint8_t)st, msg);
    if (s_manage_tx_len == 0U) {
        return -1;
    }
    s_manage_tx_off = 0U;
    se_manage_buf_wipe();
    s_manage_got = 0U;
    return 0;
}

static void tls_manage_write(void)
{
    uint32_t left = (uint32_t)s_manage_tx_len - (uint32_t)s_manage_tx_off;
    uint32_t chunk;
    int wr;
    int err;

    if (left == 0U) {
        tls_wipe_manage();
        tls_enter_shutdown();
        return;
    }
    chunk = left;
    if (chunk > TLS_WRITE_CHUNK) {
        chunk = TLS_WRITE_CHUNK;
    }
    /* WANT_WRITE is the USB TX ring still holding handshake bytes.
     * Aborting here drops the manage reply on the floor. */
    wr = wolfSSL_write(s_ssl, s_manage_tx + s_manage_tx_off, (int)chunk);
    if (wr <= 0) {
        err = wolfSSL_get_error(s_ssl, wr);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            return;
        }
        se_tls_die = 8U;
        se_tls_die_err = err;
        se_tls_abort();
        se_tls_state = (uint32_t)s_state;
        return;
    }
    s_manage_tx_off = (uint16_t)((uint32_t)s_manage_tx_off + (uint32_t)wr);
    if ((uint32_t)s_manage_tx_off >= (uint32_t)s_manage_tx_len) {
        tls_wipe_manage();
        tls_enter_shutdown();
    }
}

static void tls_app_manage_service(void)
{
    int n;
    int err;

    se_tls_state = (uint32_t)s_state;
    switch (s_state) {
    case TLS_ST_READ_MANAGE: {
        int ready = SE_FRAME_NEED_MORE;

        {
            uint8_t chunk[TLS_APP_READ_CHUNK];

            n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
            if (n > 0) {
                ready = se_manage_accum(&s_manage_got, chunk, (uint32_t)n, se_manage_req_need);
                wc_ForceZero(chunk, sizeof(chunk));
            }
        }
        if (n > 0) {
            if (ready < 0) {
                se_tls_die = 3U;
                se_tls_die_err = -125;
                se_tls_abort();
                break;
            }
            if (ready != SE_FRAME_COMPLETE) {
                break;
            }
            if (tls_manage_finish() != 0) {
                se_tls_die = 7U;
                se_tls_die_err = -126;
                se_tls_abort();
                break;
            }
            s_state = TLS_ST_WRITE_MANAGE;
            se_tls_state = (uint32_t)s_state;
            /* Queue the reply before this NSC returns. NonSecure drains USB
             * only after the call, so leaving the bytes unsent here is what
             * leaves the host blocked after KEM has already finished. */
            tls_manage_write();
            break;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            break;
        }
        se_tls_die = 2U;
        se_tls_die_err = err;
        se_tls_abort();
        break;
    }

    case TLS_ST_WRITE_MANAGE:
        tls_manage_write();
        break;

    default:
        se_tls_abort();
        break;
    }
    se_tls_state = (uint32_t)s_state;
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
        se_ram_sample();
        if (n == WOLFSSL_SUCCESS) {
            SE_HOST_LOG("handshake ok\n");
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
            SE_HOST_LOG("handshake fail err=%d\n", err);
            se_tls_die = 1U;
            se_tls_die_err = err;
            se_tls_abort();
        }
        break;

    case TLS_ST_SHUTDOWN:
        tls_shutdown_service();
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
        /* Queue close_notify in the same NSC as the last app write so the
         * peer sees reply then alert before we return to ASCII. */
        if (s_state == TLS_ST_SHUTDOWN) {
            tls_shutdown_service();
        }
        break;
    }
}
