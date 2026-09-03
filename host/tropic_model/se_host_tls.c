/**
 * @file    se_host_tls.c
 * @brief   POSIX TLS 1.3 client mirroring se_tls_client.c post-handshake path
 *
 * USB I/O is replaced by a blocking TCP socket. The host console (same names
 * as NonSecure USB) selects provision vs encrypt vs decrypt. Unix time is
 * parsed by the console; this file only runs the armed TLS session. Provision
 * verifies the SAE application CA, then sends the session uplink and ingest
 * pads. Encrypt/decrypt verify the client CA and pin the TLS peer to the
 * embedded home-PC user SPKI, wait for PIN+payload, OTP-consume, and reply.
 */
#include "se_host_tls.h"
#include "se_tropic_session.h"
#include "se_tropic.h"
#include "se_tropic_rmem.h"
#include "se_nv.h"
#include "se_tropic_port.h"
#include "se_usb_tls.h"
#include "secure_client_key.h"
#include "secure_qkd_ingest.h"
#include "secure_otp.h"
#include "se_tls_user.h"
#include "fw_creds.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TLS_APP_READ_CHUNK 512
#define TLS_WRITE_CHUNK    1024

static WOLFSSL_CTX *s_ctx;
static WOLFSSL *s_ssl;
static uint8_t s_exporter[SE_TROPIC_EXPORTER_LEN];
static int s_fd = -1;
static uint8_t s_otp_rest[TLS_APP_READ_CHUNK];
static uint32_t s_otp_rest_len;

static void tls_close_fd(void)
{
    if (s_fd >= 0) {
        (void)close(s_fd);
        s_fd = -1;
    }
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
    wc_ForceZero(s_otp_rest, s_otp_rest_len);
    s_otp_rest_len = 0U;
    se_tropic_otp_xor_close();
    secure_otp_reset();
    tls_close_fd();
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

static void tls_qkd_status(uint32_t st, uint32_t count)
{
    if (st == SECURE_QKD_WRONG_VERSION) {
        se_usb_debug_printf("downlink schema mismatch (expect v%u)",
                            (unsigned)SECURE_LV_DOWNLINK_VERSION);
    } else if (st == SECURE_QKD_STORE) {
        se_usb_debug_printf("downlink Tropic store failed");
    } else if (st != SECURE_QKD_OK) {
        se_usb_debug_printf("downlink parse error %lu", (unsigned long)st);
    } else {
        se_usb_debug_printf("response done, qkd=%lu", (unsigned long)count);
    }
}

static int tls_connect_tcp(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    char portstr[16];
    int fd = -1;
    int one = 1;

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    (void)snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        se_usb_debug_printf("TLS TCP: getaddrinfo failed");
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        (void)close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        se_usb_debug_printf("TLS TCP: connect failed (%s)", strerror(errno));
        return -1;
    }
    return fd;
}

static int tls_load_verify_ca(WOLFSSL_CTX *ctx, uint32_t mode)
{
    const unsigned char *ca;
    long ca_len;

    if (mode == SE_HOST_TLS_PROVISION) {
        ca = fw_root_ca_der;
        ca_len = (long)fw_root_ca_der_len;
    } else {
        ca = fw_client_ca_der;
        ca_len = (long)fw_client_ca_der_len;
    }
    if ((ca_len <= 0) ||
        (wolfSSL_CTX_load_verify_buffer(ctx, ca, ca_len, WOLFSSL_FILETYPE_ASN1)
         != WOLFSSL_SUCCESS)) {
        se_usb_debug_printf("TLS setup: load CA failed");
        return -1;
    }
    return 0;
}

static int tls_start(const char *host, uint16_t port, uint32_t mode)
{
    if ((mode != SE_HOST_TLS_PROVISION) && (fw_user_spki_len == 0U)) {
        se_usb_debug_printf("TLS setup: no user key (embed user-cert.pem)");
        return -1;
    }

    s_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (s_ctx == NULL) {
        se_usb_debug_printf("TLS setup: CTX_new failed");
        return -1;
    }

    wolfSSL_CTX_SetMinVersion(s_ctx, WOLFSSL_TLSV1_3);
    (void)wolfSSL_CTX_set_cipher_list(s_ctx, "TLS13-AES256-GCM-SHA384");

    if (tls_load_verify_ca(s_ctx, mode) != 0) {
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

    s_fd = tls_connect_tcp(host, port);
    if (s_fd < 0) {
        return -1;
    }

    s_ssl = wolfSSL_new(s_ctx);
    if (s_ssl == NULL) {
        se_usb_debug_printf("TLS setup: SSL_new failed");
        return -1;
    }

    if (wolfSSL_set_fd(s_ssl, s_fd) != WOLFSSL_SUCCESS) {
        se_usb_debug_printf("TLS setup: set_fd failed");
        return -1;
    }

    if (tls_setup_groups(s_ctx, s_ssl) != 0) {
        se_usb_debug_printf("TLS setup: ML-KEM group failed");
        return -1;
    }

    wolfSSL_KeepArrays(s_ssl);
    se_usb_debug_printf("sending handshake");
    return 0;
}

static int tls_handshake(uint32_t mode)
{
    int n;
    int err;
    int exported;

    n = wolfSSL_connect(s_ssl);
    if (n != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(s_ssl, n);
        se_usb_debug_printf("TLS failed err=%d", err);
        return -1;
    }

    exported = wolfSSL_export_keying_material(s_ssl, s_exporter, SE_TROPIC_EXPORTER_LEN,
                                              SE_TROPIC_EXPORTER_LABEL,
                                              SE_TROPIC_EXPORTER_LABEL_LEN, NULL, 0, 0);
    wolfSSL_FreeArrays(s_ssl);
    if (exported != WOLFSSL_SUCCESS) {
        se_usb_debug_printf("TLS exporter failed");
        return -1;
    }
    if ((mode != SE_HOST_TLS_PROVISION) && (se_tls_user_pin_peer(s_ssl) != 0)) {
        se_usb_debug_printf("TLS failed: user key mismatch");
        return -1;
    }
    if (mode == SE_HOST_TLS_PROVISION) {
        se_usb_debug_printf("handshake ok, provision");
    } else if (mode == SE_HOST_TLS_DECRYPT) {
        se_usb_debug_printf("handshake ok, waiting ciphertext");
    } else {
        se_usb_debug_printf("handshake ok, waiting plaintext");
    }
    return 0;
}

static int tls_read_ingest(void)
{
    uint8_t chunk[TLS_APP_READ_CHUNK];
    uint32_t st;
    uint32_t count = 0U;
    int n;
    int err;

    se_usb_debug_printf("report sent, reading response");
    for (;;) {
        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            st = secure_qkd_ingest(chunk, (uint32_t)n, SECURE_QKD_INGEST_CHUNK, NULL);
            wc_ForceZero(chunk, sizeof(chunk));
            if (st != SECURE_QKD_OK) {
                tls_qkd_status(st, 0U);
                return -1;
            }
            continue;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            continue;
        }
        st = secure_qkd_ingest(NULL, 0U, SECURE_QKD_INGEST_FINISH, &count);
        tls_qkd_status(st, count);
        return (st == SECURE_QKD_OK) ? 0 : -1;
    }
}

static int tls_otp_open_xor(uint32_t mode)
{
    const uint8_t *pin;
    uint8_t pin_len = 0U;
    uint32_t msg_len;
    uint32_t n_pads;
    se_nv_otp_dir_t dir;
    lt_handle_t *h;
    lt_ret_t ret;
    uint8_t decrypt;

    pin = secure_otp_request_pin(&pin_len);
    decrypt = (mode == SE_HOST_TLS_DECRYPT) ? 1U : 0U;
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
    ret = se_tropic_otp_xor_open(h, pin, pin_len, NULL, 0U, dir, msg_len, n_pads);
    if (ret != LT_OK) {
        se_tropic_otp_xor_close();
        return -1;
    }
    if (decrypt != 0U) {
        secure_otp_decrypt_begin_ciphertext(se_tropic_otp_xor_pad_max(), n_pads);
    } else {
        secure_otp_encrypt_begin_plaintext(se_tropic_otp_xor_pad_max(), msg_len);
    }
    return 0;
}

static int tls_otp_xor_and_send_pad(uint32_t mode, uint8_t *ver_written)
{
    uint8_t buf[4u + 4u + SE_TROPIC_RMEM_PLAIN_MAX];
    uint8_t *chunk;
    uint16_t take = 0U;
    uint16_t logical = 0U;
    const uint16_t *req = NULL;
    uint16_t req_slot;
    uint32_t off = 0U;
    uint32_t written = 0U;
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
    if (mode == SE_HOST_TLS_DECRYPT) {
        req_slot = secure_otp_decrypt_pad_slot();
        req = &req_slot;
    }
    ret = se_tropic_otp_xor_pad(h, req, chunk, take, chunk, &logical, NULL);
    if (ret != LT_OK) {
        return -1;
    }
    if (*ver_written == 0U) {
        if (secure_otp_encode_n_pads(se_tropic_otp_xor_pads_needed(), buf) != 0) {
            return -1;
        }
        off = 4U;
        *ver_written = 1U;
    }
    if (secure_otp_encode_pad((mode == SE_HOST_TLS_DECRYPT) ? 1U : 0U, logical, chunk, take,
                              buf + off, (uint32_t)sizeof(buf) - off, &written) != 0) {
        return -1;
    }
    off += written;
    if (tls_write_all(buf, off, s_ssl) != 0) {
        return -1;
    }
    secure_otp_pad_done();
    return 0;
}

static int tls_otp_save_leftover(const uint8_t *chunk, uint32_t len)
{
    if (len == 0U) {
        wc_ForceZero(s_otp_rest, s_otp_rest_len);
        s_otp_rest_len = 0U;
        return 0;
    }
    if (len > sizeof(s_otp_rest)) {
        wc_ForceZero(s_otp_rest, s_otp_rest_len);
        s_otp_rest_len = 0U;
        return -1;
    }
    (void)memmove(s_otp_rest, chunk, len);
    s_otp_rest_len = len;
    return 0;
}

static int tls_otp_handle_bytes(uint32_t mode, const uint8_t *data, uint32_t len,
                                uint8_t *ver_written)
{
    uint32_t consumed = 0U;
    uint32_t st;

    if (se_tropic_otp_xor_pad_max() == 0U) {
        if (mode == SE_HOST_TLS_DECRYPT) {
            st = secure_otp_decrypt_parse_request(data, len, &consumed);
        } else {
            st = secure_otp_encrypt_parse_request(data, len, &consumed);
        }
        if (st == SECURE_OTP_REQ_COMPLETE) {
            if (tls_otp_open_xor(mode) != 0) {
                se_usb_debug_printf("OTP xor open failed");
                return -1;
            }
            data += consumed;
            len -= consumed;
            if (len == 0U) {
                return 0;
            }
        } else if (st != SECURE_OTP_REQ_OK) {
            se_usb_debug_printf("OTP parse error %lu", (unsigned long)st);
            return -1;
        } else {
            return 0;
        }
    }

    st = secure_otp_read_pad(data, len, &consumed);
    if (st == SECURE_OTP_PAD_READY) {
        if (tls_otp_save_leftover(data + consumed, len - consumed) != 0) {
            return -1;
        }
        if (tls_otp_xor_and_send_pad(mode, ver_written) != 0) {
            se_usb_debug_printf("OTP xor pad failed");
            return -1;
        }
        if (se_tropic_otp_xor_bytes_left() == 0U) {
            se_tropic_otp_xor_close();
            return 1;
        }
        return 0;
    }
    if (st != SECURE_OTP_REQ_OK) {
        se_usb_debug_printf("OTP parse error %lu", (unsigned long)st);
        return -1;
    }
    wc_ForceZero(s_otp_rest, s_otp_rest_len);
    s_otp_rest_len = 0U;
    return 0;
}

static int tls_otp_parse_xor_and_reply(uint32_t mode)
{
    uint8_t chunk[TLS_APP_READ_CHUNK];
    uint8_t ver_written = 0U;
    int n;
    int err;
    int rc;

    for (;;) {
        if (s_otp_rest_len > 0U) {
            uint32_t rest_len = s_otp_rest_len;

            s_otp_rest_len = 0U;
            rc = tls_otp_handle_bytes(mode, s_otp_rest, rest_len, &ver_written);
            if (s_otp_rest_len < rest_len) {
                wc_ForceZero(s_otp_rest + s_otp_rest_len, rest_len - s_otp_rest_len);
            }
            if (rc < 0) {
                return -1;
            }
            if (rc > 0) {
                return 0;
            }
            continue;
        }

        n = wolfSSL_read(s_ssl, chunk, (int)sizeof(chunk));
        if (n > 0) {
            rc = tls_otp_handle_bytes(mode, chunk, (uint32_t)n, &ver_written);
            wc_ForceZero(chunk, sizeof(chunk));
            if (rc < 0) {
                return -1;
            }
            if (rc > 0) {
                return 0;
            }
            continue;
        }
        err = wolfSSL_get_error(s_ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            continue;
        }
        se_usb_debug_printf("otp closed before PIN/msg");
        return -1;
    }
}

int se_host_tls_run(const char *host, uint16_t port, uint32_t mode)
{
    int rc = -1;

    if ((host == NULL) || (port == 0U)) {
        return -1;
    }
    if ((mode != SE_HOST_TLS_PROVISION) && (mode != SE_HOST_TLS_ENCRYPT) &&
        (mode != SE_HOST_TLS_DECRYPT)) {
        return -1;
    }

    (void)signal(SIGPIPE, SIG_IGN);

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        se_usb_debug_printf("TLS setup: wolfSSL_Init failed");
        return -1;
    }

    secure_qkd_discard();
    secure_otp_reset();
    if (tls_start(host, port, mode) != 0) {
        goto done;
    }
    if (tls_handshake(mode) != 0) {
        goto done;
    }
    if (mode == SE_HOST_TLS_PROVISION) {
        if (se_tropic_session_uplink(s_exporter, tls_write_all, s_ssl) != 0) {
            se_usb_debug_printf("session uplink failed");
            goto done;
        }
        if (tls_read_ingest() != 0) {
            goto done;
        }
    } else {
        se_usb_debug_printf("otp xor");
        if (tls_otp_parse_xor_and_reply(mode) != 0) {
            se_usb_debug_printf("OTP xor failed");
            goto done;
        }
        se_usb_debug_printf("otp sent");
    }
    (void)wolfSSL_shutdown(s_ssl);
    se_usb_debug_printf("TLS session ok");
    rc = 0;

done:
    if (rc != 0) {
        secure_qkd_discard();
        secure_otp_reset();
    }
    tls_wipe_ssl();
    /* Leave wolfCrypt up: PIN OTP after ingest still needs AES/ML-KEM. */
    return rc;
}
