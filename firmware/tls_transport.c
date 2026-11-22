/* Core 0 owns lwIP raw TCP in polling mode and all mbedTLS state. No POSIX sockets. */
#include "tls_transport.h"
#include "agent_config.h"
#if !AGENT_LAB_MODE
#include "ca_cert.h"
#endif
#include "pico/cyw43_arch.h"
#include "pico/time.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"
#include "psa/crypto.h"
#include <string.h>
#include <time.h>

#define IO_TIMEOUT_MS 20000u
mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)(time_us_64() / 1000u);
}
static time_t build_clock(time_t *out) {
    time_t value = (time_t)HIDRA_BUILD_EPOCH + (time_t)(time_us_64() / 1000000u);
    if (out) *out = value;
    return value;
}
void hidra_network_poll(void) {
    cyw43_arch_poll();
    sleep_ms(1);
}
static void net_error(void *arg, err_t error) {
    (void)error;
    hidra_tls_t *ctx = arg;
    ctx->pcb = NULL; ctx->eof = true; ctx->connected = false;
}
static err_t net_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t error) {
    hidra_tls_t *ctx = arg;
    if (!p) { ctx->eof = true; return ERR_OK; }
    if (error != ERR_OK) { pbuf_free(p); ctx->eof = true; return ERR_OK; }
    if (p->tot_len > sizeof(ctx->rx) - ctx->used) return ERR_MEM; /* lwIP retains p. */
    u16_t copied = pbuf_copy_partial(p, ctx->rx + ctx->used, p->tot_len, 0);
    ctx->used += copied;
    tcp_recved(pcb, copied);
    pbuf_free(p);
    return ERR_OK;
}
static err_t net_connected(void *arg, struct tcp_pcb *pcb, err_t error) {
    (void)pcb;
    hidra_tls_t *ctx = arg;
    ctx->connected = error == ERR_OK;
    ctx->eof = error != ERR_OK;
    return ERR_OK;
}
static int bio_send(void *arg, const unsigned char *data, size_t len) {
    hidra_tls_t *ctx = arg;
    if (!ctx->pcb || ctx->eof) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    size_t available = tcp_sndbuf(ctx->pcb);
    if (!available) return MBEDTLS_ERR_SSL_WANT_WRITE;
    if (len > available) len = available;
    err_t result = tcp_write(ctx->pcb, data, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (result == ERR_MEM) return MBEDTLS_ERR_SSL_WANT_WRITE;
    if (result != ERR_OK) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    result = tcp_output(ctx->pcb);
    /* tcp_write already owns the bytes: do not retry them if output is temporarily busy. */
    if (result != ERR_OK && result != ERR_MEM) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return (int)len;
}
static int bio_recv(void *arg, unsigned char *data, size_t len) {
    hidra_tls_t *ctx = arg;
    if (ctx->used) {
        if (len > ctx->used) len = ctx->used;
        memcpy(data, ctx->rx, len);
        ctx->used -= len;
        memmove(ctx->rx, ctx->rx + len, ctx->used);
        return (int)len;
    }
    return ctx->eof ? 0 : MBEDTLS_ERR_SSL_WANT_READ;
}
void hidra_tls_init(hidra_tls_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_x509_crt_init(&ctx->ca);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->drbg);
}
void hidra_tls_free(hidra_tls_t *ctx) {
    if (ctx->connected && !ctx->eof) (void)mbedtls_ssl_close_notify(&ctx->ssl);
    if (ctx->pcb) {
        tcp_arg(ctx->pcb, NULL);
        tcp_recv(ctx->pcb, NULL);
        tcp_err(ctx->pcb, NULL);
        /* Abort removes all callbacks immediately; no borrowed stack state survives. */
        tcp_abort(ctx->pcb);
        ctx->pcb = NULL;
    }
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_x509_crt_free(&ctx->ca);
    mbedtls_ctr_drbg_free(&ctx->drbg);
    mbedtls_entropy_free(&ctx->entropy);
    ctx->connected = false;
    ctx->used = 0;
}
static bool retry(int result) {
    return result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE;
}
bool hidra_tls_connect(hidra_tls_t *ctx, const char *address, const char *hostname, unsigned port) {
    ip_addr_t ip;
    if (!ipaddr_aton(address, &ip) || port == 0 || port > 65535) return false;
    if (psa_crypto_init() != PSA_SUCCESS || mbedtls_platform_set_time(build_clock) != 0) return false;
    if (mbedtls_ctr_drbg_seed(&ctx->drbg, mbedtls_entropy_func, &ctx->entropy,
                             (const unsigned char *)"HIDra/2", 7) != 0) return false;
    if (mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) return false;
    mbedtls_ssl_conf_min_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->drbg);
#if AGENT_LAB_MODE
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
#else
    if (mbedtls_x509_crt_parse(&ctx->ca, (const unsigned char *)ca_cert_pem, sizeof(ca_cert_pem)) != 0) return false;
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca, NULL);
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
    if (mbedtls_ssl_setup(&ctx->ssl, &ctx->conf) != 0 ||
        mbedtls_ssl_set_hostname(&ctx->ssl, hostname) != 0) return false;
    ctx->pcb = tcp_new_ip_type(IP_GET_TYPE(&ip));
    if (!ctx->pcb) return false;
    tcp_arg(ctx->pcb, ctx);
    tcp_recv(ctx->pcb, net_recv);
    tcp_err(ctx->pcb, net_error);
    if (tcp_connect(ctx->pcb, &ip, (u16_t)port, net_connected) != ERR_OK) return false;
    absolute_time_t deadline = make_timeout_time_ms(IO_TIMEOUT_MS);
    while (!ctx->connected) {
        if (ctx->eof || time_reached(deadline)) return false;
        hidra_network_poll();
    }
    mbedtls_ssl_set_bio(&ctx->ssl, ctx, bio_send, bio_recv, NULL);
    int result;
    while ((result = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (!retry(result) || time_reached(deadline)) return false;
        hidra_network_poll();
    }
#if !AGENT_LAB_MODE
    if (mbedtls_ssl_get_verify_result(&ctx->ssl) != 0) return false;
#endif
    return true;
}
bool hidra_tls_readline(hidra_tls_t *ctx, char *out, size_t capacity) {
    size_t used = 0;
    absolute_time_t deadline = make_timeout_time_ms(IO_TIMEOUT_MS);
    while (!time_reached(deadline)) {
        unsigned char byte;
        int n = mbedtls_ssl_read(&ctx->ssl, &byte, 1);
        if (retry(n)) { hidra_network_poll(); continue; }
        if (n != 1 || byte == 0) return false;
        if (byte == '\n') { out[used] = 0; return used > 0; }
        if (used + 1 >= capacity) return false;
        out[used++] = (char)byte;
    }
    return false;
}
bool hidra_tls_writeline(hidra_tls_t *ctx, const char *line) {
    size_t length = strlen(line), sent = 0;
    absolute_time_t deadline = make_timeout_time_ms(IO_TIMEOUT_MS);
    while (sent <= length && !time_reached(deadline)) {
        const unsigned char *data = sent == length ? (const unsigned char *)"\n" : (const unsigned char *)line + sent;
        size_t remaining = sent == length ? 1 : length - sent;
        int n = mbedtls_ssl_write(&ctx->ssl, data, remaining);
        if (retry(n)) { hidra_network_poll(); continue; }
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return sent == length + 1;
}
