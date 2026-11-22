/* POSIX test BIO only. Exercises the firmware's exact mbedTLS config and codec. */
#define _POSIX_C_SOURCE 200809L
#include "protocol.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_time.h"
#include "psa/crypto.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TOKEN "fixture-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SECRET "fixture-hmac-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
int mbedtls_hardware_poll(void *unused, unsigned char *out, size_t len, size_t *olen) {
    (void)unused;
    *olen = 0;
    while (*olen < len) {
        ssize_t n = getrandom(out + *olen, len - *olen, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        *olen += (size_t)n;
    }
    return 0;
}
mbedtls_ms_time_t mbedtls_ms_time(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (mbedtls_ms_time_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int bio_send(void *p, const unsigned char *data, size_t len) {
    ssize_t n = send(*(int *)p, data, len, MSG_NOSIGNAL);
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : (int)n;
}
static int bio_recv(void *p, unsigned char *data, size_t len) {
    ssize_t n = recv(*(int *)p, data, len, 0);
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : (int)n;
}
static bool read_line(mbedtls_ssl_context *ssl, char *out, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        unsigned char c;
        if (mbedtls_ssl_read(ssl, &c, 1) != 1 || !c) return false;
        if (c == '\n') { out[used] = 0; return true; }
        out[used++] = (char)c;
    }
    return false;
}
static bool write_line(mbedtls_ssl_context *ssl, const char *line) {
    size_t len = strlen(line), sent = 0;
    while (sent < len) {
        int n = mbedtls_ssl_write(ssl, (const unsigned char *)line + sent, len - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return mbedtls_ssl_write(ssl, (const unsigned char *)"\n", 1) == 1;
}
static bool mac(void *unused, const char *data, size_t length, char out[65]) {
    (void)unused;
    unsigned char digest[32];
    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        (const unsigned char *)SECRET, strlen(SECRET), (const unsigned char *)data, length, digest)) return false;
    for (unsigned i = 0; i < 32; ++i) snprintf(out + i * 2, 3, "%02x", digest[i]);
    return true;
}
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "check failed at line %d\n", __LINE__); goto cleanup; } } while (0)
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int result = 1, fd = -1, handshake = 0;
    mbedtls_ssl_context ssl; mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config conf; mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt ca; mbedtls_x509_crt_init(&ca);
    mbedtls_entropy_context entropy; mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_context drbg; mbedtls_ctr_drbg_init(&drbg);
    char pem[8192];
    FILE *file = fopen(argv[1], "rb");
    CHECK(file != NULL);
    size_t pem_size = fread(pem, 1, sizeof(pem) - 1, file);
    bool read_ok = !ferror(file) && feof(file);
    fclose(file);
    CHECK(read_ok);
    pem[pem_size] = 0;
    CHECK(psa_crypto_init() == PSA_SUCCESS);
    CHECK(mbedtls_platform_set_time(time) == 0);
    CHECK(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0);
    CHECK(mbedtls_x509_crt_parse(&ca, (unsigned char *)pem, pem_size + 1) == 0);
    CHECK(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    CHECK(mbedtls_ssl_setup(&ssl, &conf) == 0);
    CHECK(mbedtls_ssl_set_hostname(&ssl, argv[3]) == 0);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {.tv_sec = 2};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)strtoul(argv[2], NULL, 10))};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    mbedtls_ssl_set_bio(&ssl, &fd, bio_send, bio_recv, NULL);
    handshake = mbedtls_ssl_handshake(&ssl);
    if (handshake) fprintf(stderr, "TLS handshake failed: -0x%04x\n", (unsigned)-handshake);
    CHECK(handshake == 0 && mbedtls_ssl_get_verify_result(&ssl) == 0);
    CHECK(!strcmp(mbedtls_ssl_get_version(&ssl), "TLSv1.3"));
    char line[2049], body[769], challenge[65], nonce[65], sid[65], material[139];
    unsigned char random[32], digest[32];
    hidra_object_t object;
    CHECK(read_line(&ssl, line, sizeof(line)) && hidra_parse(line, &object));
    CHECK(object.count == 1 && hidra_string(&object, "challenge", challenge, sizeof(challenge)) && hidra_hex64(challenge));
    CHECK(mbedtls_ctr_drbg_random(&drbg, random, sizeof(random)) == 0);
    for (unsigned i = 0; i < 32; ++i) snprintf(nonce + 2 * i, 3, "%02x", random[i]);
    int n = snprintf(material, sizeof(material), "HIDra/2\n%s\n%s", challenge, nonce);
    CHECK(n > 0 && (size_t)n < sizeof(material));
    CHECK(mbedtls_sha256((unsigned char *)material, (size_t)n, digest, 0) == 0);
    for (unsigned i = 0; i < 32; ++i) snprintf(sid + 2 * i, 3, "%02x", digest[i]);
    snprintf(line, sizeof(line), "{\"nonce\":\"%s\"}", nonce);
    CHECK(write_line(&ssl, line));
    CHECK(hidra_encode(sid, 1, "a2s", "{\"action\":\"auth\",\"token\":\"" TOKEN "\"}", mac, NULL, line, sizeof(line)));
    CHECK(write_line(&ssl, line) && read_line(&ssl, line, sizeof(line)));
    CHECK(hidra_decode(sid, 1, "s2a", line, mac, NULL, body, sizeof(body)));
    CHECK(hidra_parse(body, &object) && hidra_true(&object, "ok"));
    CHECK(read_line(&ssl, line, sizeof(line)) && hidra_decode(sid, 2, "s2a", line, mac, NULL, body, sizeof(body)));
    char action[16], payload[257];
    CHECK(hidra_command(body, action, payload) && !strcmp(action, "exit"));
    CHECK(hidra_encode(sid, 2, "a2s", "{\"ok\":true}", mac, NULL, line, sizeof(line)) && write_line(&ssl, line));
    puts("PASS: firmware mbedTLS config TLS 1.3 + C codec authentication and exit over loopback");
    result = 0;
cleanup:
    if (fd >= 0) close(fd);
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf); mbedtls_x509_crt_free(&ca);
    mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy);
    return result;
}
