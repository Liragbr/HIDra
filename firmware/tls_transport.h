#ifndef HIDRA_TLS_TRANSPORT_H
#define HIDRA_TLS_TRANSPORT_H
#include <stdbool.h>
#include <stddef.h>
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "lwip/tcp.h"

typedef struct {
    struct tcp_pcb *pcb;
    unsigned char rx[8192];
    size_t used;
    bool connected, eof;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
} hidra_tls_t;
void hidra_tls_init(hidra_tls_t *);
void hidra_tls_free(hidra_tls_t *);
bool hidra_tls_connect(hidra_tls_t *, const char *address, const char *hostname, unsigned port);
bool hidra_tls_readline(hidra_tls_t *, char *, size_t);
bool hidra_tls_writeline(hidra_tls_t *, const char *);
void hidra_network_poll(void);
#endif
