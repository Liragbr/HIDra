/**
 * mbedtls_config.h — lean mbedTLS config for Pico W
 *
 * Goals:
 *   - TLS 1.3 only (matches [SEC-4] from the desktop agent)
 *   - Disable every cipher suite / feature not needed for TLS 1.3
 *   - Keep RAM footprint under ~60 KB so the rest of the firmware fits
 *     in RP2040's 264 KB (RP2350 has 520 KB — more headroom there)
 *
 * TLS 1.3 cipher suites enabled:
 *   TLS_AES_128_GCM_SHA256
 *   TLS_AES_256_GCM_SHA384
 *   TLS_CHACHA20_POLY1305_SHA256  (good on M0+ which has no AES hw)
 *
 * Key exchange: ECDHE (X25519 / secp256r1)
 * Auth:         ECDSA or RSA (for server cert)
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ── System ──────────────────────────────────────────────────────────── */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT   /* hook pico get_rand_32()       */

/* ── TLS ─────────────────────────────────────────────────────────────── */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C              /* client mode                   */
#define MBEDTLS_SSL_PROTO_TLS1_3       /* TLS 1.3 only                  */
/* Disable older protocols */
#undef  MBEDTLS_SSL_PROTO_TLS1_2
#undef  MBEDTLS_SSL_PROTO_TLS1_1
#undef  MBEDTLS_SSL_PROTO_TLS1
#undef  MBEDTLS_SSL_PROTO_DTLS

/* ── TLS 1.3 key exchange ────────────────────────────────────────────── */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

/* ── Cipher suites ───────────────────────────────────────────────────── */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* ── Hash ────────────────────────────────────────────────────────────── */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C

/* ── HMAC (for protocol signing) ─────────────────────────────────────── */
#define MBEDTLS_MD_C   /* already set, just noting it's needed here     */

/* ── ECC (ECDHE + ECDSA) ─────────────────────────────────────────────── */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_X25519_ENABLED

/* ── RSA (for parsing server certs signed with RSA) ─────────────────── */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C

/* ── X.509 cert parsing ──────────────────────────────────────────────── */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* ── PRNG ────────────────────────────────────────────────────────────── */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_AES_C   /* already set; CTR-DRBG needs it               */

/* ── Constant-time comparison [SEC-3] ───────────────────────────────── */
/* mbedtls_ct_memcmp is always available in mbedTLS 3.x                 */

/* ── Net sockets (lwIP glue) ─────────────────────────────────────────── */
#define MBEDTLS_NET_C

/* ── Memory ──────────────────────────────────────────────────────────── */
/* Use standard malloc/free (pico-sdk maps these to heap)               */
#define MBEDTLS_PLATFORM_MEMORY

/* Maximum TLS record size — standard is 16384; 4096 saves ~25 KB RAM  */
#define MBEDTLS_SSL_MAX_CONTENT_LEN    4096
#define MBEDTLS_SSL_IN_CONTENT_LEN     4096
#define MBEDTLS_SSL_OUT_CONTENT_LEN    4096

/* ── Disable unused features to save flash ───────────────────────────── */
#undef MBEDTLS_SSL_SRV_C          /* no server mode                     */
#undef MBEDTLS_SSL_DTLS_SRTP      /* no SRTP                            */
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_RC4_C
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_BLOWFISH_C

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
