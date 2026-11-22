#include "protocol.h"
#include <stdio.h>
#include <string.h>

static void whitespace(const char *s, size_t *p) {
    while (s[*p] && strchr(" \t\r\n", s[*p])) ++*p;
}
static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* Parse and optionally decode one string. Input is NUL terminated and bounded by caller. */
static bool string_at(const char *s, size_t *p, char *out, size_t capacity) {
    if (s[(*p)++] != '"') return false;
    size_t n = 0;
    while (s[*p] && s[*p] != '"') {
        unsigned char c = (unsigned char)s[(*p)++];
        if (c < 32 || c > 127) return false;
        if (c == '\\') {
            c = (unsigned char)s[(*p)++];
            switch (c) {
            case '"': case '\\': case '/': break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                unsigned value = 0;
                for (unsigned i = 0; i < 4; ++i) {
                    int h = hex(s[*p]);
                    if (h < 0) return false;
                    ++*p;
                    value = value * 16 + (unsigned)h;
                }
                if (value == 0 || value > 127) return false;
                c = (unsigned char)value;
                break;
            }
            default: return false;
            }
        }
        if (out) {
            if (n + 1 >= capacity) return false;
            out[n] = (char)c;
        }
        ++n;
    }
    if (s[*p] != '"') return false;
    ++*p;
    if (out) {
        if (n >= capacity) return false;
        out[n] = 0;
    }
    return true;
}
static const hidra_field_t *field(const hidra_object_t *o, const char *key) {
    for (unsigned i = 0; i < o->count; ++i)
        if (!strcmp(o->fields[i].key, key)) return &o->fields[i];
    return NULL;
}
bool hidra_parse(const char *s, hidra_object_t *o) {
    memset(o, 0, sizeof(*o));
    o->json = s;
    if (strlen(s) > HIDRA_MAX_FRAME) return false;
    size_t p = 0;
    whitespace(s, &p);
    if (s[p++] != '{') return false;
    whitespace(s, &p);
    if (s[p] == '}') { ++p; whitespace(s, &p); return s[p] == 0; }
    for (;;) {
        if (o->count >= HIDRA_MAX_FIELDS) return false;
        hidra_field_t *f = &o->fields[o->count];
        if (!string_at(s, &p, f->key, sizeof(f->key)) || field(o, f->key)) return false;
        whitespace(s, &p);
        if (s[p++] != ':') return false;
        whitespace(s, &p);
        f->start = p;
        if (s[p] == '"') {
            f->type = 's';
            if (!string_at(s, &p, NULL, 0)) return false;
        } else if (!strncmp(s + p, "true", 4)) {
            f->type = 't'; p += 4;
        } else if (!strncmp(s + p, "false", 5)) {
            f->type = 'f'; p += 5;
        } else {
            f->type = 'n';
            if (s[p] < '0' || s[p] > '9') return false;
            if (s[p] == '0') ++p;
            else while (s[p] >= '0' && s[p] <= '9') ++p;
            if (p - f->start > 10) return false;
            uint32_t value = 0;
            for (size_t i = f->start; i < p; ++i) {
                unsigned digit = (unsigned)(s[i] - '0');
                if (value > (HIDRA_MAX_SEQ - digit) / 10) return false;
                value = value * 10 + digit;
            }
        }
        f->end = p;
        ++o->count;
        whitespace(s, &p);
        if (s[p] == '}') { ++p; whitespace(s, &p); return s[p] == 0; }
        if (s[p++] != ',') return false;
        whitespace(s, &p);
    }
}
bool hidra_string(const hidra_object_t *o, const char *key, char *out, size_t n) {
    const hidra_field_t *f = field(o, key);
    if (!f || f->type != 's') return false;
    size_t p = f->start;
    return string_at(o->json, &p, out, n);
}
bool hidra_uint(const hidra_object_t *o, const char *key, uint32_t *out) {
    const hidra_field_t *f = field(o, key);
    if (!f || f->type != 'n') return false;
    uint32_t value = 0;
    for (size_t p = f->start; p < f->end; ++p) {
        unsigned digit = (unsigned)(o->json[p] - '0');
        if (value > (HIDRA_MAX_SEQ - digit) / 10) return false;
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}
bool hidra_true(const hidra_object_t *o, const char *key) {
    const hidra_field_t *f = field(o, key);
    return f && f->type == 't';
}
bool hidra_quote(const char *s, char *out, size_t cap) {
    size_t p = 0;
    if (cap < 3) return false;
    out[p++] = '"';
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c > 127) return false;
        if (c < 32) {
            if (p + 6 + 2 > cap) return false;
            int n = snprintf(out + p, cap - p, "\\u%04x", c);
            if (n != 6) return false;
            p += 6;
        } else {
            if (p + (c == '"' || c == '\\' ? 2u : 1u) + 2 > cap) return false;
            if (c == '"' || c == '\\') out[p++] = '\\';
            out[p++] = (char)c;
        }
    }
    out[p++] = '"'; out[p] = 0;
    return true;
}
bool hidra_hex64(const char *s) {
    if (strlen(s) != 64) return false;
    for (unsigned i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static bool signature(const char *sid, uint32_t seq, const char *direction, const char *body,
                      hidra_mac_fn mac, void *user, char out[65]) {
    char signed_data[HIDRA_MAX_BODY + 100];
    if (!hidra_hex64(sid) || !seq || seq > HIDRA_MAX_SEQ || strlen(body) > HIDRA_MAX_BODY ||
        (strcmp(direction, "a2s") && strcmp(direction, "s2a"))) return false;
    int n = snprintf(signed_data, sizeof(signed_data), "HIDra/2\n%s\n%s\n%lu\n%s",
                     direction, sid, (unsigned long)seq, body);
    return n > 0 && (size_t)n < sizeof(signed_data) && mac(user, signed_data, (size_t)n, out);
}
bool hidra_encode(const char *sid, uint32_t seq, const char *direction, const char *body,
                  hidra_mac_fn mac, void *user, char *out, size_t cap) {
    char sig[65], quoted[HIDRA_MAX_FRAME + 1];
    hidra_object_t object;
    if (!hidra_parse(body, &object) || !signature(sid, seq, direction, body, mac, user, sig) ||
        !hidra_quote(body, quoted, sizeof(quoted))) return false;
    int n = snprintf(out, cap, "{\"v\":2,\"sid\":\"%s\",\"seq\":%lu,\"body\":%s,\"sig\":\"%s\"}",
                     sid, (unsigned long)seq, quoted, sig);
    return n > 0 && (size_t)n < cap && (size_t)n <= HIDRA_MAX_FRAME;
}
bool hidra_decode(const char *sid, uint32_t seq, const char *direction, const char *line,
                  hidra_mac_fn mac, void *user, char *body, size_t cap) {
    hidra_object_t object;
    uint32_t version, received_seq;
    char received_sid[65], received_sig[65], expected[65];
    if (!hidra_parse(line, &object) || object.count != 5 ||
        !hidra_uint(&object, "v", &version) || version != 2 ||
        !hidra_uint(&object, "seq", &received_seq) || received_seq != seq ||
        !hidra_string(&object, "sid", received_sid, sizeof(received_sid)) || strcmp(sid, received_sid) ||
        !hidra_string(&object, "sig", received_sig, sizeof(received_sig)) || !hidra_hex64(received_sig) ||
        !hidra_string(&object, "body", body, cap) ||
        !signature(sid, seq, direction, body, mac, user, expected)) return false;
    /* Fixed-length comparison; volatile accumulator prevents early-exit replacement. */
    volatile unsigned difference = 0;
    for (unsigned i = 0; i < 64; ++i) difference |= (unsigned)(expected[i] ^ received_sig[i]);
    return difference == 0 && hidra_parse(body, &object);
}
bool hidra_command(const char *body, char action[16], char payload[257]) {
    hidra_object_t object;
    if (!hidra_parse(body, &object) || !hidra_string(&object, "action", action, 16)) return false;
    payload[0] = 0;
    if (!strcmp(action, "ping") || !strcmp(action, "exit") || !strcmp(action, "terminate"))
        return object.count == 1;
    bool key = !strcmp(action, "key");
    if (strcmp(action, "type") && strcmp(action, "delay") && !key) return false;
    if (object.count != 2 || !hidra_string(&object, key ? "keys" : "text", payload, 257)) return false;
    size_t len = strlen(payload);
    if (!strcmp(action, "type")) {
        if (!len) return false;
        for (size_t i = 0; i < len; ++i)
            if (payload[i] != '\n' && payload[i] != '\t' && (payload[i] < 32 || payload[i] > 126)) return false;
        return true;
    }
    if (!strcmp(action, "delay")) {
        if (!len || len > 4 || (len > 1 && payload[0] == '0')) return false;
        unsigned ms = 0;
        for (size_t i = 0; i < len; ++i) {
            if (payload[i] < '0' || payload[i] > '9') return false;
            ms = ms * 10 + (unsigned)(payload[i] - '0');
        }
        return ms <= 5000;
    }
    if (!len || len > 63) return false;
    const char *modifiers[] = {"CTRL", "CONTROL", "SHIFT", "ALT", "WIN", "GUI"};
    const char *keys[] = {"ENTER","ESC","TAB","SPACE","DEL","BACKSPACE","HOME","END",
                         "PGUP","PGDN","UP","DOWN","LEFT","RIGHT","F1","F2","F3","F4",
                         "F5","F6","F7","F8","F9","F10","F11","F12"};
    char copy[64]; memcpy(copy, payload, len + 1);
    char *tokens[8]; unsigned count = 0, normal = 0;
    char *cursor = copy;
    for (;;) {
        if (count == 8 || !*cursor) return false;
        char *end = strchr(cursor, ' ');
        if (end) *end = 0;
        if (!*cursor) return false;
        for (unsigned i = 0; i < count; ++i) if (!strcmp(tokens[i], cursor)) return false;
        tokens[count++] = cursor;
        bool modifier = false, known = false;
        for (unsigned i = 0; i < sizeof(modifiers)/sizeof(*modifiers); ++i)
            if (!strcmp(cursor, modifiers[i])) modifier = true;
        if (!modifier) {
            ++normal;
            for (unsigned i = 0; i < sizeof(keys)/sizeof(*keys); ++i)
                if (!strcmp(cursor, keys[i])) known = true;
            char c = cursor[0];
            if (!known && !(cursor[1] == 0 && ((c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))) return false;
        }
        if (!end) break;
        cursor = end + 1;
    }
    return normal == 1;
}
bool hidra_rate_allow(uint32_t now, uint32_t timestamps[30], unsigned *count) {
    if (*count > 30) return false;
    unsigned retained = 0;
    for (unsigned i = 0; i < *count; ++i)
        if ((uint32_t)(now - timestamps[i]) < 60000u) timestamps[retained++] = timestamps[i];
    *count = retained;
    if (retained == 30) return false;
    timestamps[(*count)++] = now;
    return true;
}
