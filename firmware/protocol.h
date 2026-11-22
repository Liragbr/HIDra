#ifndef HIDRA_PROTOCOL_H
#define HIDRA_PROTOCOL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define HIDRA_MAX_FRAME 2048u
#define HIDRA_MAX_BODY 768u
#define HIDRA_MAX_TEXT 256u
#define HIDRA_MAX_SEQ 2147483647u
#define HIDRA_MAX_FIELDS 8u

typedef struct {
    char key[17];
    size_t start, end;
    char type;
} hidra_field_t;
typedef struct {
    const char *json;
    hidra_field_t fields[HIDRA_MAX_FIELDS];
    unsigned count;
} hidra_object_t;
/* Callback must produce a lowercase SHA256 HMAC and return false on crypto failure. */
typedef bool (*hidra_mac_fn)(void *, const char *, size_t, char[65]);
bool hidra_parse(const char *json, hidra_object_t *out);
bool hidra_string(const hidra_object_t *, const char *, char *, size_t);
bool hidra_uint(const hidra_object_t *, const char *, uint32_t *);
bool hidra_true(const hidra_object_t *, const char *);
bool hidra_quote(const char *, char *, size_t);
bool hidra_hex64(const char *);
bool hidra_encode(const char *, uint32_t, const char *, const char *, hidra_mac_fn, void *, char *, size_t);
bool hidra_decode(const char *, uint32_t, const char *, const char *, hidra_mac_fn, void *, char *, size_t);
bool hidra_command(const char *body, char action[16], char payload[257]);
/* Unsigned elapsed subtraction remains correct across one timer wrap. */
bool hidra_rate_allow(uint32_t now, uint32_t timestamps[30], unsigned *count);
#endif
