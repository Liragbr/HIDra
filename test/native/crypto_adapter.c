#include "protocol.h"
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
static bool mac(void *secret, const char *data, size_t length, char output[65]) {
    unsigned char digest[32]; unsigned n = 0;
    if (!HMAC(EVP_sha256(), secret, (int)strlen(secret), (const unsigned char *)data,
              length, digest, &n) || n != 32) return false;
    for (unsigned i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", digest[i]);
    return true;
}
bool test_encode(const char *secret, const char *sid, uint32_t seq, const char *direction,
                 const char *body, char *out, size_t size) {
    return hidra_encode(sid, seq, direction, body, mac, (void *)secret, out, size);
}
bool test_decode(const char *secret, const char *sid, uint32_t seq, const char *direction,
                 const char *line, char *out, size_t size) {
    return hidra_decode(sid, seq, direction, line, mac, (void *)secret, out, size);
}
