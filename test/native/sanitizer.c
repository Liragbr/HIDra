#include "protocol.h"
#include "hid_queue.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

static hid_queue_t queue;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static void enter(void *m) { assert(pthread_mutex_lock(m) == 0); }
static void leave(void *m) { assert(pthread_mutex_unlock(m) == 0); }
static void enable(hid_queue_t *q, void *unused) { (void)unused; q->enabled = true; }
static unsigned consumed;
static void consume(hid_queue_t *q, void *unused) {
    (void)unused;
    if (q->tail != q->head) {
        hid_key_t key = q->records[q->tail];
        assert(key.delay_ms == (uint16_t)consumed);
        assert(key.modifier == (uint8_t)(consumed >> 16));
        assert(key.keycode == (uint8_t)consumed);
        ++consumed;
        q->tail = (q->tail + 1) % RING_CAP;
    }
}
static void *producer(void *unused) {
    (void)unused;
    for (unsigned i = 0; i < 100000; ++i) {
        hid_key_t key = {(uint8_t)(i >> 16), (uint8_t)i, (uint16_t)i};
        while (!hid_queue_push(&queue, key)) sched_yield();
    }
    return NULL;
}
static void *consumer(void *unused) {
    (void)unused;
    while (consumed < 100000) { hid_queue_visit(&queue, consume, NULL); sched_yield(); }
    return NULL;
}
static bool dummy_mac(void *unused, const char *msg, size_t len, char out[65]) {
    (void)unused; (void)msg; (void)len;
    memset(out, 'a', 64); out[64] = 0; return true;
}
int main(void) {
    hid_queue_init(&queue, enter, leave, &mutex);
    assert(!hid_queue_push(&queue, (hid_key_t){0,1,0}));
    hid_queue_visit(&queue, enable, NULL);
    for (unsigned i = 0; i < 63; ++i) assert(hid_queue_push(&queue, (hid_key_t){0,1,0}));
    assert(!hid_queue_push(&queue, (hid_key_t){0,1,0}));
    hid_queue_cancel(&queue);
    assert(queue.head == queue.tail && queue.generation == 1);
    pthread_t p, c;
    assert(pthread_create(&p, NULL, producer, NULL) == 0);
    assert(pthread_create(&c, NULL, consumer, NULL) == 0);
    assert(pthread_join(p, NULL) == 0 && pthread_join(c, NULL) == 0);
    assert(consumed == 100000 && queue.head == queue.tail);
    hid_queue_cancel(&queue);
    assert(queue.generation == 2);

    char sid[65], line[2049], out[769], action[16], payload[257];
    memset(sid, '1', 64); sid[64] = 0;
    assert(hidra_encode(sid, 1, "s2a", "{\"action\":\"ping\"}", dummy_mac, NULL, line, sizeof(line)));
    size_t length = strlen(line);
    for (size_t i = 0; i < length; ++i) {
        char truncated[2049]; memcpy(truncated, line, i); truncated[i] = 0;
        assert(!hidra_decode(sid, 1, "s2a", truncated, dummy_mac, NULL, out, sizeof(out)));
    }
    /* Deterministic malformed corpus. These exercise actual parsers, never HID hardware. */
    uint32_t state = 0x12345678;
    for (unsigned iteration = 0; iteration < 50000; ++iteration) {
        state = state * 1664525u + 1013904223u;
        size_t n = state % 2049u;
        for (size_t i = 0; i < n; ++i) {
            state = state * 1664525u + 1013904223u;
            line[i] = (char)(1u + (state >> 24) % 127u);
        }
        line[n] = 0;
        hidra_object_t object;
        (void)hidra_parse(line, &object);
        (void)hidra_decode(sid, 1, "s2a", line, dummy_mac, NULL, out, sizeof(out));
        (void)hidra_command(line, action, payload);
        if (n < HIDRA_MAX_BODY) (void)hidra_quote(line, out, sizeof(out));
    }
    puts("PASS: queue capacity/cancel/FIFO with 100000 concurrent records; 50000 parser cases; all truncations");
    return 0;
}
