#ifndef HIDRA_QUEUE_H
#define HIDRA_QUEUE_H
#include <stdbool.h>
#include <stdint.h>
#define RING_CAP 64u
typedef struct { uint8_t modifier, keycode; uint16_t delay_ms; } hid_key_t;
typedef void (*hid_lock_fn)(void *);
typedef struct hid_queue {
    hid_key_t records[RING_CAP];
    unsigned head, tail;
    uint32_t generation;
    bool enabled;
    hid_lock_fn enter, leave;
    void *lock;
} hid_queue_t;
void hid_queue_init(hid_queue_t *, hid_lock_fn, hid_lock_fn, void *);
bool hid_queue_push(hid_queue_t *, hid_key_t);
bool hid_queue_enabled(hid_queue_t *);
void hid_queue_cancel(hid_queue_t *);
/* Visitor runs under the same lock as producer/cancellation. Never block or re-enter. */
void hid_queue_visit(hid_queue_t *, void (*visitor)(hid_queue_t *, void *), void *);
#endif
