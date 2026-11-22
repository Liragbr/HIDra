#include "hid_queue.h"
#include <string.h>
void hid_queue_init(hid_queue_t *q, hid_lock_fn enter, hid_lock_fn leave, void *lock) {
    memset(q, 0, sizeof(*q));
    q->enter = enter; q->leave = leave; q->lock = lock;
}
bool hid_queue_push(hid_queue_t *q, hid_key_t key) {
    bool pushed = false;
    q->enter(q->lock);
    unsigned next = (q->head + 1) % RING_CAP;
    if (q->enabled && next != q->tail) {
        q->records[q->head] = key;
        q->head = next;
        pushed = true;
    }
    q->leave(q->lock);
    return pushed;
}
bool hid_queue_enabled(hid_queue_t *q) {
    q->enter(q->lock);
    bool result = q->enabled;
    q->leave(q->lock);
    return result;
}
void hid_queue_cancel(hid_queue_t *q) {
    q->enter(q->lock);
    q->tail = q->head;
    ++q->generation;
    q->leave(q->lock);
}
void hid_queue_visit(hid_queue_t *q, void (*visitor)(hid_queue_t *, void *), void *arg) {
    q->enter(q->lock);
    visitor(q, arg);
    q->leave(q->lock);
}
