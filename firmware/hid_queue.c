#include "hid_queue.h"
#include <string.h>
void hid_queue_init(hid_queue_t *q, hid_lock_fn enter, hid_lock_fn leave, void *lock) {
    memset(q, 0, sizeof(*q));
    q->enter = enter; q->leave = leave; q->lock = lock;
}
uint32_t hid_queue_generation(hid_queue_t *q) {
    q->enter(q->lock);
    uint32_t generation = q->generation;
    q->leave(q->lock);
    return generation;
}
bool hid_queue_push(hid_queue_t *q, hid_key_t key, uint32_t generation) {
    bool pushed = false;
    q->enter(q->lock);
    unsigned next = (q->head + 1) % RING_CAP;
    if (q->enabled && q->generation == generation && next != q->tail) {
        q->records[q->head] = key;
        q->head = next;
        pushed = true;
    }
    q->leave(q->lock);
    return pushed;
}
bool hid_queue_active(hid_queue_t *q, uint32_t generation) {
    q->enter(q->lock);
    bool result = q->enabled && q->generation == generation;
    q->leave(q->lock);
    return result;
}
bool hid_queue_idle(hid_queue_t *q, uint32_t generation) {
    q->enter(q->lock);
    bool idle = q->enabled && q->generation == generation && !q->busy && q->head == q->tail;
    q->leave(q->lock);
    return idle;
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
