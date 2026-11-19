/*
 * A single-producer, single-consumer ring of 64 entries with free-running head and tail, as an event queue between a
 * plugin and its host uses it: bursts of pushes that drop when full, and drains of random size.
 */
#include "corpus.h"

#define CAP 64

struct ring {
    u32 head;
    u32 tail;
    u64 items[CAP];
};

static struct ring ring;

static int push(struct ring *r, u64 v) {
    if (r->head - r->tail == CAP)
        return 0;
    r->items[r->head & (CAP - 1)] = v;
    r->head++;
    return 1;
}

static int pop(struct ring *r, u64 *v) {
    if (r->head == r->tail)
        return 0;
    *v = r->items[r->tail & (CAP - 1)];
    r->tail++;
    return 1;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), sum = 0, dropped = 0, popped = 0;
    for (u32 step = 0; step < 400; step++) {
        u64 r = rng_next(&rng);
        for (u32 n = r & 15; n; n--)
            dropped += !push(&ring, r ^ step * n);
        u64 v;
        for (u32 n = r >> 8 & 15; n && pop(&ring, &v); n--) {
            sum = sum * 31 + v;
            popped++;
        }
    }
    return sum ^ dropped << 48 ^ popped << 32 ^ (ring.head - ring.tail);
}
