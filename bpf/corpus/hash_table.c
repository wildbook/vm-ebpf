/*
 * An open-addressing hash table with linear probing in .bss, counting how often each key of a small key space occurs,
 * as a dedup cache or a per-flow counter does. Each call starts a new epoch instead of clearing the table.
 */
#include "corpus.h"

#define SLOTS 256

struct slot {
    u32 key;
    u32 count;
    u32 epoch;
};

static struct slot table[SLOTS];
static u32 epoch;

static struct slot *find(u32 key, u64 *probes) {
    u32 i = (key * 2654435761u) >> 24;
    for (;;) {
        struct slot *s = &table[i];
        if (s->epoch != epoch || s->key == key)
            return s;
        i = (i + 1) & (SLOTS - 1);
        (*probes)++;
    }
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), probes = 0, distinct = 0, hits = 0;
    epoch++;
    for (u32 i = 0; i < 180; i++) {
        u32 key = rng_next(&rng) % 400;
        struct slot *s = find(key, &probes);
        if (s->epoch != epoch) {
            s->epoch = epoch;
            s->key = key;
            s->count = 0;
            distinct++;
        }
        s->count++;
    }
    for (u32 i = 0; i < 400; i++) {
        struct slot *s = find(rng_next(&rng) % 400, &probes);
        if (s->epoch == epoch)
            hits += s->count;
    }
    return distinct << 48 | hits << 24 | probes;
}
