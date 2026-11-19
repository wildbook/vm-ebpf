/*
 * FNV-1a, 32 and 64 bit, over keys of varied length cut from a buffer, as a hash table or a dedup filter uses it.
 */
#include "corpus.h"

#define SIZE 1024

static u8 data[SIZE];

static u32 fnv32(const u8 *p, u32 n) {
    u32 h = 0x811c9dc5;
    for (u32 i = 0; i < n; i++)
        h = (h ^ p[i]) * 0x01000193;
    return h;
}

static u64 fnv64(const u8 *p, u32 n) {
    u64 h = 0xcbf29ce484222325ULL;
    for (u32 i = 0; i < n; i++)
        h = (h ^ p[i]) * 0x100000001b3ULL;
    return h;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    for (u32 i = 0; i < SIZE; i += 8) {
        u64 x = rng_next(&rng);
        for (u32 b = 0; b < 8; b++)
            data[i + b] = x >> (8 * b);
    }

    u64 acc = 0;
    for (u32 k = 0; k < 64; k++) {
        u64 r = rng_next(&rng);
        u32 off = r % (SIZE - 64), len = 1 + (r >> 32) % 63;
        acc = acc * 31 + (fnv32(data + off, len) ^ fnv64(data + off, len));
    }
    return acc;
}
