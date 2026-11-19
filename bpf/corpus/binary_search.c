/*
 * Lower-bound binary search in a sorted table, as a lookup of rules, symbols or ranges does it: builds 512 increasing
 * keys, then looks up random targets and counts the hits.
 */
#include "corpus.h"

#define KEYS 512

static u32 keys[KEYS];

static u32 lower_bound(const u32 *a, u32 n, u32 target) {
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (a[mid] < target)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    u32 key = 0;
    for (u32 i = 0; i < KEYS; i++) {
        key += 1 + rng_next(&rng) % 16;
        keys[i] = key;
    }

    u64 hits = 0, sum = 0;
    for (u32 q = 0; q < 800; q++) {
        u32 target = rng_next(&rng) % (key + 16);
        u32 at = lower_bound(keys, KEYS, target);
        hits += at < KEYS && keys[at] == target;
        sum += at;
    }
    return hits << 32 | sum;
}
