/*
 * Shared by the corpus programs, small plugin-style workloads that each export `u64 run(u64 seed)` and return a
 * checksum. A xorshift generator stands in for bpf_get_prandom_u32, so every run is deterministic.
 */
#ifndef CORPUS_H
#define CORPUS_H

#include "rvm_bpf.h"

/* A nonzero xorshift64 state from any seed. */
static inline u64 rng_seed(u64 seed) {
    return seed * 0x9e3779b97f4a7c15ULL | 1;
}

static inline u64 rng_next(u64 *state) {
    u64 x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *state = x;
}

#endif
