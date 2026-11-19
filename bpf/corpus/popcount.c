/*
 * Population count three ways without builtins: the SWAR reduction, Kernighan's clear-lowest-bit loop and a nibble
 * table, plus parity, over words of varied density.
 */
#include "corpus.h"

static const u8 nibble[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};

static u64 swar(u64 x) {
    x -= x >> 1 & 0x5555555555555555ULL;
    x = (x & 0x3333333333333333ULL) + (x >> 2 & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
    return x * 0x0101010101010101ULL >> 56;
}

static u64 kernighan(u64 x) {
    u64 n = 0;
    for (; x; x &= x - 1)
        n++;
    return n;
}

static u64 by_table(u64 x) {
    u64 n = 0;
    for (; x; x >>= 4)
        n += nibble[x & 15];
    return n;
}

static u64 parity(u64 x) {
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    return 0x6996 >> (x & 15) & 1;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), total = 0, odd = 0, bad = 0;
    for (u32 i = 0; i < 256; i++) {
        u64 x = rng_next(&rng);
        x = i & 1 ? x & rng_next(&rng) : x >> (i & 63);
        u64 n = swar(x);
        bad += n != kernighan(x) || n != by_table(x) || (n & 1) != parity(x);
        total += n;
        odd += parity(x);
    }
    return total << 32 | odd << 16 | bad;
}
