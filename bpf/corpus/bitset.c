/*
 * Operations on 1024-bit sets: set, clear and test bits, combine two sets word by word, count bits, and walk the set
 * bits of the intersection with a de Bruijn lowest-bit index.
 */
#include "corpus.h"

#define WORDS 16

static u64 a[WORDS], b[WORDS];
static const u8 debruijn[64] = {
    0,  1,  48, 2,  57, 49, 28, 3,  61, 58, 50, 42, 38, 29, 17, 4,  62, 55, 59, 36, 53, 51,
    43, 22, 45, 39, 33, 30, 24, 18, 12, 5,  63, 47, 56, 27, 60, 41, 37, 16, 54, 35, 52, 21,
    44, 32, 23, 11, 46, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9,  13, 8,  7,  6,
};

static u32 lowest(u64 x) {
    return debruijn[((x & -x) * 0x03f79d71b4ca8b09ULL) >> 58];
}

static u64 count(u64 x) {
    x -= x >> 1 & 0x5555555555555555ULL;
    x = (x & 0x3333333333333333ULL) + (x >> 2 & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
    return x * 0x0101010101010101ULL >> 56;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    for (u32 i = 0; i < WORDS; i++) {
        a[i] = rng_next(&rng) & rng_next(&rng);
        b[i] = rng_next(&rng) | rng_next(&rng);
    }
    u64 tested = 0;
    for (u32 k = 0; k < 300; k++) {
        u64 r = rng_next(&rng);
        u32 bit = r & 1023;
        if (r >> 10 & 1)
            a[bit / 64] |= 1ULL << (bit % 64);
        else
            b[bit / 64] &= ~(1ULL << (bit % 64));
        tested += a[(r >> 16 & 1023) / 64] >> (r >> 16 & 63) & 1;
    }

    u64 both = 0, either = 0, differ = 0, walk = 0;
    for (u32 i = 0; i < WORDS; i++) {
        both += count(a[i] & b[i]);
        either += count(a[i] | b[i]);
        differ += count(a[i] ^ b[i]);
        for (u64 x = a[i] & b[i]; x; x &= x - 1)
            walk = walk * 7 + i * 64 + lowest(x);
    }
    return walk ^ both << 48 ^ either << 36 ^ differ << 24 ^ tested;
}
