/*
 * Naive substring search with a first-byte filter and memcmp, counting every occurrence of short needles in a
 * DNA-like haystack, as a log filter or a signature matcher does without a fancier algorithm.
 */
#include "corpus.h"

#define HAY 768

static u8 hay[HAY];
static const u8 letters[4] = {'a', 'c', 'g', 't'};

static s32 compare(const u8 *x, const u8 *y, u32 n) {
    for (u32 i = 0; i < n; i++)
        if (x[i] != y[i])
            return x[i] - y[i];
    return 0;
}

/* The first position at or after `from` where `needle` occurs, or -1. */
static s32 find(const u8 *h, u32 hlen, const u8 *needle, u32 nlen, u32 from) {
    for (u32 i = from; i + nlen <= hlen; i++)
        if (h[i] == needle[0] && compare(h + i + 1, needle + 1, nlen - 1) == 0)
            return i;
    return -1;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    for (u32 i = 0; i < HAY; i += 32) {
        u64 x = rng_next(&rng);
        for (u32 j = 0; j < 32; j++)
            hay[i + j] = letters[x >> (2 * j) & 3];
    }

    u64 acc = 0;
    for (u32 k = 0; k < 12; k++) {
        u8 needle[8];
        u64 x = rng_next(&rng);
        u32 len = 3 + x % 4;
        for (u32 j = 0; j < len; j++)
            needle[j] = letters[x >> (8 + 2 * j) & 3];
        u32 count = 0;
        for (s32 at = find(hay, HAY, needle, len, 0); at >= 0; at = find(hay, HAY, needle, len, at + 1)) {
            acc += at;
            count++;
        }
        acc = acc * 31 + count;
    }
    return acc;
}
