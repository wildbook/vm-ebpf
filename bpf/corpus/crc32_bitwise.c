/*
 * CRC-32C (Castagnoli, reflected) a bit at a time with a branch-free mask, as code too small for a table computes it.
 */
#include "corpus.h"

static u8 msg[512];

static u32 crc32c(const u8 *p, u32 len) {
    u32 c = ~0u;
    for (u32 i = 0; i < len; i++) {
        c ^= p[i];
        for (u32 k = 0; k < 8; k++)
            c = c >> 1 ^ (0x82f63b78 & -(c & 1));
    }
    return ~c;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 i = 0; i < sizeof(msg); i++)
        msg[i] = rng_next(&rng);
    for (u32 round = 0; round < 4; round++) {
        u32 off = rng_next(&rng) % 256;
        acc = acc * 0x9e3779b97f4a7c15ULL + crc32c(msg + off, sizeof(msg) - off);
    }
    return acc;
}
