/*
 * XXH32 over inputs of varied length and alignment, with the four-lane stripe loop, the tail in words and bytes, and
 * the final avalanche. Words are read a byte at a time, as portable code reads unaligned input.
 */
#include "corpus.h"

#define P1 0x9e3779b1u
#define P2 0x85ebca77u
#define P3 0xc2b2ae3du
#define P4 0x27d4eb2fu
#define P5 0x165667b1u

static u8 data[1024];

static u32 rotl(u32 x, u32 r) {
    return x << r | x >> (32 - r);
}

static u32 read32(const u8 *p) {
    return p[0] | p[1] << 8 | p[2] << 16 | (u32)p[3] << 24;
}

static u32 round32(u32 acc, u32 lane) {
    return rotl(acc + lane * P2, 13) * P1;
}

static u32 xxh32(const u8 *p, u32 len, u32 seed) {
    const u8 *end = p + len;
    u32 h;
    if (len >= 16) {
        u32 v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
        for (; p + 16 <= end; p += 16) {
            v1 = round32(v1, read32(p));
            v2 = round32(v2, read32(p + 4));
            v3 = round32(v3, read32(p + 8));
            v4 = round32(v4, read32(p + 12));
        }
        h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    } else {
        h = seed + P5;
    }
    h += len;
    for (; p + 4 <= end; p += 4)
        h = rotl(h + read32(p) * P3, 17) * P4;
    for (; p < end; p++)
        h = rotl(h + *p * P5, 11) * P1;
    h ^= h >> 15;
    h *= P2;
    h ^= h >> 13;
    h *= P3;
    return h ^ h >> 16;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 i = 0; i < sizeof(data); i += 8) {
        u64 x = rng_next(&rng);
        for (u32 b = 0; b < 8; b++)
            data[i + b] = x >> (8 * b);
    }
    for (u32 k = 0; k < 24; k++) {
        u64 r = rng_next(&rng);
        u32 off = r % 512, len = (r >> 16) % 300;
        acc = acc << 7 ^ acc >> 57 ^ xxh32(data + off, len, (u32)(r >> 40));
    }
    return acc;
}
