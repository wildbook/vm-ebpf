/*
 * Integer square roots two ways, digit by digit in base 4 and by Newton's iteration, checked against each other and
 * against r*r <= n < (r+1)*(r+1), as distance and variance code computes them without floats.
 */
#include "corpus.h"

static u64 isqrt_bits(u64 n) {
    u64 r = 0, bit = 1ULL << 62;
    while (bit > n)
        bit >>= 2;
    while (bit) {
        if (n >= r + bit) {
            n -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    return r;
}

static u64 isqrt_newton(u64 n) {
    if (n < 2)
        return n;
    u64 x = n, y = x / 2 + (x & 1);
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0, bad = 0;
    for (u32 i = 0; i < 160; i++) {
        u64 n = rng_next(&rng) >> (i % 64);
        u64 r = isqrt_bits(n);
        bad += r != isqrt_newton(n);
        // r < 2^32, so (r + 1)^2 only overflows when r + 1 == 2^32
        bad += r * r > n || (r + 1 < (1ULL << 32) && (r + 1) * (r + 1) <= n);
        acc = acc * 31 + r;
    }
    return acc + (bad << 56);
}
