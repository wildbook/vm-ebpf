/*
 * Greatest common divisors two ways, Euclid's remainder loop and Stein's binary algorithm, on pairs with a shared
 * factor, plus the least common multiple, as ratio and timer arithmetic does.
 */
#include "corpus.h"

static u64 gcd_euclid(u64 a, u64 b) {
    while (b) {
        u64 t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/* Trailing zero bits of a nonzero x. */
static u64 trailing_zeros(u64 x) {
    u64 n = 0;
    while (!(x & 1)) {
        x >>= 1;
        n++;
    }
    return n;
}

static u64 gcd_binary(u64 a, u64 b) {
    if (!a || !b)
        return a | b;
    u64 shift = trailing_zeros(a | b);
    a >>= trailing_zeros(a);
    do {
        b >>= trailing_zeros(b);
        if (a > b) {
            u64 t = a;
            a = b;
            b = t;
        }
        b -= a;
    } while (b);
    return a << shift;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0, bad = 0;
    for (u32 i = 0; i < 120; i++) {
        u64 m = 1 + rng_next(&rng) % 5000;
        u64 a = (rng_next(&rng) >> 36) * m, b = (rng_next(&rng) >> 40) * m;
        u64 g = gcd_euclid(a, b);
        bad += g != gcd_binary(a, b);
        acc = acc * 31 + g;
        if (g)
            acc ^= a / g * b;
    }
    return acc + bad;
}
