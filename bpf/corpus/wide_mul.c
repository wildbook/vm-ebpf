/*
 * Wide arithmetic without __int128: a 64x64 to 128 multiply through 32-bit halves, add with carry, and a 256x256 to
 * 512 schoolbook multiply over 64-bit limbs, as big-integer and crypto code does.
 */
#include "corpus.h"

#define LIMBS 4

static void mul64(u64 a, u64 b, u64 *hi, u64 *lo) {
    u64 a0 = (u32)a, a1 = a >> 32, b0 = (u32)b, b1 = b >> 32;
    u64 p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    u64 mid = (p00 >> 32) + (u32)p01 + (u32)p10;
    *lo = mid << 32 | (u32)p00;
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

/* r += x, returning the carry out. */
static u64 add_carry(u64 *r, u64 x) {
    *r += x;
    return *r < x;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 round = 0; round < 48; round++) {
        u64 a[LIMBS], b[LIMBS], r[2 * LIMBS];
        for (u32 i = 0; i < LIMBS; i++) {
            a[i] = rng_next(&rng);
            b[i] = rng_next(&rng);
            r[i] = r[i + LIMBS] = 0;
        }
        for (u32 i = 0; i < LIMBS; i++) {
            u64 carry = 0;
            for (u32 j = 0; j < LIMBS; j++) {
                u64 hi, lo;
                mul64(a[i], b[j], &hi, &lo);
                hi += add_carry(&lo, carry);
                hi += add_carry(&lo, r[i + j]);
                r[i + j] = lo;
                carry = hi;
            }
            r[i + LIMBS] = carry;
        }
        for (u32 k = 0; k < 2 * LIMBS; k++)
            acc = (acc << 1 | acc >> 63) ^ r[k];
    }
    return acc;
}
