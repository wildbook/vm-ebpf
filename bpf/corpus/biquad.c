/*
 * A cascade of four Q14 biquad filters (direct form I) over a block of samples, as an audio or sensor plugin runs
 * an equaliser: every stage keeps two inputs and two outputs of history, so the loop has 16 state values and 20
 * coefficients live, more than the registers.
 */
#include "corpus.h"

#define STAGES 4
#define SAMPLES 512

struct coeffs {
    s32 b0, b1, b2, a1, a2;
};

static struct coeffs bank[STAGES];
static s16 in[SAMPLES], out[SAMPLES];

static s32 sat16(s64 x) {
    return x > 32767 ? 32767 : x < -32768 ? -32768 : (s32)x;
}

static u64 filter(void) {
    s32 x1a = 0, x2a = 0, y1a = 0, y2a = 0, x1b = 0, x2b = 0, y1b = 0, y2b = 0;
    s32 x1c = 0, x2c = 0, y1c = 0, y2c = 0, x1d = 0, x2d = 0, y1d = 0, y2d = 0;
    const struct coeffs a = bank[0], b = bank[1], c = bank[2], d = bank[3];
    u64 energy = 0;
    for (u32 n = 0; n < SAMPLES; n++) {
        s32 x = in[n], y;
        y = sat16(((s64)a.b0 * x + (s64)a.b1 * x1a + (s64)a.b2 * x2a - (s64)a.a1 * y1a - (s64)a.a2 * y2a) >> 14);
        x2a = x1a, x1a = x, y2a = y1a, y1a = y, x = y;
        y = sat16(((s64)b.b0 * x + (s64)b.b1 * x1b + (s64)b.b2 * x2b - (s64)b.a1 * y1b - (s64)b.a2 * y2b) >> 14);
        x2b = x1b, x1b = x, y2b = y1b, y1b = y, x = y;
        y = sat16(((s64)c.b0 * x + (s64)c.b1 * x1c + (s64)c.b2 * x2c - (s64)c.a1 * y1c - (s64)c.a2 * y2c) >> 14);
        x2c = x1c, x1c = x, y2c = y1c, y1c = y, x = y;
        y = sat16(((s64)d.b0 * x + (s64)d.b1 * x1d + (s64)d.b2 * x2d - (s64)d.a1 * y1d - (s64)d.a2 * y2d) >> 14);
        x2d = x1d, x1d = x, y2d = y1d, y1d = y;
        out[n] = (s16)y;
        energy += (u64)((s64)y * y);
    }
    return energy;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 s = 0; s < STAGES; s++) {
        u64 r = rng_next(&rng);
        /* gentle low-pass sections around unity gain */
        bank[s] = (struct coeffs){4096 + (s32)(r & 0x3ff), 8192, 4096, -(s32)(8000 + (r >> 10 & 0xfff)), 3000};
    }
    for (u32 block = 0; block < 2; block++) {
        for (u32 n = 0; n < SAMPLES; n++)
            in[n] = (s16)(rng_next(&rng) >> 50) - 8192;
        acc = (acc << 13 | acc >> 51) ^ filter();
        for (u32 n = 0; n < SAMPLES; n += 64)
            acc ^= (u16)out[n] << (n & 31);
    }
    return acc;
}
