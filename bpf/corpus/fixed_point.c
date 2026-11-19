/*
 * Q16.16 fixed point as a game or audio plugin without floats uses it: a rounding multiply, a divide, a polynomial
 * sine, and a damped spring driven by a sine force, stepped through time.
 */
#include "corpus.h"

typedef s32 fix;

#define ONE    (1 << 16)
#define PI     205887
#define TWO_PI 411775

static fix fmul(fix a, fix b) {
    return (fix)(((s64)a * b + (1 << 15)) >> 16);
}

static fix fdiv(fix a, fix b) {
    return (fix)((s64)a * ONE / b);
}

/* sin(x) for x in [-pi, pi], Taylor to x^7. */
static fix fsin(fix x) {
    fix x2 = fmul(x, x);
    return fmul(x, ONE - fmul(x2, ONE / 6 - fmul(x2, ONE / 120 - fmul(x2, ONE / 5040))));
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    fix pos = (fix)(rng_next(&rng) % (8 * ONE)) - 4 * ONE;
    fix vel = 0, phase = 0;
    fix stiffness = 2 * ONE + (fix)(rng_next(&rng) % ONE);
    fix damping = ONE / 8, mass = ONE + (fix)(rng_next(&rng) % (2 * ONE));
    fix omega = ONE / 10 + (fix)(rng_next(&rng) % (ONE / 4)), dt = ONE / 50;
    for (u32 step = 0; step < 600; step++) {
        fix force = fmul(ONE / 2, fsin(phase)) - fmul(stiffness, pos) - fmul(damping, vel);
        vel += fmul(fdiv(force, mass), dt);
        pos += fmul(vel, dt);
        phase += omega;
        if (phase > PI)
            phase -= TWO_PI;
        acc = acc * 31 + (u32)pos;
    }
    return acc ^ (u64)(u32)vel << 32;
}
