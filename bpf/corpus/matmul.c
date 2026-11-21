/*
 * 4x4 fixed-point (Q16) matrix kernels as a game or physics plugin runs them on transforms: a product with all
 * sixteen accumulators of a row block live, a transpose, and points pushed through the composed transform.
 */
#include "corpus.h"

#define N 4
typedef s32 mat[N][N];

static s32 q(s64 x) {
    return (s32)((x + (1 << 15)) >> 16);
}

static void mul(const mat a, const mat b, mat out) {
    for (u32 i = 0; i < N; i++) {
        s64 c0 = 0, c1 = 0, c2 = 0, c3 = 0;
        for (u32 k = 0; k < N; k++) {
            s64 x = a[i][k];
            c0 += x * b[k][0];
            c1 += x * b[k][1];
            c2 += x * b[k][2];
            c3 += x * b[k][3];
        }
        out[i][0] = q(c0);
        out[i][1] = q(c1);
        out[i][2] = q(c2);
        out[i][3] = q(c3);
    }
}

static void transform(const mat m, s32 p[N], s32 out[N]) {
    s64 x = p[0], y = p[1], z = p[2], w = p[3];
    out[0] = q(m[0][0] * x + m[0][1] * y + m[0][2] * z + m[0][3] * w);
    out[1] = q(m[1][0] * x + m[1][1] * y + m[1][2] * z + m[1][3] * w);
    out[2] = q(m[2][0] * x + m[2][1] * y + m[2][2] * z + m[2][3] * w);
    out[3] = q(m[3][0] * x + m[3][1] * y + m[3][2] * z + m[3][3] * w);
}

static mat world, step, tmp;

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 i = 0; i < N; i++)
        for (u32 j = 0; j < N; j++) {
            world[i][j] = i == j ? 1 << 16 : 0;
            step[i][j] = (i == j ? 1 << 16 : 0) + (s32)(rng_next(&rng) & 0x7ff) - 0x400;
        }
    for (u32 frame = 0; frame < 40; frame++) {
        mul(world, step, tmp);
        for (u32 i = 0; i < N; i++)
            for (u32 j = 0; j < N; j++)
                world[i][j] = tmp[j][i] / 2 + tmp[i][j] / 2;
        for (u32 n = 0; n < 8; n++) {
            u64 r = rng_next(&rng);
            s32 p[N] = {(s32)(r & 0xffff) << 4, (s32)(r >> 16 & 0xffff) << 4, (s32)(r >> 32 & 0xffff) << 4, 1 << 16};
            s32 out[N];
            transform(world, p, out);
            acc = (acc << 3 | acc >> 61) ^ (u32)out[0] ^ (u64)(u32)out[1] << 32 ^ (u32)out[2] ^ (u32)out[3];
        }
    }
    return acc;
}
