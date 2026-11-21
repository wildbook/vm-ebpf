/*
 * The ChaCha20 block function (RFC 8439): 16 state words, 10 double rounds of quarter rounds, then the input added
 * back, as a stream cipher or a random generator in a plugin runs it over a counter.
 */
#include "corpus.h"

#define ROTL(x, n) ((x) << (n) | (x) >> (32 - (n)))
#define QR(a, b, c, d)                                                                                             \
    a += b; d ^= a; d = ROTL(d, 16);                                                                               \
    c += d; b ^= c; b = ROTL(b, 12);                                                                               \
    a += b; d ^= a; d = ROTL(d, 8);                                                                                \
    c += d; b ^= c; b = ROTL(b, 7)

static u32 key[8], nonce[3];

static void block(u32 counter, u32 out[16]) {
    u32 x0 = 0x61707865, x1 = 0x3320646e, x2 = 0x79622d32, x3 = 0x6b206574;
    u32 x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
    u32 x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
    u32 x12 = counter, x13 = nonce[0], x14 = nonce[1], x15 = nonce[2];
    for (u32 i = 0; i < 10; i++) {
        QR(x0, x4, x8, x12);
        QR(x1, x5, x9, x13);
        QR(x2, x6, x10, x14);
        QR(x3, x7, x11, x15);
        QR(x0, x5, x10, x15);
        QR(x1, x6, x11, x12);
        QR(x2, x7, x8, x13);
        QR(x3, x4, x9, x14);
    }
    out[0] = x0 + 0x61707865;
    out[1] = x1 + 0x3320646e;
    out[2] = x2 + 0x79622d32;
    out[3] = x3 + 0x6b206574;
    out[4] = x4 + key[0];
    out[5] = x5 + key[1];
    out[6] = x6 + key[2];
    out[7] = x7 + key[3];
    out[8] = x8 + key[4];
    out[9] = x9 + key[5];
    out[10] = x10 + key[6];
    out[11] = x11 + key[7];
    out[12] = x12 + counter;
    out[13] = x13 + nonce[0];
    out[14] = x14 + nonce[1];
    out[15] = x15 + nonce[2];
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 i = 0; i < 8; i++)
        key[i] = rng_next(&rng);
    for (u32 i = 0; i < 3; i++)
        nonce[i] = rng_next(&rng);
    u32 out[16];
    for (u32 counter = 1; counter <= 24; counter++) {
        block(counter, out);
        for (u32 i = 0; i < 16; i++)
            acc = (acc << 5 | acc >> 59) ^ out[i];
    }
    return acc;
}
