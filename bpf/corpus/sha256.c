/*
 * SHA-256 (FIPS 180-4) over messages of varied length: padding, the 64-word message schedule and the 64-round
 * compression, as a signature check or a content hash in a plugin computes it.
 */
#include "corpus.h"

static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static u8 msg[256];

static void compress(u32 h[8], const u8 *block) {
    u32 w[64];
    for (u32 i = 0; i < 16; i++)
        w[i] = (u32)block[4 * i] << 24 | (u32)block[4 * i + 1] << 16 | (u32)block[4 * i + 2] << 8 | block[4 * i + 3];
    for (u32 i = 16; i < 64; i++) {
        u32 s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (u32 i = 0; i < 64; i++) {
        u32 t1 = hh + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        u32 t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

static u64 sha256(u32 len) {
    u32 h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    u8 block[64];
    u32 done = 0;
    for (; done + 64 <= len; done += 64)
        compress(h, msg + done);
    /* the tail, the 0x80 byte, zeros and the bit length, over one or two final blocks */
    u32 rest = len - done, blocks = rest < 56 ? 1 : 2;
    u64 bits = (u64)len * 8;
    for (u32 n = 0; n < blocks; n++) {
        for (u32 i = 0; i < 64; i++) {
            u32 at = 64 * n + i;
            u8 byte = at < rest ? msg[done + at] : at == rest ? 0x80 : 0;
            if (n == blocks - 1 && i >= 56)
                byte = bits >> (8 * (63 - i));
            block[i] = byte;
        }
        compress(h, block);
    }
    return (u64)h[0] << 32 ^ (u64)h[3] << 16 ^ h[7];
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 i = 0; i < sizeof(msg); i += 8) {
        u64 x = rng_next(&rng);
        for (u32 k = 0; k < 8; k++)
            msg[i + k] = x >> (8 * k);
    }
    for (u32 len = 0; len <= sizeof(msg); len += 37)
        acc = (acc << 7 | acc >> 57) ^ sha256(len);
    return acc;
}
