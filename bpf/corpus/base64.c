/*
 * Base64 (RFC 4648): encodes random bytes with the standard alphabet and padding, decodes the text with a character
 * classifier that rejects bad input, and checks the round trip.
 */
#include "corpus.h"

#define MAX 190

static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static u8 raw[MAX];
static u8 text[(MAX + 2) / 3 * 4];
static u8 back[MAX];

static s32 sextet(u8 c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static u32 encode(u32 n) {
    u32 len = 0;
    for (u32 i = 0; i < n; i += 3) {
        u32 left = n - i;
        u32 v = raw[i] << 16 | (left > 1 ? raw[i + 1] << 8 : 0) | (left > 2 ? raw[i + 2] : 0);
        text[len++] = alphabet[v >> 18];
        text[len++] = alphabet[v >> 12 & 63];
        text[len++] = left > 1 ? alphabet[v >> 6 & 63] : '=';
        text[len++] = left > 2 ? alphabet[v & 63] : '=';
    }
    return len;
}

/* The decoded length, or -1 if the text isn't valid base64. */
static s32 decode(u32 len) {
    u32 n = 0;
    for (u32 i = 0; i + 4 <= len; i += 4) {
        s32 a = sextet(text[i]), b = sextet(text[i + 1]);
        s32 c = text[i + 2] == '=' ? 0 : sextet(text[i + 2]);
        s32 d = text[i + 3] == '=' ? 0 : sextet(text[i + 3]);
        if ((a | b | c | d) < 0)
            return -1;
        u32 v = a << 18 | b << 12 | c << 6 | d;
        back[n++] = v >> 16;
        if (text[i + 2] != '=')
            back[n++] = v >> 8;
        if (text[i + 3] != '=')
            back[n++] = v;
    }
    return n;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), sum = 0;
    for (u32 round = 0; round < 6; round++) {
        u32 n = MAX - rng_next(&rng) % 8;
        for (u32 i = 0; i < n; i++)
            raw[i] = rng_next(&rng) >> 56;
        s32 got = decode(encode(n));
        if (got != (s32)n)
            return ~0ULL;
        for (u32 i = 0; i < n; i++)
            sum = sum * 33 + (back[i] ^ raw[i]) + back[i];
    }
    return sum;
}
