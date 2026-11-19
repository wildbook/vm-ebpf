/*
 * strtol-style integer parsing: leading spaces, a sign, a 0x or 0 prefix for hex and octal, digits up to the first
 * other character, and saturation on overflow. The input is a comma-separated list formatted from the seed.
 */
#include "corpus.h"

#define COUNT 64

static const char digits[] = "0123456789abcdef";
static u8 text[COUNT * 28];

static s32 digit_value(u8 c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f')
        return (c | 0x20) - 'a' + 10;
    return 99;
}

static s64 parse(const u8 **cursor) {
    const u8 *p = *cursor;
    while (*p == ' ' || *p == '\t')
        p++;
    u64 negative = *p == '-';
    if (*p == '-' || *p == '+')
        p++;
    u32 base = 10;
    if (p[0] == '0' && (p[1] | 0x20) == 'x') {
        base = 16;
        p += 2;
    } else if (p[0] == '0') {
        base = 8;
    }
    u64 limit = negative ? (u64)1 << 63 : ((u64)1 << 63) - 1;
    u64 cutoff = limit / base, cutlim = limit % base, acc = 0;
    u32 overflow = 0;
    for (s32 d; (d = digit_value(*p)) < (s32)base; p++) {
        if (acc > cutoff || (acc == cutoff && (u64)d > cutlim))
            overflow = 1;
        else
            acc = acc * base + d;
    }
    *cursor = p;
    if (overflow)
        acc = limit;
    return negative ? (s64)(0 - acc) : (s64)acc;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    u32 len = 0;
    for (u32 i = 0; i < COUNT; i++) {
        u64 r = rng_next(&rng), v = rng_next(&rng) >> (r & 63);
        u32 base = (r >> 8 & 3) == 0 ? 16 : (r >> 8 & 3) == 1 ? 8 : 10;
        for (u32 s = r >> 10 & 3; s; s--)
            text[len++] = ' ';
        if (r >> 12 & 1)
            text[len++] = '-';
        if (base != 10)
            text[len++] = '0';
        if (base == 16)
            text[len++] = 'x';
        u8 rev[22];
        u32 n = 0;
        do {
            rev[n++] = digits[v % base];
            v /= base;
        } while (v);
        while (n)
            text[len++] = rev[--n];
        text[len++] = ',';
    }
    text[len] = 0;

    u64 hash = 0;
    for (const u8 *p = text; *p; p++)
        hash = (hash ^ (u64)parse(&p)) * 0x100000001b3ULL;
    return hash;
}
