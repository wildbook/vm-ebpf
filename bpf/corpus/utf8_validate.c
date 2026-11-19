/*
 * UTF-8 validation and decoding: encodes random code points of every length, mixed with stray continuation bytes,
 * overlong forms, surrogates and truncated sequences, then decodes the bytes and counts the errors.
 */
#include "corpus.h"

#define SIZE 1024

static u8 bytes[SIZE];
static const u32 min_of[4] = {0, 0x80, 0x800, 0x10000};

static u32 put(u8 *out, u32 cp) {
    if (cp < 0x80) {
        out[0] = cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = 0xc0 | cp >> 6;
        out[1] = 0x80 | (cp & 0x3f);
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = 0xe0 | cp >> 12;
        out[1] = 0x80 | (cp >> 6 & 0x3f);
        out[2] = 0x80 | (cp & 0x3f);
        return 3;
    }
    out[0] = 0xf0 | cp >> 18;
    out[1] = 0x80 | (cp >> 12 & 0x3f);
    out[2] = 0x80 | (cp >> 6 & 0x3f);
    out[3] = 0x80 | (cp & 0x3f);
    return 4;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    u32 len = 0;
    while (len + 4 <= SIZE) {
        u64 r = rng_next(&rng);
        switch (r & 15) {
        case 0: bytes[len++] = 0x80 | (r >> 8 & 0x3f); break;    // stray continuation
        case 1: len += put(bytes + len, 0xd800 + (r >> 8 & 0x7ff)); break; // surrogate
        case 2: bytes[len++] = 0xc0 | (r >> 8 & 1); break;         // overlong lead, then whatever follows
        case 3: case 4: len += put(bytes + len, 0x80 + (r >> 8) % 0x780); break;
        case 5: case 6: len += put(bytes + len, 0x800 + (r >> 8) % 0xd000); break;
        case 7: len += put(bytes + len, 0x10000 + (r >> 8) % 0x100000); break;
        default: bytes[len++] = 0x20 + (r >> 8) % 0x5f; break;
        }
    }

    u64 sum = 0, errors = 0, points = 0;
    for (u32 i = 0; i < len;) {
        u8 c = bytes[i];
        u32 cp, need;
        if (c < 0x80) { cp = c; need = 0; }
        else if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; need = 1; }
        else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; need = 2; }
        else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; need = 3; }
        else { errors++; i++; continue; }
        u32 j = 1;
        for (; j <= need && i + j < len && (bytes[i + j] & 0xc0) == 0x80; j++)
            cp = cp << 6 | (bytes[i + j] & 0x3f);
        if (j <= need || cp < min_of[need] || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
            errors++;
            i++;
            continue;
        }
        sum = sum * 33 + cp;
        points++;
        i += j;
    }
    return sum ^ errors << 48 ^ points << 32;
}
