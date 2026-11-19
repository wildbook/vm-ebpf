/*
 * LEB128 varints as DWARF and WebAssembly use them: encodes a batch of unsigned and signed values of mixed sizes, then
 * decodes the stream and checks every value.
 */
#include "corpus.h"

#define COUNT 256

static u8 stream[COUNT * 10];
static u64 values[COUNT];

static u64 put_uleb(u8 *out, u64 v) {
    u64 n = 0;
    do {
        u8 byte = v & 0x7f;
        v >>= 7;
        out[n++] = byte | (v ? 0x80 : 0);
    } while (v);
    return n;
}

static u64 put_sleb(u8 *out, s64 v) {
    u64 n = 0;
    for (;;) {
        u8 byte = v & 0x7f;
        v >>= 7;
        if ((v == 0 && !(byte & 0x40)) || (v == -1 && (byte & 0x40))) {
            out[n++] = byte;
            return n;
        }
        out[n++] = byte | 0x80;
    }
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), len = 0;
    for (u32 i = 0; i < COUNT; i++) {
        u64 v = rng_next(&rng) >> (rng_next(&rng) & 63);
        if (i & 1) {
            s64 sv = (i & 2) ? -(s64)(v >> 1) : (s64)(v >> 1);
            values[i] = (u64)sv;
            len += put_sleb(stream + len, sv);
        } else {
            values[i] = v;
            len += put_uleb(stream + len, v);
        }
    }

    u64 pos = 0, hash = 0, bad = 0;
    for (u32 i = 0; i < COUNT; i++) {
        u64 v = 0, shift = 0;
        u8 byte;
        do {
            byte = stream[pos++];
            if (shift < 64)
                v |= (u64)(byte & 0x7f) << shift;
            shift += 7;
        } while (byte & 0x80);
        if ((i & 1) && shift < 64 && (byte & 0x40))
            v |= ~0ULL << shift;
        bad += v != values[i];
        hash = (hash ^ v) * 0x100000001b3ULL;
    }
    return hash + len * 3 + bad * 1000003;
}
