/*
 * Passes over an array of records with fields of every width and signedness, as a plugin scans entity or connection
 * tables: per-kind totals, a filtered sum, a maximum with its id, and an in-place update.
 */
#include "corpus.h"

#define COUNT 128

struct record {
    u8 kind;
    u8 level;
    u16 flags;
    u32 id;
    u64 bytes;
    s16 delta;
    s8 bias;
    u8 tag;
    s32 score;
};

static struct record records[COUNT];

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    for (u32 i = 0; i < COUNT; i++) {
        u64 r = rng_next(&rng);
        struct record *rec = &records[i];
        rec->kind = r & 3;
        rec->level = r >> 2 & 7;
        rec->flags = r >> 5;
        rec->id = i * 7919;
        rec->bytes = r >> 21;
        rec->delta = (s16)(r >> 40);
        rec->bias = (s8)(r >> 56);
        rec->tag = r >> 8;
        rec->score = (s32)(r >> 24) >> 8;
    }

    u64 acc = 0;
    for (u32 round = 0; round < 4; round++) {
        u64 per_kind[4] = {0}, filtered = 0;
        s64 drift = 0;
        s32 best = -0x7fffffff;
        u32 best_id = 0;
        for (u32 i = 0; i < COUNT; i++) {
            const struct record *rec = &records[i];
            per_kind[rec->kind] += rec->bytes;
            if ((rec->flags & 0x8) && rec->level > 2) {
                filtered += rec->bytes >> rec->level;
                drift += rec->delta + rec->bias;
            }
            if (rec->score > best) {
                best = rec->score;
                best_id = rec->id;
            }
        }
        for (u32 i = 0; i < COUNT; i++) {
            records[i].score += records[i].delta >> 4;
            records[i].flags ^= records[i].tag;
        }
        acc = acc * 31 + (per_kind[0] ^ per_kind[1] << 1 ^ per_kind[2] << 2 ^ per_kind[3] << 3);
        acc ^= filtered + (u64)drift + ((u64)best_id << 32 | (u32)best);
    }
    return acc;
}
