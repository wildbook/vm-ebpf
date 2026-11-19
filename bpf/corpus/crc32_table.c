/*
 * CRC-32 (IEEE, reflected) with a 256-entry table built on the first call, over packets of varied length.
 */
#include "corpus.h"

static u32 table[256];
static u32 table_ready;
static u8 packet[1536];

static void build_table(void) {
    for (u32 i = 0; i < 256; i++) {
        u32 c = i;
        for (u32 k = 0; k < 8; k++)
            c = c & 1 ? 0xedb88320 ^ c >> 1 : c >> 1;
        table[i] = c;
    }
    table_ready = 1;
}

static u32 crc32(const u8 *p, u32 len) {
    u32 c = ~0u;
    for (u32 i = 0; i < len; i++)
        c = table[(c ^ p[i]) & 0xff] ^ c >> 8;
    return ~c;
}

u64 run(u64 seed) {
    if (!table_ready)
        build_table();
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 round = 0; round < 6; round++) {
        u32 len = 64 + rng_next(&rng) % (sizeof(packet) - 64);
        for (u32 i = 0; i < len; i += 4) {
            u32 x = rng_next(&rng);
            packet[i] = x;
            packet[i + 1] = x >> 8;
            packet[i + 2] = x >> 16;
            packet[i + 3] = x >> 24;
        }
        acc = acc << 32 ^ acc >> 32 ^ crc32(packet, len);
    }
    return acc;
}
