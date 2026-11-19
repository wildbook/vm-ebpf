/*
 * Event counters in maps, the usual shape of a metrics plugin: an array map of per-type counters bumped atomically,
 * and a hash map of per-key stats found with a lookup or inserted with an update.
 */
#include "corpus.h"

struct stats {
    u64 count;
    u64 sum;
    u64 max;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} by_type SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, struct stats);
} by_key SEC(".maps");

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), failed = 0;
    for (u32 e = 0; e < 300; e++) {
        u64 r = rng_next(&rng);
        u32 type = r & 15, key = (r >> 8) % 48;
        u64 value = (r >> 20) % 1000;
        u64 *counter = bpf_map_lookup_elem(&by_type, &type);
        if (counter)
            __sync_fetch_and_add(counter, 1);

        struct stats *st = bpf_map_lookup_elem(&by_key, &key);
        if (st) {
            st->count++;
            st->sum += value;
            if (value > st->max)
                st->max = value;
        } else {
            struct stats fresh = {1, value, value};
            failed += bpf_map_update_elem(&by_key, &key, &fresh, BPF_NOEXIST) != 0;
        }
    }

    u64 acc = failed;
    for (u32 type = 0; type < 16; type++) {
        u64 *counter = bpf_map_lookup_elem(&by_type, &type);
        acc = acc * 31 + (counter ? *counter : 0);
    }
    for (u32 key = 0; key < 48; key++) {
        struct stats *st = bpf_map_lookup_elem(&by_key, &key);
        if (st)
            acc = acc * 31 + (st->count ^ st->sum << 16 ^ st->max << 40);
    }
    return acc;
}
