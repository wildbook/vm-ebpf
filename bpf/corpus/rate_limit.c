/*
 * A token-bucket rate limiter per client in a hash map smaller than the client count: refills by elapsed ticks, drops
 * requests without a token, and sweeps out idle buckets when the map is full. The event index stands in for
 * bpf_ktime_get_ns.
 */
#include "corpus.h"

#define CLIENTS 96
#define BURST   3

struct bucket {
    u64 last;
    u32 tokens;
    u32 dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 48);
    __type(key, u32);
    __type(value, struct bucket);
} buckets SEC(".maps");

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), passed = 0, untracked = 0, swept = 0;
    for (u64 now = 0; now < 600; now++) {
        u64 r = rng_next(&rng);
        u32 client = r % CLIENTS;
        if (client >= 64)
            client = r % 16;
        struct bucket *b = bpf_map_lookup_elem(&buckets, &client);
        if (!b) {
            struct bucket fresh = {now, BURST - 1, 0};
            if (bpf_map_update_elem(&buckets, &client, &fresh, BPF_NOEXIST) == 0) {
                passed++;
                continue;
            }
            untracked++;
            for (u32 c = 0; c < CLIENTS; c++) {
                struct bucket *old = bpf_map_lookup_elem(&buckets, &c);
                if (old && now - old->last > 40) {
                    bpf_map_delete_elem(&buckets, &c);
                    swept++;
                }
            }
            continue;
        }
        u64 refill = (now - b->last) / 32;
        if (refill) {
            b->tokens = b->tokens + refill > BURST ? BURST : b->tokens + refill;
            b->last = now;
        }
        if (b->tokens) {
            b->tokens--;
            passed++;
        } else {
            b->dropped++;
        }
    }
    return passed << 40 ^ untracked << 20 ^ swept;
}
