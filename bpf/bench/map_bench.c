/*
 * Map helper throughput, for lib/rvm/benches/exec.rs.
 */
#include "rvm_bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} array SEC(".maps");

u64 hash_update(u64 n) {
    for (u64 i = 0; i < n; i++) {
        u64 key = i & 1023;
        bpf_map_update_elem(&hash, &key, &i, 0);
    }
    return 0;
}

u64 hash_lookup(u64 n) {
    u64 sum = 0;
    for (u64 i = 0; i < n; i++) {
        u64 key = i & 1023;
        u64 *value = bpf_map_lookup_elem(&hash, &key);
        if (value)
            sum += *value;
    }
    return sum;
}

u64 array_lookup(u64 n) {
    u64 sum = 0;
    for (u64 i = 0; i < n; i++) {
        u32 key = i & 1023;
        u64 *value = bpf_map_lookup_elem(&array, &key);
        if (value)
            sum += *value;
    }
    return sum;
}
