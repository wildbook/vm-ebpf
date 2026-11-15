/*
 * Map helper throughput, for lib/rvm/benches/exec.rs.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/map_bench.c -o bpf/map_bench.o
 */
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;

struct {
    __uint(type, 1 /* hash */);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} hash SEC(".maps");

struct {
    __uint(type, 2 /* array */);
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
