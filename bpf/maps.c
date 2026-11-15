/*
 * Array and hash maps declared libbpf style, used through the standard helpers.
 * Build: clang -target bpf -mcpu=v3 -O2 -g -c bpf/maps.c -o bpf/maps.o
 */
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_ANY 0
#define BPF_NOEXIST 1

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, u64);
    __type(value, u64);
} seen SEC(".maps");

/* Count calls per bucket `x % 4` in place; returns the new count. */
u64 count(u64 x) {
    u32 bucket = x % 4;
    u64 *slot = bpf_map_lookup_elem(&counters, &bucket);
    if (!slot)
        return -1;
    __sync_fetch_and_add(slot, 1);
    return *slot;
}

/* Insert `key` once; returns the update result (0, or -EEXIST / -E2BIG). */
long remember(u64 key) {
    u64 value = key * 10;
    return bpf_map_update_elem(&seen, &key, &value, BPF_NOEXIST);
}

/* Look `key` up: its value, or -1 if absent. */
u64 recall(u64 key) {
    u64 *value = bpf_map_lookup_elem(&seen, &key);
    return value ? *value : (u64)-1;
}

long forget(u64 key) {
    return bpf_map_delete_elem(&seen, &key);
}
