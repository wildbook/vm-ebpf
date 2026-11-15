/*
 * One array map, `hits`, for sharing between plugins. Build:
 *   clang -target bpf -mcpu=v3 -O2 -g -c bpf/shared_counter.c -o bpf/shared_counter.o
 *   clang -target bpf -mcpu=v3 -O2 -g -DVALUE=u32 -c bpf/shared_counter.c -o bpf/shared_counter_u32.o
 */
typedef unsigned int u32;
typedef unsigned long long u64;

#ifndef VALUE
#define VALUE u64
#endif

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    __uint(type, 2 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, VALUE);
} hits SEC(".maps");

/* Atomically count a hit and return the new total. */
u64 bump(void) {
    u32 key = 0;
    VALUE *count = bpf_map_lookup_elem(&hits, &key);
    if (!count)
        return -1;
    return __sync_fetch_and_add(count, 1) + 1;
}
