/*
 * Counter plugin for lib/rvm/examples/hot_reload.rs. `hit` adds STEP to the total of an id. Version 1 steps by 1; the
 * COUNTER_V2 build is version 2 and steps by 10.
 */
#include "rvm_bpf.h"

#ifdef COUNTER_V2
#define VERSION 2
#define STEP    10
#else
#define VERSION 1
#define STEP    1
#endif

/* The host shares this map, so it belongs to the VM and keeps its contents across a reload. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} totals SEC(".maps");

/* A global belongs to the program, so each version starts with its own at 0. */
static u64 calls;

u64 version(void) {
    return VERSION;
}

/* Returns the new total of `id`. */
u64 hit(u64 id) {
    u32 key = id;
    calls++;

    u64 *total = bpf_map_lookup_elem(&totals, &key);
    if (total) {
        *total += STEP;
        return *total;
    }

    u64 first = STEP;
    bpf_map_update_elem(&totals, &key, &first, BPF_ANY);
    return first;
}

/* The calls of `hit` that this version of the program has run. */
u64 calls_seen(void) {
    return calls;
}
