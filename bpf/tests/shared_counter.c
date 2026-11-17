/*
 * One array map, `hits`, for sharing between plugins; a second build with
 * VALUE=u32 gives it 32-bit values.
 */
#include "../rvm_bpf.h"

#ifndef VALUE
#define VALUE u64
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
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
