/*
 * Benchmark workloads for lib/rvm/benches.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/bench/workloads.c -o bpf/bench/workloads.o
 */
#include "../rvm_bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u64);
} counts SEC(".maps");

/* Hook-style entry point: the cost of calling into a program. */
u64 noop(void) {
    return 0;
}

/* Parse `len` bytes of length-prefixed records: [u8 kind][u8 n][n bytes], summing payloads. */
u64 parse(const u8 *buf, u64 len) {
    u64 sum = 0, pos = 0;
    while (pos + 2 <= len) {
        u8 kind = buf[pos], n = buf[pos + 1];
        pos += 2;
        if (pos + n > len)
            break;
        for (u8 i = 0; i < n; i++)
            sum += (u64)buf[pos + i] * (kind + 1);
        pos += n;
    }
    return sum;
}

/* Count `n` pseudo-random keys into a hash map. */
u64 aggregate(u64 n) {
    u64 x = 0x9e3779b97f4a7c15ULL;
    for (u64 i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        u32 key = x & 255;
        u64 *count = bpf_map_lookup_elem(&counts, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            u64 one = 1;
            bpf_map_update_elem(&counts, &key, &one, 0);
        }
    }
    return 0;
}

static noinline u64 fib(u64 n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

/* Call-heavy: naive recursion within the 8-frame depth limit. */
u64 calls(u64 rounds) {
    volatile u64 depth = 7;
    u64 total = 0;
    for (u64 i = 0; i < rounds; i++)
        total += fib(depth); /* volatile load keeps clang from hoisting the call */
    return total;
}
