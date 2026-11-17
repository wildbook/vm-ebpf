/*
 * A global named like the map in shared_counter.c, for linking the two together.
 * Build: clang -target bpf -mcpu=v3 -O2 -g -c bpf/global_hits.c -o bpf/global_hits.o
 */
typedef unsigned long long u64;

u64 hits = 5;

u64 get(void) {
    return hits;
}
