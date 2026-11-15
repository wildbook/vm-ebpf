/*
 * Plain loads and stores through pointers into a host-shared region.
 * Build: clang -target bpf -O2 -g -c bpf/shared_region.c -o bpf/shared_region.o
 */
typedef unsigned long long u64;

u64 put(u64 *slot, u64 value) {
    *slot = value;
    return 0;
}

u64 get(u64 *slot) {
    return *slot;
}
