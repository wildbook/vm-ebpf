/*
 * Plain loads and stores through pointers into a host-shared region.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/shared_region.c -o bpf/tests/shared_region.o
 */
#include "../rvm_bpf.h"

u64 put(u64 *slot, u64 value) {
    *slot = value;
    return 0;
}

u64 get(u64 *slot) {
    return *slot;
}
