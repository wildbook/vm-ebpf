/*
 * A global named like the map in shared_counter.c, for linking the two together.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/global_hits.c -o bpf/tests/global_hits.o
 */
#include "../rvm_bpf.h"

u64 hits = 5;

u64 get(void) {
    return hits;
}
