/*
 * BPF atomics as clang emits them.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/atomics.c -o bpf/tests/atomics.o
 */
#include "../rvm_bpf.h"

u64 counter64 = 0;
u32 counter32 = 0;

/* Returns the sum of all fetched old values so every fetch result is observable. */
u64 run(u64 x) {
    u64 seen = 0;

    __sync_fetch_and_add(&counter64, x);                 /* add, no fetch */
    seen += __sync_fetch_and_add(&counter64, 1);         /* add | fetch */
    seen += __sync_fetch_and_or(&counter64, 0x100);
    seen += __sync_fetch_and_and(&counter64, ~0x1ULL);
    seen += __sync_fetch_and_xor(&counter64, 0xF0);
    seen += __sync_lock_test_and_set(&counter64, 7);     /* xchg */
    seen += __sync_val_compare_and_swap(&counter64, 7, 9);
    seen += __sync_val_compare_and_swap(&counter64, 7, 11); /* fails: value is 9 */

    seen += __sync_fetch_and_add(&counter32, (u32)x);
    seen += __sync_val_compare_and_swap(&counter32, (u32)x, 0xFFFFFFFFu);

    return seen;
}
