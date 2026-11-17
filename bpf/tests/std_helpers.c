/*
 * Uses the opt-in standard helpers: ktime_get_ns, trace_printk, get_prandom_u32.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/std_helpers.c -o bpf/tests/std_helpers.o
 */
#include "../rvm_bpf.h"

/* Prints one line and returns nanoseconds elapsed across the print. */
u64 report(u64 x) {
    static const char fmt[] = "x=%llu neg=%d hex=%x\n";
    u64 start = bpf_ktime_get_ns();
    bpf_trace_printk(fmt, sizeof(fmt), x, -(int)x, (u32)x);
    return bpf_ktime_get_ns() - start;
}

/* Two draws differ (with overwhelming probability). */
u64 draws_differ(void) {
    return bpf_get_prandom_u32() != bpf_get_prandom_u32();
}
