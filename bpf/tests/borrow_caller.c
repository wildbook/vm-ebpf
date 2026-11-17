/*
 * Passes stack buffers to borrow_callee.c's exports.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/borrow_caller.c -o bpf/tests/borrow_caller.o
 */
#include "../rvm_bpf.h"

extern u64 sum(const u64 *buf, u64 len);
extern u64 fill(u64 *buf, u64 len, u64 value);
extern u64 poke(u64 *buf, u64 len);

/* sum(1..4) * 1000 + the first and last element after fill(7). */
u64 run(void) {
    volatile u64 arr[4] = {1, 2, 3, 4};
    u64 total = sum((const u64 *)arr, sizeof(arr));
    fill((u64 *)arr, sizeof(arr), 7);
    return total * 1000 + arr[0] + arr[3];
}

/* Claims a length past the caller's stack. */
u64 overrun(void) {
    volatile u64 arr[2] = {1, 2};
    return sum((const u64 *)arr, 1 << 20);
}

u64 write_ro(void) {
    volatile u64 arr[1] = {0};
    return poke((u64 *)arr, sizeof(arr));
}
