/*
 * Calls native functions, which the tests in lib/rvm/tests/integration/natives.rs register: integers, buffers with
 * a length, a pointer checked for one byte, and a native that calls back into this plugin.
 */
#include "rvm_bpf.h"

extern u64 nat_add(u64 a, u64 b);
extern u64 nat_five(u64 a, u64 b, u64 c, u64 d, u64 e);
extern u64 nat_sum(const u8 *buf BORROW_RO(1), u64 len);
extern u64 nat_fill(u8 *buf BORROW(1), u64 len, u64 byte);
extern u64 nat_first(const u8 *p);
extern u64 nat_reenter(u64 x);

u64 add(u64 a, u64 b) {
    return nat_add(a, b);
}

u64 five(void) {
    return nat_five(1, 2, 3, 4, 5);
}

/* 1 + 2 + ... + 16 = 136, read by the native from the stack. */
u64 sum(void) {
    u8 buf[16];
    for (int i = 0; i < 16; i++)
        buf[i] = i + 1;
    return nat_sum(buf, sizeof(buf));
}

/* The native fills the buffer with 3s; the guest sums it back: 24. */
u64 fill(void) {
    u8 buf[8] = {};
    nat_fill(buf, sizeof(buf), 3);
    u64 total = 0;
    for (int i = 0; i < 8; i++)
        total += buf[i];
    return total;
}

/* A length past the end of the stack. */
u64 overrun(void) {
    u8 buf[8] = {};
    return nat_sum(buf, 1 << 20);
}

/* Any address the caller picks. */
u64 first(u64 p) {
    return nat_first((const u8 *)p);
}

/* The first byte of a string in rodata, which `nat_fill` may not write. */
u64 fill_rodata(void) {
    static const char text[] = "abc";
    return nat_fill((u8 *)text, 3, 0);
}

/* An empty buffer may be null. */
u64 sum_empty(void) {
    return nat_sum(NULL, 0);
}

u64 reenter(u64 x) {
    return nat_reenter(x);
}

/* n native calls in a loop: the sum of 1 to n. */
u64 count(u64 n) {
    u64 total = 0;
    for (u64 i = 0; i < n; i++)
        total = nat_add(total, i + 1);
    return total;
}
