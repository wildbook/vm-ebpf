/*
 * Exports that take buffers borrowed from the caller's memory for one call.
 * `borrow:N` / `borrow_ro:N` on a pointer parameter names the parameter holding
 * its length in bytes.
 */
#include "rvm_bpf.h"

u64 sum(const u64 *buf BORROW_RO(1), u64 len) {
    u64 total = 0;
    for (u64 i = 0; i < len / 8; i++)
        total += buf[i];
    return total;
}

u64 fill(u64 *buf BORROW(1), u64 len, u64 value) {
    for (u64 i = 0; i < len / 8; i++)
        buf[i] = value;
    return 0;
}

/* Writes through a read-only borrow, which must fault. */
u64 poke(u64 *buf BORROW_RO(1), u64 len) {
    *(volatile u64 *)buf = len;
    return 0;
}

struct key { u64 a, b; };

/* `key` takes r1 and r2, so the buffer arrives in r3 and its length in r4. */
u64 sum_keyed(struct key key, const u64 *buf BORROW_RO(2), u64 len) {
    return key.a + key.b + sum(buf, len);
}
