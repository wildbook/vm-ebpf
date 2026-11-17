/*
 * Exports that take buffers borrowed from the caller's memory for one call.
 * `borrow:N` / `borrow_ro:N` on a pointer parameter names the parameter holding
 * its length in bytes.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/borrow_callee.c -o bpf/tests/borrow_callee.o
 */
typedef unsigned long long u64;

#define BORROW(len_arg) __attribute__((btf_decl_tag("borrow:" #len_arg)))
#define BORROW_RO(len_arg) __attribute__((btf_decl_tag("borrow_ro:" #len_arg)))

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
