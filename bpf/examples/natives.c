/*
 * Calls native functions of the host in lib/rvm/examples/natives.rs: one on integers, two on a buffer with its
 * length, and one that returns a pointer to a host struct, which the guest follows with passthrough on.
 */
#include "rvm_bpf.h"

struct config {
    u32 version;
    u32 scale;
};

extern u64 mix(u64 a, u64 b, u64 c);
extern u64 checksum(const u8 *buf BORROW_RO(1), u64 len);
extern void upper(u8 *buf BORROW(1), u64 len);
extern const struct config *host_config(void);

u64 mixed(u64 x) {
    return mix(x, x + 1, x + 2);
}

/* Upper-cases a greeting on the stack in place and returns the checksum of the result. */
u64 shout(void) {
    char text[] = "hello, natives";
    upper((u8 *)text, sizeof(text) - 1);
    return checksum((const u8 *)text, sizeof(text) - 1);
}

/* Multiplies by the scale in the host's config. */
u64 scaled(u64 x) {
    return x * host_config()->scale;
}
