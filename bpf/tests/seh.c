/*
 * Calls and accesses that raise structured exceptions on Windows, for lib/rvm/tests/integration/seh.rs and the C host
 * in lib/rvmrt/tests: native functions that fault, and every kind of load and store through a raw host pointer.
 */
#include "rvm_bpf.h"

/* All arguments are integers to the VM, so the natives get them as the guest passes them. */
extern u64 nat_strlen(u64 text);
extern u64 nat_raise(u64 code, u64 flags, u64 count, u64 args);
extern u64 nat_break(void);
extern u64 nat_sort(u64 base, u64 count, u64 size, u64 compare);
extern u64 nat_throw(u64 x);
extern u64 nat_recurse(u64 depth);

u64 text_len(u64 text) {
    return nat_strlen(text) + 1;
}

u64 raise(u64 code) {
    return nat_raise(code, 0, 0, 0) + 1;
}

u64 debug_break(void) {
    return nat_break() + 1;
}

/* The native calls `compare` back while it sorts the two values at `base`. */
u64 sort(u64 base, u64 compare) {
    return nat_sort(base, 2, 8, compare);
}

u64 throw(u64 x) {
    return nat_throw(x) + 1;
}

u64 recurse(u64 depth) {
    return nat_recurse(depth) + 1;
}

u64 load8(u8 *p) { return *p; }
u64 load16(u16 *p) { return *p; }
u64 load32(u32 *p) { return *p; }
u64 load64(u64 *p) { return *p; }

u64 store8(u8 *p, u64 v) { *p = v; return 0; }
u64 store16(u16 *p, u64 v) { *p = v; return 0; }
u64 store32(u32 *p, u64 v) { *p = v; return 0; }
u64 store64(u64 *p, u64 v) { *p = v; return 0; }

/* Stores of a constant, which are `st` instructions. */
u64 clear32(u32 *p) { *p = 7; return 0; }
u64 clear64(u64 *p) { *p = 7; return 0; }

/* Sign-extending loads. */
s64 loads8(s8 *p) { return *p; }
s64 loads16(s16 *p) { return *p; }
s64 loads32(s32 *p) { return *p; }

u64 add64(u64 *p, u64 v) { return __sync_fetch_and_add(p, v); }
u64 add32(u32 *p, u64 v) { return __sync_fetch_and_add(p, (u32)v); }
u64 or64(u64 *p, u64 v) { return __sync_fetch_and_or(p, v); }
u64 and32(u32 *p, u64 v) { return __sync_fetch_and_and(p, (u32)v); }
u64 xor64(u64 *p, u64 v) { return __sync_fetch_and_xor(p, v); }
u64 swap64(u64 *p, u64 v) { return __sync_lock_test_and_set(p, v); }
u64 swap32(u32 *p, u64 v) { return __sync_lock_test_and_set(p, (u32)v); }
u64 cas64(u64 *p, u64 old, u64 new) { return __sync_val_compare_and_swap(p, old, new); }
u64 cas32(u32 *p, u64 old, u64 new) { return __sync_val_compare_and_swap(p, (u32)old, (u32)new); }

u64 acquire8(u8 *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
u64 acquire64(u64 *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
u64 release16(u16 *p, u64 v) { __atomic_store_n(p, (u16)v, __ATOMIC_RELEASE); return 0; }
u64 release64(u64 *p, u64 v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); return 0; }

/* `mov, add, ldxw`, which runs as one superinstruction: the load is its third instruction. */
u64 fused(u8 *base, u64 off) {
    u32 v = *(u32 *)(base + off);
    return v + (u64)base;
}

static noinline u64 second(u64 *p) {
    return p[1];
}

/* A load below a local call. */
u64 nested(u64 *p) {
    return second(p) + 1;
}
