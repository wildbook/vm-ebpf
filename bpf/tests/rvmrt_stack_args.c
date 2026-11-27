/*
 * Fixture for the C host test of rvmrt (lib/rvmrt/tests/stack_args.rs): guest functions, native functions and raw
 * calls with 6 to 12 arguments, without host-only externs or maps.
 */
#include "rvm_bpf.h"

#define W6(a, b, c, d, e, f) ((a) + 2 * (b) + 3 * (c) + 4 * (d) + 5 * (e) + 6 * (f))
#define W8(a, b, c, d, e, f, g, h) (W6(a, b, c, d, e, f) + 7 * (g) + 8 * (h))
#define W12(a, b, c, d, e, f, g, h, i, j, k, l) (W8(a, b, c, d, e, f, g, h) + 9 * (i) + 10 * (j) + 11 * (k) + 12 * (l))

#define ARGS6(x) (x), (x) + 1, (x) + 2, (x) + 3, (x) + 4, (x) + 5
#define ARGS12(x) ARGS6(x), (x) + 6, (x) + 7, (x) + 8, (x) + 9, (x) + 10, (x) + 11

typedef u64 (*fn6)(u64, u64, u64, u64, u64, u64);
typedef u64 (*fn12)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);

u64 g6(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) { return W6(a, b, c, d, e, f); }

u64 g12(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l) {
    return W12(a, b, c, d, e, f, g, h, i, j, k, l);
}

extern u64 n6(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f);
extern u64 n12(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l);
extern u64 n_buf(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, const u8 *buf BORROW_RO(7), u64 len);

u64 call_n6(u64 x) { return n6(ARGS6(x)); }
u64 call_n12(u64 x) { return n12(ARGS12(x)); }

u64 call_n_buf(u64 x, u64 len) {
    volatile u8 bytes[4] = {1, 2, 3, (u8)x};
    return n_buf(ARGS6(x), (const u8 *)bytes, len);
}

u64 raw6(u64 addr, u64 x) { return ((fn6)addr)(ARGS6(x)); }
u64 raw12(u64 addr, u64 x) { return ((fn12)addr)(ARGS12(x)); }
