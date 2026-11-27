/*
 * Calls with 6, 8 and 12 arguments, which clang passes on the stack from the sixth on: to the plugin's own
 * functions, directly and through a pointer, to host functions, to native functions, and through a raw function
 * pointer that the host passes in.
 *
 * Every callee returns its arguments weighted by their position, so a missing, swapped or stale argument shows in
 * the result.
 */
#include "rvm_bpf.h"

#define W6(a, b, c, d, e, f) ((a) + 2 * (b) + 3 * (c) + 4 * (d) + 5 * (e) + 6 * (f))
#define W8(a, b, c, d, e, f, g, h) (W6(a, b, c, d, e, f) + 7 * (g) + 8 * (h))
#define W12(a, b, c, d, e, f, g, h, i, j, k, l) (W8(a, b, c, d, e, f, g, h) + 9 * (i) + 10 * (j) + 11 * (k) + 12 * (l))

/* x, x + 1, ... as the arguments of a call */
#define ARGS6(x) (x), (x) + 1, (x) + 2, (x) + 3, (x) + 4, (x) + 5
#define ARGS8(x) ARGS6(x), (x) + 6, (x) + 7
#define ARGS12(x) ARGS8(x), (x) + 8, (x) + 9, (x) + 10, (x) + 11

typedef u64 (*fn5)(u64, u64, u64, u64, u64);
typedef u64 (*fn6)(u64, u64, u64, u64, u64, u64);
typedef u64 (*fn8)(u64, u64, u64, u64, u64, u64, u64, u64);
typedef u64 (*fn12)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);

/* A 16-byte struct after four integers: `a` goes in r5 and `b` on the stack. */
struct s16 {
    u64 a, b;
};

/* Hides where a function pointer comes from, so that the call through it stays a `callx`. */
#define OPAQUE(f) asm volatile("" : "+r"(f))

/* The plugin's own functions. The host calls them too, as do other plugins. */

noinline u64 g6(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) { return W6(a, b, c, d, e, f); }

noinline u64 g8(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h) { return W8(a, b, c, d, e, f, g, h); }

noinline u64 g12(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l) {
    return W12(a, b, c, d, e, f, g, h, i, j, k, l);
}

noinline u64 g_split(u64 a, u64 b, u64 c, u64 d, struct s16 s) { return W6(a, b, c, d, s.a, s.b); }

/* The sum of the `len / 8` values at `buf`, a buffer that a caller in another plugin lends, plus W6 of the rest. */
u64 g_sum(u64 a, u64 b, u64 c, u64 d, u64 e, const u64 *buf BORROW_RO(6), u64 len) {
    u64 total = W6(a, b, c, d, e, 0);
    for (u64 i = 0; i < len / 8; i++)
        total += buf[i];
    return total;
}

u64 call_g6(u64 x) { return g6(ARGS6(x)); }
u64 call_g8(u64 x) { return g8(ARGS8(x)); }
u64 call_g12(u64 x) { return g12(ARGS12(x)); }

u64 call_g_split(u64 x) {
    struct s16 s = {x + 4, x + 5};
    return g_split(x, x + 1, x + 2, x + 3, s);
}

u64 callx_g6(u64 x) {
    fn6 f = g6;
    OPAQUE(f);
    return f(ARGS6(x));
}

u64 callx_g12(u64 x) {
    fn12 f = g12;
    OPAQUE(f);
    return f(ARGS12(x));
}

/* g6 with five arguments: its sixth is the one that the last call from this depth stored, or 0. */
u64 call_g6_short(u64 x) {
    fn5 f = (fn5)g6;
    OPAQUE(f);
    return f(x, 0, 0, 0, 0);
}

/*
 * Recursion: every level passes other stack arguments down, and mixes in its own after the call returns.
 */
noinline u64 nest(u64 depth, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g) {
    if (depth == 0)
        return f + g;
    u64 below = nest(depth - 1, b, c, d, e, f * 3, g + 1);
    return (below ^ f) + g;
}

u64 call_nest(u64 depth, u64 f, u64 g) { return nest(depth, 0, 0, 0, 0, f, g); }

/* Host functions. */

extern u64 h6(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f);
extern u64 h8(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h);
extern u64 h12(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l);
extern u64 h_split(u64 a, u64 b, u64 c, u64 d, struct s16 s);

u64 call_h6(u64 x) { return h6(ARGS6(x)); }
u64 call_h8(u64 x) { return h8(ARGS8(x)); }
u64 call_h12(u64 x) { return h12(ARGS12(x)); }

u64 call_h_split(u64 x) {
    struct s16 s = {x + 4, x + 5};
    return h_split(x, x + 1, x + 2, x + 3, s);
}

/* A host function between two levels of the plugin's own calls, each with its own stack arguments. */
noinline u64 through_host(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g) {
    return h6(g, f, e, d, c, b) + g8(a, b, c, d, e, f, g, 1) + f + g;
}

u64 call_through_host(u64 x) { return through_host(ARGS6(x), x + 6); }

/* Native functions. `n_buf` returns the sum of the `len` bytes at `buf` plus W6 of the rest. */

extern u64 n6(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f);
extern u64 n8(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h);
extern u64 n12(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l);
extern u64 n_buf(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, const u8 *buf, u64 len);

u64 call_n6(u64 x) { return n6(ARGS6(x)); }
u64 call_n8(u64 x) { return n8(ARGS8(x)); }
u64 call_n12(u64 x) { return n12(ARGS12(x)); }

/* `len` bytes of a 4-byte buffer: more than 4 reach past the stack. */
u64 call_n_buf(u64 x, u64 len) {
    volatile u8 bytes[4] = {1, 2, 3, x};
    return n_buf(ARGS6(x), (const u8 *)bytes, len);
}

/* The native function at `addr`, through a pointer without a signature. */

u64 raw6(u64 addr, u64 x) { return ((fn6)addr)(ARGS6(x)); }
u64 raw8(u64 addr, u64 x) { return ((fn8)addr)(ARGS8(x)); }
u64 raw12(u64 addr, u64 x) { return ((fn12)addr)(ARGS12(x)); }
