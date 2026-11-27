/*
 * Calls stack_args.c's functions from another plugin, with arguments on the stack: integers, a 16-byte struct that
 * starts in r5, and a borrowed buffer whose pointer and length are both stack arguments.
 */
#include "rvm_bpf.h"

struct s16 {
    u64 a, b;
};

extern u64 g8(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h);
extern u64 g12(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l);
extern u64 g_split(u64 a, u64 b, u64 c, u64 d, struct s16 s);
extern u64 g_sum(u64 a, u64 b, u64 c, u64 d, u64 e, const u64 *buf, u64 len);

u64 export_g8(u64 x) { return g8(x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7); }

u64 export_g12(u64 x) {
    return g12(x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, x + 8, x + 9, x + 10, x + 11);
}

u64 export_g_split(u64 x) {
    struct s16 s = {x + 4, x + 5};
    return g_split(x, x + 1, x + 2, x + 3, s);
}

/* The callee reads `len` bytes of a 32-byte array on this plugin's stack. */
u64 export_g_sum(u64 x, u64 len) {
    volatile u64 values[4] = {x, 10, 20, 30};
    return g_sum(1, 2, 3, 4, 5, (const u64 *)values, len);
}
