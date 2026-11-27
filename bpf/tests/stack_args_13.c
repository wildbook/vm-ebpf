/*
 * A function of 13 arguments, one more than rvm passes. Clang compiles it and the call, and rvm fails the load.
 */
#include "rvm_bpf.h"

noinline u64 g13(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 g, u64 h, u64 i, u64 j, u64 k, u64 l, u64 m) {
    return a + b + c + d + e + f + g + h + i + j + k + l + m;
}

u64 call_g13(u64 x) { return g13(x, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13); }
