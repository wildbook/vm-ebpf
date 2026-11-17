/*
 * Library module for cross-module link tests (see link_main.c).
 */
#include "rvm_bpf.h"

/* Library-private state: each program that links this module gets its own copy. */
u64 lib_calls = 0;

noinline u64 lib_scale(u64 x) {
    lib_calls++;
    return x * 3;
}
