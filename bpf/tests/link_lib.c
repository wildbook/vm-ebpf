/*
 * Library module for cross-module link tests (see link_main.c).
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/link_lib.c -o bpf/tests/link_lib.o
 */
#include "../rvm_bpf.h"

/* Library-private state: each program that links this module gets its own copy. */
u64 lib_calls = 0;

noinline u64 lib_scale(u64 x) {
    lib_calls++;
    return x * 3;
}
