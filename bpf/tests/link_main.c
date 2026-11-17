/*
 * Main module for cross-module link tests. Imports a function from link_lib.c,
 * a host extern function by name, and calls host helper 100.
 */
#include "rvm_bpf.h"
extern u64 lib_scale(u64 x);  /* defined in link_lib.o */
extern u64 host_add(u64 a, u64 b); /* provided by the host by name */

static u64 (*helper_double)(u64) = (void *)100; /* host helper ID 100 */

/* host_add(lib_scale(x), helper_double(x)) = 3x + 2x */
u64 run(u64 x) {
    return host_add(lib_scale(x), helper_double(x));
}
