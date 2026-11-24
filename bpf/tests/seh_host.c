/*
 * A read by a host function, which no guard of lib/rvm/tests/integration/seh.rs covers.
 */
#include "rvm_bpf.h"

extern u64 host_read(u64 p);

u64 via_host(u64 p) {
    return host_read(p);
}
