/*
 * Plain loads and stores through pointers into a host-shared region.
 */
#include "rvm_bpf.h"
u64 put(u64 *slot, u64 value) {
    *slot = value;
    return 0;
}

u64 get(u64 *slot) {
    return *slot;
}
