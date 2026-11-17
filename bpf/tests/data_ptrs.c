/*
 * Pointers stored in global data, which need data relocations at link time.
 */
#include "rvm_bpf.h"
u64 target = 41;
const u64 table[3] = {10, 20, 30};

u64 *ptr = &target;               /* .data -> .data */
const u64 *const entries[2] = {   /* .rodata -> .rodata, with an addend */
    &table[0],
    &table[2],
};

u64 deref(void) {
    *ptr += 1;
    return *ptr + *entries[0] + *entries[1];
}
