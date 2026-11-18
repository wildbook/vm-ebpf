/*
 * Lends a stack buffer to borrow_host.c's export.
 */
#include "rvm_bpf.h"
extern u64 peek(const u64 *buf, u64 len);

u64 run(void) {
    volatile u64 arr[1] = {42};
    return peek((const u64 *)arr, sizeof(arr));
}
