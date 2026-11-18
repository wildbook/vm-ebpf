/*
 * An export that calls a host function while it holds a buffer borrowed from the caller.
 */
#include "rvm_bpf.h"
extern u64 host_peek(u64 first);

u64 peek(const u64 *buf BORROW_RO(1), u64 len) {
    return host_peek(buf[0]);
}
