/*
 * __host pointers and HOST() (addr_space_cast between address spaces 0 and 1): pointers inside a struct passed to
 * native code, dereferencing host addresses into plugin and host memory, and round trips.
 */
#include "rvm_bpf.h"

struct iovec {
    const u8 __host *base;
    u64 len;
};

extern u64 sum_iovec(const struct iovec *parts BORROW_RO(1), u64 byte_len);

static const u32 ro_word = 0x11223344;
static u32 rw_word = 0x55667788;
static const u8 ro_bytes[3] = {10, 20, 30};

u64 host_ro_word(void) {
    return (u64)HOST(&ro_word);
}

u64 host_rw_word(void) {
    return (u64)HOST(&rw_word);
}

u64 read_host_u32(const u32 __host *p) {
    return *p;
}

u64 write_host_u32(u32 __host *p, u32 v) {
    *p = v;
    return *p;
}

u64 read_rw_word(void) {
    return rw_word;
}

u64 sum_parts(void) {
    u8 stack_bytes[4] = {1, 2, 3, 4};
    struct iovec parts[2] = {
        {HOST(stack_bytes), sizeof(stack_bytes)},
        {HOST(ro_bytes), sizeof(ro_bytes)},
    };
    return sum_iovec(parts, sizeof(parts));
}
