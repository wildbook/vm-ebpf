/*
 * Calls through pointers to native functions of the tests in lib/rvm/tests/integration/raw_calls.rs: a table of
 * function pointers in a host struct, a pointer the caller passes, and addresses the plugin holds as constants.
 */
#include "rvm_bpf.h"

/* `HostApi` in the tests. */
struct host_api {
    u64 (*zero)(void);
    u64 (*one)(u64 a);
    u64 (*five)(u64 a, u64 b, u64 c, u64 d, u64 e);
    u64 (*sum)(const u8 *buf, u64 len);
};

/* Reads the table through a host address and passes a stack pointer as it is, which works in an untagged plugin. */
u64 through_table(const struct host_api *api) {
    u8 buf[4] = {1, 2, 3, 4};
    return api->zero() + api->one(10) + api->five(1, 2, 3, 4, 5) + api->sum(buf, sizeof(buf));
}

/* Global, so clang keeps the call through `callback`, whatever the caller passes. */
noinline u64 call_back(u64 (*callback)(u64), u64 x) {
    return callback(x) + 1;
}

static noinline u64 twice(u64 x) {
    return 2 * x;
}

/* A function of this plugin stays one. */
u64 call_own(u64 x) {
    return call_back(twice, x);
}

/* A plugin whose pointers carry tags converts a pointer the native function follows with HOST(). */
u64 sum_host(u64 (*sum)(const u8 __host *buf, u64 len)) {
    u8 buf[4] = {1, 2, 3, 4};
    return sum(HOST(buf), sizeof(buf));
}

/* Below 64 KiB: a helper ID. */
u64 call_low(u64 x) {
    return NATIVE_AT(u64 (*)(u64), 0x1234)(x);
}

/* An address above 4 GiB where nothing is mapped. The tests call this without raw calls only. */
u64 call_high(u64 x) {
    return NATIVE_AT(u64 (*)(u64), 0x7ff812340000ULL)(x);
}
