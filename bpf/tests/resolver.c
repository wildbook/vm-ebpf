/*
 * Externs bound through a native resolver: IMPORT_FROM("dll") and IMPORT_FROM("dll!symbol"), pointer tag stripping
 * in register and stack arguments, an 8-byte struct argument/return, and untagged externs shared with host closures.
 */
#include "rvm_bpf.h"

struct s8 { u32 a; u32 b; };

extern u64 res_add(u64 a, u64 b) IMPORT_FROM("host.dll");
extern u64 res_aliased(u64 x) IMPORT_FROM("host.dll!alias_target");
extern u64 res_strlen(const char *s) IMPORT_FROM("ucrtbase.dll!strlen");
extern u64 res_stack_sum(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, const u8 *buf) IMPORT_FROM("host.dll");
extern struct s8 res_small_struct(struct s8 d) IMPORT_FROM("host.dll");
extern u64 res_plain(u64 a, u64 b);

static const char greeting[] = "hello resolver";

u64 call_add(u64 a, u64 b) {
    return res_add(a, b) + res_add(b, a);
}

u64 call_aliased(u64 x) {
    return res_aliased(x);
}

u64 call_strlen_rodata(void) {
    return res_strlen(greeting);
}

u64 call_strlen_stack(u8 ch) {
    char buf[8] = {'a', 'b', 'c', (char)ch, 0};
    return res_strlen(buf);
}

u64 call_strlen_ptr(const char *p) {
    return res_strlen(p);
}

u64 call_stack_sum(u64 x) {
    u8 buf[4] = {10, 20, 30, (u8)x};
    return res_stack_sum(x, x + 1, x + 2, x + 3, x + 4, x + 5, buf);
}

u64 call_small_struct(u32 x) {
    struct s8 d = {x, x + 1};
    struct s8 r = res_small_struct(d);
    return ((u64)r.b << 32) | r.a;
}

u64 call_plain(u64 a, u64 b) {
    return res_plain(a, b);
}
