/*
 * &extern tokens in code, .rodata tables, and .data tables: calling host closures, plugin exports, and native
 * functions indirectly through function pointers without RawCalls::on().
 */
#include "rvm_bpf.h"

extern u64 tok_host(u64 a, u64 b);
extern u64 tok_nat(u64 a, u64 b);
extern u64 tok_checked(const u8 *buf BORROW_RO(1), u64 len);
extern u64 tok_stack(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f);

static u64 (*const ro_ops[2])(u64, u64) = {tok_host, tok_nat};
static u64 (*rw_ops[2])(u64, u64) = {tok_nat, tok_host};

u64 call_code_token(u64 pick, u64 a, u64 b) {
    u64 (*fn)(u64, u64) = pick ? tok_nat : tok_host;
    return fn(a, b);
}

u64 call_ro_token(u64 idx, u64 a, u64 b) {
    return ro_ops[idx & 1](a, b);
}

u64 call_rw_token(u64 idx, u64 a, u64 b) {
    return rw_ops[idx & 1](a, b);
}

u64 call_checked_token(u64 bad) {
    u8 buf[4] = {1, 2, 3, 4};
    u64 (*fn)(const u8 *, u64) = tok_checked;
    if (bad) {
        return fn((const u8 *)0, 4);
    }
    return fn(buf, 4);
}

u64 call_stack_token(u64 x) {
    u64 (*fn)(u64, u64, u64, u64, u64, u64) = tok_stack;
    return fn(x, x + 1, x + 2, x + 3, x + 4, x + 5);
}
