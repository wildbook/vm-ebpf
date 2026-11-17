/*
 * Function pointers: callback tables in .rodata and .data, a callback passed as an
 * argument, and a dense switch that clang lowers to a jump table (gotox).
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/func_ptr.c -o bpf/tests/func_ptr.o
 */
typedef unsigned long long u64;
typedef u64 (*op_fn)(u64, u64);

static __attribute__((noinline)) u64 add(u64 a, u64 b) { return a + b; }
static __attribute__((noinline)) u64 sub(u64 a, u64 b) { return a - b; }
static __attribute__((noinline)) u64 mul(u64 a, u64 b) { return a * b; }

static op_fn const ro_ops[3] = {add, sub, mul}; /* .rodata */
op_fn rw_ops[2] = {mul, add};                    /* .data */

/* Global, so clang can't specialize it for each callback. */
__attribute__((noinline)) u64 apply(op_fn f, u64 a, u64 b) { return f(a, b); }

u64 call_ro(u64 i, u64 a, u64 b) { return ro_ops[i](a, b); }

u64 call_rw(u64 i, u64 a, u64 b) { return rw_ops[i](a, b); }

u64 pass_callback(u64 a, u64 b) { return apply(mul, a, b) + apply(sub, a, b); }

/* The host reads a code address here and passes good and bad ones to `call_ptr`. */
u64 addr_of_add(void) { return (u64)add; }

u64 call_ptr(u64 target, u64 a, u64 b) { return ((op_fn)target)(a, b); }

u64 dense_switch(u64 x, u64 y) {
    switch (x) {
    case 0: return y + 3;
    case 1: return y ^ 7;
    case 2: return y * 5;
    case 3: return y - 9;
    case 4: return y << 2;
    case 5: return y | 0x40;
    case 6: return y >> 1;
    case 7: return y & 0xf0;
    case 8: return y * y;
    case 9: return y + 100;
    case 10: return ~y;
    case 11: return y / 3;
    case 12: return y % 7;
    case 13: return y << 9;
    case 14: return y - 1000;
    case 15: return y * 11 + 1;
    }
    return 0;
}
