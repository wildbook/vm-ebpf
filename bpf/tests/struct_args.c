/*
 * Host externs that take or return structs by value, where the BTF parameters differ from the registers: a struct
 * of 9 to 16 bytes takes two argument registers and returns in r0 and r2, and a struct of more than 16 bytes returns
 * through a result pointer in r1. A 16-byte struct after four integers splits across r5 and the first stack slot.
 *
 * With TOO_MANY defined, the object only takes the address of an extern that needs 13 registers.
 */
#include "rvm_bpf.h"

struct s8 { u32 a, b; };
struct s12 { u32 a, b, c; };
struct s16 { u64 a, b; };
struct s24 { u64 a, b, c; };
enum color { RED = 1, BLUE = 2 };

#ifndef TOO_MANY

extern u64 scalars(u32 a, enum color c, const void *p);
extern u64 s8_arg(struct s8 s, u64 x);
extern u64 s12_arg(struct s12 s, u64 x);
extern u64 split(u64 a, u64 b, u64 c, u64 d, struct s16 s);
extern struct s8 s8_ret(u64 x);
extern struct s12 s12_ret(u64 x);
extern struct s24 s24_ret(u64 x);

u64 call_scalars(void) { return scalars(1, BLUE, NULL); }
u64 call_s8_arg(void) { return s8_arg((struct s8){1, 2}, 3); }
u64 call_s12_arg(void) { return s12_arg((struct s12){1, 2, 3}, 4); }
u64 call_split(void) { return split(1, 2, 3, 4, (struct s16){5, 6}); }

u64 call_s8_ret(void) {
    struct s8 r = s8_ret(1);
    return r.a + 10 * r.b;
}

u64 call_s12_ret(void) {
    struct s12 r = s12_ret(1);
    return r.a + 10 * r.b + 100 * r.c;
}

u64 call_s24_ret(void) {
    struct s24 r = s24_ret(1);
    return r.a + 10 * r.b + 100 * r.c;
}

#else

extern u64 thirteen(struct s16 a, struct s16 b, struct s16 c, struct s16 d, struct s16 e, struct s16 f, u64 x);

u64 address_of_thirteen(void) { return (u64)&thirteen; }

#endif
