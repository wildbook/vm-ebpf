/*
 * Host externs that take or return structs by value, where the BTF parameter
 * count differs from the argument registers: a struct of 9 to 16 bytes takes
 * two registers, and a struct return passes a hidden result pointer in r1.
 * Each call_<name> calls the extern <name>.
 *
 * With TOO_MANY defined, the object only takes the address of an extern that
 * needs six registers. Clang rejects a call to it, but BTF still declares it.
 */
#include "rvm_bpf.h"

struct s3 { u8 a, b, c; };
struct s8 { u32 a, b; };
struct s12 { u32 a, b, c; };
struct s16 { u64 a, b; };
union pair { u64 a[2]; u32 b; };
struct s24 { u64 a, b, c; };
enum color { RED = 1, BLUE = 2 };

#ifndef TOO_MANY

extern u64 scalars(u32 a, enum color c, const void *p);
extern u64 s3_arg(struct s3 s, u64 x);
extern u64 s8_arg(struct s8 s, u64 x);
extern u64 s12_arg(struct s12 s, u64 x);
extern u64 s16_arg(struct s16 s, u64 x);
extern u64 pair_arg(union pair u, u64 x);
extern u64 two_s16(struct s16 a, struct s16 b, u64 x);
extern struct s8 s8_ret(u64 x);
extern struct s24 s24_ret(u64 x);

u64 call_scalars(void) { return scalars(1, BLUE, NULL); }
u64 call_s3_arg(void) { return s3_arg((struct s3){1, 2, 3}, 4); }
u64 call_s8_arg(void) { return s8_arg((struct s8){1, 2}, 3); }
u64 call_s12_arg(void) { return s12_arg((struct s12){1, 2, 3}, 4); }
u64 call_s16_arg(void) { return s16_arg((struct s16){1, 2}, 3); }
u64 call_pair_arg(void) { return pair_arg((union pair){.a = {1, 2}}, 3); }
u64 call_two_s16(void) { return two_s16((struct s16){1, 2}, (struct s16){3, 4}, 5); }
u64 call_s8_ret(void) { return s8_ret(1).a; }
u64 call_s24_ret(void) { return s24_ret(1).c; }

#else

extern u64 six(struct s16 a, struct s16 b, u64 x, u64 y);

u64 address_of_six(void) { return (u64)&six; }

#endif
