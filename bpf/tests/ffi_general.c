/*
 * General FFI marshalling (`ffi` feature): 3/5/6/7 and 9..16-byte struct arguments, 3/5/7/12/16/24-byte struct
 * returns, float and double arguments and returns, variadic calls, real ucrtbase exports, and &extern tokens of
 * general natives.
 */
#include "rvm_bpf.h"

struct s3 { u8 a, b, c; };
struct s5 { u8 b[5]; };
struct s7 { u8 b[7]; };
struct s12 { u32 a, b, c; };
struct s16 { u64 a, b; };
struct s24 { u64 a, b, c; };

extern u64 take_s3_s5(struct s3 a, struct s5 b, u64 k);
extern u64 take_s7_s12(struct s7 a, struct s12 b, u64 k);
extern u64 take_s16_ptr(struct s16 s, const u8 *buf, u64 len);
extern struct s3 ret_s3(u64 x);
extern struct s5 ret_s5(u64 x);
extern struct s7 ret_s7(u64 x);
extern struct s12 ret_s12(u64 x);
extern struct s16 ret_s16(u64 x);
extern struct s24 ret_s24(u64 x, u64 y);

extern float nat_f32(float a, double b);
extern double nat_f64_6(double a, float b, double c, float d, double e, double f);
extern double c_sqrt(double x) IMPORT_FROM("ucrtbase.dll!sqrt");

extern u64 var_mix(const char *tag, u64 count, ...);
extern int c_snprintf(char *buf, u64 size, const char *fmt, ...) IMPORT_FROM("ucrtbase.dll!_snprintf");

u64 test_take_small_odd(u64 k) {
    struct s3 a = {1, 2, 3};
    struct s5 b = {{10, 20, 30, 40, 50}};
    return take_s3_s5(a, b, k);
}

u64 test_take_mid_wide(u64 k) {
    struct s7 a = {{1, 2, 3, 4, 5, 6, 7}};
    struct s12 b = {100, 200, 300};
    return take_s7_s12(a, b, k);
}

u64 test_take_s16_ptr(u64 a, u64 b) {
    struct s16 s = {a, b};
    u8 buf[4] = {3, 5, 7, 11};
    return take_s16_ptr(s, buf, 4);
}

u64 test_ret_s3(u64 x) {
    struct s3 r = ret_s3(x);
    return (u64)r.a + (u64)r.b * 10 + (u64)r.c * 100;
}

u64 test_ret_s5(u64 x) {
    struct s5 r = ret_s5(x);
    return (u64)r.b[0] + r.b[1] + r.b[2] + r.b[3] + r.b[4];
}

u64 test_ret_s7(u64 x) {
    struct s7 r = ret_s7(x);
    u64 sum = 0;
    for (int i = 0; i < 7; i++)
        sum += r.b[i];
    return sum;
}

u64 test_ret_s12(u64 x) {
    struct s12 r = ret_s12(x);
    return (u64)r.a + (u64)r.b * 10 + (u64)r.c * 100;
}

u64 test_ret_s16(u64 x) {
    struct s16 r = ret_s16(x);
    return r.a ^ (r.b * 3);
}

u64 test_ret_s16_token(u64 x) {
    struct s16 (*fn)(u64) = ret_s16;
    struct s16 r = fn(x);
    return r.a ^ (r.b * 3);
}

u64 test_ret_s24(u64 x, u64 y) {
    struct s24 r = ret_s24(x, y);
    return r.a + r.b * 2 + r.c * 3;
}

u64 test_f32(const float *a, const double *b) {
    float r = nat_f32(*a, *b);
    u32 bits = 0;
    __builtin_memcpy(&bits, &r, 4);
    return bits;
}

u64 test_f64_6(const double *a, const float *b, const double *c, const float *d, const double *e, const double *f) {
    double r = nat_f64_6(*a, *b, *c, *d, *e, *f);
    u64 bits = 0;
    __builtin_memcpy(&bits, &r, 8);
    return bits;
}

u64 test_sqrt(const double *x) {
    double r = c_sqrt(*x);
    u64 bits = 0;
    __builtin_memcpy(&bits, &r, 8);
    return bits;
}

u64 test_var_mix(const double *d, u64 n) {
    return var_mix("tag", 3, n, *d, (u64)42);
}

u64 test_snprintf(u64 a, u64 b) {
    char out[32] = {0};
    int n = c_snprintf(out, sizeof(out), "%llu+%llu", a, b);
    u64 hash = (u64)n * 1000;
    for (int i = 0; i < 32 && out[i]; i++)
        hash = hash * 31 + (u8)out[i];
    return hash;
}
