/*
 * Native-to-guest callbacks: qsort comparator, float and struct callback ABIs, &extern token as callback,
 * retained callbacks (rvm_callback / rvm_callback_free / CALLS_BACK), and Miri-safe call_guest paths.
 */
#include "rvm_bpf.h"

#ifndef FACTOR
#define FACTOR 2
#endif

struct S3 {
    u8 a;
    u8 b;
    u8 c;
};

struct S12 {
    u32 x;
    u32 y;
    u32 z;
};

extern void qsort(void *base, u64 nmemb, u64 size, int (*compar)(const void __host *, const void __host *))
    IMPORT_FROM("ucrtbase.dll");

extern double call_float_cb(double (*cb)(double a, float b, u64 c, double d, float e), double a, float b, u64 c,
                            double d, float e);
extern u64 call_struct_cb(u64 (*cb)(struct S3 s3, struct S12 s12, u64 k), struct S3 s3, struct S12 s12, u64 k);

extern u64 nat_double(u64 x);
extern u64 apply_u64(u64 (*cb)(u64), u64 x);

extern u64 fire_cb(u64 x) CALLS_BACK;
extern u64 host_call_guest(u64 cb, u64 arg);
extern u64 host_remap(void);

static int cmp_u64(const void __host *a, const void __host *b) {
    u64 va = *(const u64 __host *)a;
    u64 vb = *(const u64 __host *)b;
    return (va > vb) - (va < vb);
}

u64 test_qsort(void) {
    u64 arr[6] = {42, 7, 99, 1, 15, 3};
    qsort(arr, 6, sizeof(u64), cmp_u64);
    /* verify sorted order: 1, 3, 7, 15, 42, 99 */
    for (u64 i = 1; i < 6; i++) {
        if (arr[i - 1] > arr[i]) return 0;
    }
    return arr[0] + arr[1] * 10 + arr[2] * 100 + arr[3] * 1000 + arr[4] * 10000 + arr[5] * 100000;
}

static u64 f64_bits(double v) {
    union {
        double d;
        u64 u;
    } x = {.d = v};
    return x.u;
}

static u32 f32_bits(float v) {
    union {
        float f;
        u32 u;
    } x = {.f = v};
    return x.u;
}

static double bits_f64(u64 u) {
    union {
        double d;
        u64 u;
    } x = {.u = u};
    return x.d;
}

static double float_cb(double a, float b, u64 c, double d, float e) {
    /* XOR all incoming bit patterns and return as a double (verifies xmm0..xmm3, stack arg 5, and xmm0 return). */
    u64 mix = f64_bits(a) ^ ((u64)f32_bits(b) << 1) ^ (c << 2) ^ (f64_bits(d) >> 1) ^ ((u64)f32_bits(e) << 3);
    return bits_f64(mix);
}

u64 test_float_cb(void) {
    double r = call_float_cb(float_cb, 1.5, 2.25f, 3, 4.0, 5.5f);
    return f64_bits(r);
}

static u64 struct_cb(struct S3 s3, struct S12 s12, u64 k) {
    return (u64)s3.a + (u64)s3.b * 2 + (u64)s3.c * 3 + s12.x + s12.y * 10 + s12.z * 100 + k * 1000;
}

u64 test_struct_cb(u64 k) {
    struct S3 s3 = {1, 2, 3};
    struct S12 s12 = {4, 5, 6};
    return call_struct_cb(struct_cb, s3, s12, k);
}

u64 test_token_as_cb(u64 x) {
    return apply_u64(nat_double, x);
}

u64 test_null_cb(u64 x) {
    return apply_u64(NULL, x);
}

u64 on_event(u64 x) {
    return x * FACTOR + 1;
}

static u64 static_cb(u64 x) {
    return x + 100;
}

u64 make_exported_cb(void) {
    return (u64)rvm_callback(on_event);
}

u64 make_static_cb(void) {
    return (u64)rvm_callback(static_cb);
}

void free_cb(u64 thunk) {
    rvm_callback_free((void *)thunk);
}

u64 run_fire_cb(u64 x) {
    return fire_cb(x);
}

static void *pool_slots[64];

u64 test_pool_exhaustion(void) {
    for (int i = 0; i < 64; i++) {
        pool_slots[i] = rvm_callback(static_cb);
        if (!pool_slots[i]) return 1000 + (u64)i;
    }
    /* 65th must fail (NULL) */
    if (rvm_callback(static_cb) != NULL) return 2000;
    /* free one and claim again */
    rvm_callback_free(pool_slots[17]);
    void *reused = rvm_callback(static_cb);
    if (!reused) return 3000;
    pool_slots[17] = reused;
    for (int i = 0; i < 64; i++) {
        rvm_callback_free(pool_slots[i]);
    }
    return 1;
}

static noinline u64 guest_double(u64 x) {
    return x * 2 + 1;
}

static noinline u64 guest_recurse(u64 n) {
    if (n == 0) return 1;
    return 1 + host_call_guest((u64)guest_recurse, n - 1);
}

static noinline u64 guest_fault(u64 x) {
    volatile u64 *bad = (volatile u64 *)(x + 0x1234);
    return *bad;
}

static noinline u64 guest_spin(u64 n) {
    u64 acc = 0;
    for (u64 i = 0; i < n; i++) {
        acc += i;
        asm volatile("" : "+r"(acc));
    }
    return acc;
}

static noinline u64 guest_remap(u64 x) {
    u64 addr = host_remap();
    volatile u64 *p = (volatile u64 *)addr;
    *p = x + 77;
    return *p;
}

static noinline u64 guest_switch(u64 x) {
    switch (x) {
    case 0: return 10;
    case 1: return 20;
    case 2: return 30;
    case 3: return 40;
    case 4: return 50;
    case 5: return 60;
    case 6: return 70;
    case 7: return 80;
    case 8: return 90;
    case 9: return 100;
    default: return 999;
    }
}

u64 run_call_guest(u64 which, u64 arg) {
    u64 fn = 0;
    if (which == 0) fn = (u64)guest_double;
    else if (which == 1) fn = (u64)guest_recurse;
    else if (which == 2) fn = (u64)guest_fault;
    else if (which == 3) fn = (u64)guest_spin;
    else if (which == 4) fn = (u64)guest_remap;
    else if (which == 5) fn = (u64)guest_switch;
    else fn = arg;
    return host_call_guest(fn, arg);
}

/* Calls a local function that reads stack memory before and after the callback to verify window revalidation. */
u64 run_remap_and_read(u64 x) {
    u64 local = 55;
    asm volatile("" : "+m"(local));
    u64 r = host_call_guest((u64)guest_remap, x);
    return r + local;
}
