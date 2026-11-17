/*
 * Calculator used by bin/loader and the integration tests: globals in .rodata
 * and .data, BPF-to-BPF calls, and struct pointer arguments.
 * Build: clang -target bpf -O2 -g -c bpf/example.c -o bpf/example.o
 */

#define NULL ((void *)0)

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

#define SEC(name) __attribute__((section(name), used))

struct input_ctx {
    u64 value_a;
    u64 value_b;
    u32 operation;  /* 0=add, 1=sub, 2=mul, 3=div, 4=fibonacci */
    u32 flags;
};

struct output_result {
    u64 result;
    u32 status;     /* 0=success, 1=error */
    u32 reserved;
};

SEC(".rodata")
const u32 MAX_FIB_N = 20;

SEC(".rodata")
const u64 MAGIC_VALUE = 0xDEADBEEFCAFEBABEULL;

SEC(".data")
u64 call_count = 0;

SEC(".data")
u64 last_result = 0;

static u64 fibonacci(u32 n) {
    if (n <= 1) {
        return n;
    }

    u64 prev = 0;
    u64 curr = 1;

    for (u32 i = 2; i <= n; i++) {
        u64 next = prev + curr;
        prev = curr;
        curr = next;
    }

    return curr;
}

static u64 saturating_add(u64 a, u64 b) {
    u64 result = a + b;
    if (result < a) {
        return ~0ULL;
    }
    return result;
}

static u64 safe_divide(u64 a, u64 b, u32 *status) {
    if (b == 0) {
        *status = 1; /* divide by zero */
        return 0;
    }
    *status = 0;
    return a / b;
}

/* Returns 0 on success and -1 on error, with the error in out->status. */
SEC("prog")
int bpf_main(struct input_ctx *ctx, struct output_result *out) {
    call_count++;

    out->status = 0;
    out->reserved = 0;

    u64 a = ctx->value_a;
    u64 b = ctx->value_b;
    u32 op = ctx->operation;
    u64 result = 0;

    switch (op) {
        case 0:
            result = saturating_add(a, b);
            break;

        case 1:
            result = a - b;
            break;

        case 2:
            result = a * b;
            break;

        case 3:
            result = safe_divide(a, b, &out->status);
            break;

        case 4:
            if (a > MAX_FIB_N) {
                out->status = 1; /* n too large */
                result = 0;
            } else {
                result = fibonacci((u32)a);
            }
            break;

        default:
            out->status = 1; /* unknown operation */
            result = MAGIC_VALUE;
            break;
    }

    out->result = result;
    last_result = result;

    return out->status ? -1 : 0;
}

SEC("simple")
u64 simple_add(u64 a, u64 b) {
    return a + b;
}

SEC("const")
u64 return_magic(void) {
    return MAGIC_VALUE;
}
