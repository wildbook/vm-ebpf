/**
 * example.c - eBPF program that compiles to BPF bytecode
 *
 * This program demonstrates:
 * - Global variables (rodata/data sections)
 * - Function calls (BPF-to-BPF calls)
 * - Arithmetic operations
 * - Conditional branches
 * - Memory access via struct pointers
 *
 * Compile with:
 *   clang -target bpf -O2 -g -c example.c -o example.o
 *
 * Or use the provided Makefile:
 *   make example.o
 */

/* Prevent clang from using standard includes */
#define NULL ((void *)0)

/* Types for eBPF */
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

/* eBPF section attributes */
#define SEC(name) __attribute__((section(name), used))

/* Input context structure - passed to the eBPF program */
struct input_ctx {
    u64 value_a;
    u64 value_b;
    u32 operation;  /* 0=add, 1=sub, 2=mul, 3=div, 4=fibonacci */
    u32 flags;
};

/* Result structure - filled by the eBPF program */
struct output_result {
    u64 result;
    u32 status;     /* 0=success, 1=error */
    u32 reserved;
};

/* Global constants (goes into .rodata section) */
SEC(".rodata")
const u32 MAX_FIB_N = 20;

SEC(".rodata")
const u64 MAGIC_VALUE = 0xDEADBEEFCAFEBABEULL;

/* Global mutable data (goes into .data section) */
SEC(".data")
u64 call_count = 0;

SEC(".data")
u64 last_result = 0;

/**
 * Helper function: compute nth Fibonacci number
 * Demonstrates BPF-to-BPF function calls and recursion
 * (Note: deep recursion may hit stack limits)
 */
static u64 fibonacci(u32 n) {
    if (n <= 1) {
        return n;
    }

    /* Iterative version to avoid deep recursion */
    u64 prev = 0;
    u64 curr = 1;

    for (u32 i = 2; i <= n; i++) {
        u64 next = prev + curr;
        prev = curr;
        curr = next;
    }

    return curr;
}

/**
 * Helper function: saturating add (no overflow)
 */
static u64 saturating_add(u64 a, u64 b) {
    u64 result = a + b;
    /* Check for overflow */
    if (result < a) {
        return ~0ULL; /* Return max value on overflow */
    }
    return result;
}

/**
 * Helper function: safe divide (handle divide by zero)
 */
static u64 safe_divide(u64 a, u64 b, u32 *status) {
    if (b == 0) {
        *status = 1; /* Error: divide by zero */
        return 0;
    }
    *status = 0;
    return a / b;
}

/**
 * Main eBPF program entry point
 *
 * Takes a pointer to input_ctx in r1, pointer to output_result in r2
 * Returns 0 on success, non-zero on error
 */
SEC("prog")
int bpf_main(struct input_ctx *ctx, struct output_result *out) {
    /* Increment call counter */
    call_count++;

    /* Initialize output */
    out->status = 0;
    out->reserved = 0;

    u64 a = ctx->value_a;
    u64 b = ctx->value_b;
    u32 op = ctx->operation;
    u64 result = 0;

    /* Perform requested operation */
    switch (op) {
        case 0: /* Addition */
            result = saturating_add(a, b);
            break;

        case 1: /* Subtraction */
            result = a - b;
            break;

        case 2: /* Multiplication */
            result = a * b;
            break;

        case 3: /* Division */
            result = safe_divide(a, b, &out->status);
            break;

        case 4: /* Fibonacci */
            if (a > MAX_FIB_N) {
                out->status = 1; /* Error: n too large */
                result = 0;
            } else {
                result = fibonacci((u32)a);
            }
            break;

        default:
            out->status = 1; /* Error: unknown operation */
            result = MAGIC_VALUE; /* Return magic value for debugging */
            break;
    }

    /* Store result */
    out->result = result;
    last_result = result;

    return out->status ? -1 : 0;
}

/**
 * Alternative entry point: simple calculator
 * Takes two values and returns their sum
 * Simpler version for basic testing
 */
SEC("simple")
u64 simple_add(u64 a, u64 b) {
    return a + b;
}

/**
 * Entry point that just returns a constant
 * Useful for minimal testing
 */
SEC("const")
u64 return_magic(void) {
    return MAGIC_VALUE;
}
