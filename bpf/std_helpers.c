/*
 * Uses the opt-in standard helpers: ktime_get_ns, trace_printk, get_prandom_u32.
 * Build: clang -target bpf -O2 -g -c bpf/std_helpers.c -o bpf/std_helpers.o
 */
typedef unsigned int u32;
typedef unsigned long long u64;

static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_trace_printk)(const char *fmt, u32 fmt_size, ...) = (void *)6;
static u32 (*bpf_get_prandom_u32)(void) = (void *)7;

/* Prints one line and returns nanoseconds elapsed across the print. */
u64 report(u64 x) {
    static const char fmt[] = "x=%llu neg=%d hex=%x\n";
    u64 start = bpf_ktime_get_ns();
    bpf_trace_printk(fmt, sizeof(fmt), x, -(int)x, (u32)x);
    return bpf_ktime_get_ns() - start;
}

/* Two draws differ (with overwhelming probability). */
u64 draws_differ(void) {
    return bpf_get_prandom_u32() != bpf_get_prandom_u32();
}
