/*
 * Helpers that read through pointers the caller passes in, which need the guest's read permission.
 * Build: clang -target bpf -mcpu=v3 -O2 -g -c bpf/guest_ptrs.c -o bpf/guest_ptrs.o
 */
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*bpf_trace_printk)(const char *fmt, u32 fmt_size, ...) = (void *)6;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, u64);
    __type(value, u64);
} seen SEC(".maps");

/* Print `fmt`, 8 bytes long. */
long print_fmt(const char *fmt) {
    return bpf_trace_printk(fmt, 8);
}

/* Print the string at `s`. */
long print_str(const char *s) {
    static const char fmt[] = "%s";
    return bpf_trace_printk(fmt, sizeof(fmt), s);
}

/* The value for the key at `key`, or -1 if absent. */
u64 lookup(const u64 *key) {
    u64 *value = bpf_map_lookup_elem(&seen, key);
    return value ? *value : (u64)-1;
}

/* Store the value at `value` under key 0. */
long store(const u64 *value) {
    u64 key = 0;
    return bpf_map_update_elem(&seen, &key, value, BPF_ANY);
}
