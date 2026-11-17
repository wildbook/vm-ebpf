/*
 * Helpers that read through pointers the caller passes in, which need the guest's read permission.
 */
#include "../rvm_bpf.h"

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
