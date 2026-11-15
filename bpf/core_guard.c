/*
 * CO-RE against a host that may lack a field: `read_flags` checks for it first,
 * `read_flags_unguarded` doesn't.
 * Build: clang -target bpf -O2 -g -c bpf/core_guard.c -o bpf/core_guard.o
 */
typedef unsigned int u32;
typedef unsigned long long u64;

struct event {
    u64 timestamp;
    u32 pid;
    u32 flags;
} __attribute__((preserve_access_index));

u64 read_pid(struct event *e) {
    return e->pid;
}

u64 read_flags(struct event *e) {
    if (!__builtin_preserve_field_info(e->flags, 2 /* BPF_FIELD_EXISTS */))
        return 0xdead;
    return e->flags;
}

u64 read_flags_unguarded(struct event *e) {
    return e->flags;
}
