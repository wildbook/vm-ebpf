/*
 * A host's actual `struct event` layout, shipped as plain BTF (no CO-RE access
 * indexes: this is the real layout, not a program reading someone else's).
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/host_event.c -o bpf/tests/host_event.o
 */
#include "../rvm_bpf.h"

struct event {
    u32 flags;
    u32 pid;
    u64 timestamp;
};

/* Forces clang to emit the struct's BTF; a type that's merely declared and never
 * referenced from a variable or function doesn't make it into the .BTF section. */
struct event host_event;
