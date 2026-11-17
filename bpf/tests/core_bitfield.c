/*
 * CO-RE bitfield read, written out in the style of libbpf's bpf_core_read.h
 * BPF_CORE_READ_BITFIELD macro (no libbpf headers available to this fixture).
 */
#include "../rvm_bpf.h"

struct bits {
    unsigned reserved : 20;
    int b : 12;
} __attribute__((preserve_access_index));

enum {
    BPF_FIELD_BYTE_OFFSET = 0,
    BPF_FIELD_BYTE_SIZE = 1,
    BPF_FIELD_LSHIFT_U64 = 4,
    BPF_FIELD_RSHIFT_U64 = 5,
    BPF_FIELD_SIGNED = 3,
};

static u64 extract(const void *p, unsigned byte_size, unsigned lshift, unsigned rshift, int is_signed) {
    u64 val;
    switch (byte_size) {
    case 1: val = *(const unsigned char *)p; break;
    case 2: val = *(const unsigned short *)p; break;
    case 4: val = *(const unsigned int *)p; break;
    default: val = *(const u64 *)p; break;
    }
    val <<= lshift;
    if (is_signed)
        return (u64)(((long long)val) >> rshift);
    return val >> rshift;
}

u64 read_b(struct bits *s) {
    const char *base = (const char *)s + __builtin_preserve_field_info(s->b, BPF_FIELD_BYTE_OFFSET);
    return extract(base,
                    __builtin_preserve_field_info(s->b, BPF_FIELD_BYTE_SIZE),
                    __builtin_preserve_field_info(s->b, BPF_FIELD_LSHIFT_U64),
                    __builtin_preserve_field_info(s->b, BPF_FIELD_RSHIFT_U64),
                    __builtin_preserve_field_info(s->b, BPF_FIELD_SIGNED));
}
