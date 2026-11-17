/*
 * Reads `struct event` fields through CO-RE relocations, which the linker
 * patches to the host's layout of the struct.
 */

#define NULL ((void *)0)

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed int         __s32;
typedef signed long long   __s64;

#define SEC(name) __attribute__((section(name), used))

#define __bpf_attribute_preserve_access_index \
    __attribute__((preserve_access_index))

/*
 * The layout this program is compiled against. lib/rvm/examples/core_reloc.rs
 * describes a host layout with flags at 0 and timestamp at 16.
 */
struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 _pad;
    __u64 data;
} __bpf_attribute_preserve_access_index;

SEC("prog")
__u64 read_timestamp(struct event *evt) {
    return evt->timestamp;
}

SEC("prog")
__u32 read_pid(struct event *evt) {
    return evt->pid;
}

SEC("prog")
__u32 read_flags(struct event *evt) {
    return evt->flags;
}

SEC("prog")
__u64 read_data(struct event *evt) {
    return evt->data;
}

SEC("prog")
__u64 combine_fields(struct event *evt) {
    __u64 ts = evt->timestamp;
    __u32 pid = evt->pid;
    __u32 flags = evt->flags;

    return ts + (((__u64)pid) << 32) + flags;
}

/* No CO-RE relocations. */
SEC("prog")
__u64 no_core_add(__u64 a, __u64 b) {
    return a + b;
}
