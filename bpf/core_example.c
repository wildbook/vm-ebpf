/**
 * core_example.c - eBPF program demonstrating CO-RE relocations
 *
 * This program reads fields from a struct where the compile-time layout
 * may differ from the runtime layout. CO-RE relocations adjust the field
 * offsets at load time based on the host's type registry.
 *
 * Compile with BTF for CO-RE support:
 *   clang -target bpf -O2 -g -c core_example.c -o core_example.o
 *
 * The -g flag generates BTF (BPF Type Format) which includes type information
 * and CO-RE relocation records in .BTF and .BTF.ext sections.
 */

/* Prevent clang from using standard includes */
#define NULL ((void *)0)

/* eBPF types */
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed int         __s32;
typedef signed long long   __s64;

/* Section attribute */
#define SEC(name) __attribute__((section(name), used))

/* CO-RE helper macros */
#define __bpf_attribute_preserve_access_index \
    __attribute__((preserve_access_index))

/**
 * Event structure - the BPF program accesses fields of this struct.
 *
 * The preserve_access_index attribute tells clang to generate CO-RE
 * relocations for any field accesses. At runtime, the actual field
 * offsets are looked up in the host's type registry and patched into
 * the instructions.
 *
 * COMPILE-TIME LAYOUT (what the BPF program sees):
 *   offset 0:  timestamp (8 bytes)
 *   offset 8:  pid       (4 bytes)
 *   offset 12: uid       (4 bytes)
 *   offset 16: flags     (4 bytes)
 *   offset 20: padding   (4 bytes)
 *   offset 24: data      (8 bytes)
 *   total size: 32 bytes
 *
 * RUNTIME LAYOUT (what the host may use - different offsets!):
 *   offset 0:  flags     (4 bytes)  <- moved to front
 *   offset 4:  pid       (4 bytes)
 *   offset 8:  uid       (4 bytes)
 *   offset 12: padding   (4 bytes)
 *   offset 16: timestamp (8 bytes)  <- moved later
 *   offset 24: data      (8 bytes)
 *   total size: 32 bytes
 *
 * CO-RE relocations make the same compiled BPF program work with both layouts!
 */
struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 _pad;
    __u64 data;
} __bpf_attribute_preserve_access_index;

/**
 * Read the timestamp field from an event struct.
 *
 * The access `evt->timestamp` generates a CO-RE relocation that will
 * be patched to use the correct offset from the host's type registry.
 */
SEC("prog")
__u64 read_timestamp(struct event *evt) {
    /* This field access generates:
     * - A load instruction with compile-time offset (0)
     * - A CO-RE relocation record to patch in runtime offset
     */
    return evt->timestamp;
}

/**
 * Read the pid field from an event struct.
 */
SEC("prog")
__u32 read_pid(struct event *evt) {
    return evt->pid;
}

/**
 * Read the flags field from an event struct.
 */
SEC("prog")
__u32 read_flags(struct event *evt) {
    return evt->flags;
}

/**
 * Read the data field from an event struct.
 */
SEC("prog")
__u64 read_data(struct event *evt) {
    return evt->data;
}

/**
 * Read multiple fields and combine them.
 * This demonstrates that multiple CO-RE relocations work together.
 */
SEC("prog")
__u64 combine_fields(struct event *evt) {
    /* Each field access generates its own CO-RE relocation */
    __u64 ts = evt->timestamp;
    __u32 pid = evt->pid;
    __u32 flags = evt->flags;
    
    /* Combine: timestamp + (pid << 32) + flags */
    return ts + (((__u64)pid) << 32) + flags;
}

/**
 * Simple function that doesn't use CO-RE, for baseline testing.
 */
SEC("prog")
__u64 no_core_add(__u64 a, __u64 b) {
    return a + b;
}
