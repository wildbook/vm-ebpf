/*
 * Declarations shared by the BPF programs under bpf/: integer types, libbpf-style map definitions, borrow tags and
 * the standard helpers rvm provides.
 */
#ifndef RVM_BPF_H
#define RVM_BPF_H

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

#define NULL ((void *)0)

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define noinline __attribute__((noinline))

/* The callee uses the caller's buffer in place for one call; parameter `len_arg` holds its size in bytes. */
#define BORROW(len_arg)    __attribute__((btf_decl_tag("borrow:" #len_arg)))
#define BORROW_RO(len_arg) __attribute__((btf_decl_tag("borrow_ro:" #len_arg)))

/* Map types and update flags, as in lib/rvm/src/map_def/btf.rs and lib/rvm/src/maps/mod.rs. */
#define BPF_MAP_TYPE_HASH  1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

/* The info kinds of clang's __builtin_preserve_field_info and __builtin_preserve_type_info, as libbpf names them. */
enum bpf_field_info_kind {
    BPF_FIELD_BYTE_OFFSET = 0,
    BPF_FIELD_BYTE_SIZE = 1,
    BPF_FIELD_EXISTS = 2,
    BPF_FIELD_SIGNED = 3,
    BPF_FIELD_LSHIFT_U64 = 4,
    BPF_FIELD_RSHIFT_U64 = 5,
};

enum bpf_type_info_kind {
    BPF_TYPE_EXISTS = 0,
    BPF_TYPE_SIZE = 1,
    BPF_TYPE_MATCHES = 2,
};

/* Map helpers, always available; see lib/rvm/src/maps/helpers.rs. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;

/* Opt-in helpers the host enables with Vm::enable_*; see lib/rvm/src/std_helpers.rs. */
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_trace_printk)(const char *fmt, u32 fmt_size, ...) = (void *)6;
static u32 (*bpf_get_prandom_u32)(void) = (void *)7;

/*
 * Calls through a function pointer to native code, which the host allows with RawCalls::on().
 *
 * NATIVE_AT(type, addr) is a function pointer of type `type` to the native code at `addr`, for an address the plugin
 * holds as a constant. Clang compiles a call through a constant address as a helper call and keeps only the low 32
 * bits of the address, so the macro moves the address through a register.
 */
#define NATIVE_AT(type, addr)             \
    ({                                    \
        u64 rvm_at_ = (u64)(addr);        \
        asm volatile("" : "+r"(rvm_at_)); \
        (type) rvm_at_;                   \
    })

/*
 * The pointer `p` without its region tag: the host address of its byte, which native code can follow. A call through
 * a function pointer passes each argument as the register holds it, so a plugin whose pointers carry tags strips
 * the tag of a pointer argument. An untagged plugin needs no UNTAG: its pointers are host addresses.
 */
#define UNTAG(p) ((__typeof__(0 ? (p) : (p)))((u64)(p) & 0x03ffffffffffffffULL))

#endif
