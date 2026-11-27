// rvmrt: load a prepared rvm image and call its functions.
//
// Link rvmrt.dll through its import library rvmrt.dll.lib, or link the static rvmrt.lib together with the system
// libraries that `cargo rustc --print native-static-libs` lists. A panic inside the runtime aborts the process.

#ifndef RVMRT_H
#define RVMRT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rvm_program rvm_program;

typedef enum rvm_status {
    RVM_OK = 0,
    // a malformed image, one written by another rvm version, or one that needs more memory than rvm's
    // DEFAULT_MEMORY_LIMIT
    RVM_ERR_IMAGE = 1,
    // the image imports a helper or host function that the runtime doesn't have, a native function with another
    // signature, or declares maps
    RVM_ERR_LINK = 2,
    // no function with this name
    RVM_ERR_NOT_FOUND = 3,
    // more than 12 call arguments, a length that can't be mapped, no free region to map, an address that rvm_map
    // didn't return, a name that isn't UTF-8, a null required pointer, or an invalid rvm_native or rvm_options
    RVM_ERR_ARGUMENT = 4,
    // the call ran more than the runtime's limit of 1,000,000 instructions (rvm's DEFAULT_INSTRUCTION_LIMIT); a
    // library built without its `fuel` feature has no limit
    RVM_ERR_LIMIT = 5,
    // an invalid instruction or memory access, or a call stack overflow; also an rvm_read or rvm_write of bytes the
    // guest may not read or write
    RVM_ERR_FAULT = 6,
    // a helper failed
    RVM_ERR_HELPER = 7,
    RVM_ERR_OTHER = 8,
} rvm_status;

// Loads a prepared image (rvm's Image::to_bytes) and stores the program in *program.
rvm_status rvm_load(const uint8_t *image, size_t len, rvm_program **program);

// A native function that images import by name, as an extern (`extern u64 name(...);` in C), and that the
// interpreter calls directly. It must:
// - take its `args` arguments, each an integer or pointer of up to 64 bits, in the host C convention (Windows x64 on
//   Windows, System V AMD64 on Unix) and return its result in rax. The guest passes the sixth argument and those after
//   it on its stack, as clang 23 compiles a call with more than five, and they reach the function like the first five;
// - never unwind: no C++ exception, SEH unwind or longjmp may leave it;
// - stay loaded while any program loaded with it may call it, and be safe to run on several threads at once;
// - leave the program that calls it alone: no rvmrt function may take that program during the call;
// - stay sound for any argument values: the runtime checks only the pointers `kind` declares, so integer arguments
//   and the bytes behind pointers are the guest's choice.
// Before the call, each pointer argument is checked: the guest must be allowed to read the bytes (RVM_ARG_READ) or
// read and write them (RVM_ARG_WRITE), one byte at the pointer or as many as its length argument holds. The function
// then gets the host address of the bytes (or a canonical non-null, 16-byte-aligned dangling address when the length
// argument is 0), and a failed check stops the guest's call with RVM_ERR_FAULT. Pointers
// inside guest memory keep the guest's region tags and don't resolve in native code; pointers the function returns
// don't resolve in the guest. RVM_UNTAGGED and RVM_RAW_POINTERS change both. Native time doesn't count against the
// instruction limit, and a native function can't fail the guest's call.
enum { RVM_ARG_INT = 0, RVM_ARG_READ = 1, RVM_ARG_WRITE = 2 };

typedef struct rvm_native {
    const char *name;
    size_t name_len;
    const void *func;
    // number of arguments, 0 to 12
    uint8_t args;
    // per argument: RVM_ARG_INT, RVM_ARG_READ or RVM_ARG_WRITE
    uint8_t kind[12];
    // per pointer argument: 0 to check one byte, or the number (1 to 12) of the integer argument that holds the
    // pointer's length in bytes
    uint8_t len_arg[12];
} rvm_native;

// What the guest of a program may do beyond the default, in which every memory access is checked against the memory
// the runtime maps for the program and a call through a pointer reaches only the program's own functions. Each flag
// makes the guest as trusted as native code for what it allows, and nothing checks what the guest then does:
// - RVM_RAW_POINTERS: an address without a region tag, from 64 KiB up, is a host address, which the guest reads and
//   writes directly. The guest's own memory stays checked. The host hands the guest such pointers as integers.
// - RVM_UNTAGGED: every guest pointer is a plain host address, also into the guest's own memory, and no access is
//   checked. Native functions get each argument as the register holds it, without the checks of rvm_native. rvm_map
//   returns a host address. Includes RVM_RAW_POINTERS.
// - RVM_RAW_CALLS: a call through a function pointer that holds an address without a region tag, from 64 KiB up,
//   calls the native function there, with up to 5 arguments in the Windows x64 convention, the first four also in
//   xmm0 to xmm3. Nothing validates the address, so the guest can call any code in the process with any arguments.
//   The arguments pass as the registers hold them: a pointer into guest memory keeps its region tag unless the
//   program is loaded with RVM_UNTAGGED or the guest strips the tag (UNTAG in rvm's bpf/rvm_bpf.h). In a program
//   with a call of more than five arguments anywhere, every such call passes 12: the five registers, and the seven
//   stack arguments as the calling function stored them last. The function must never unwind and must leave the
//   calling program alone, as a native function of rvm_native must, and its time doesn't count against the
//   instruction limit.
enum { RVM_UNTAGGED = 1, RVM_RAW_POINTERS = 2, RVM_RAW_CALLS = 4 };

typedef struct rvm_options {
    // sizeof(rvm_options)
    size_t size;
    // the native functions the image imports, `native_count` entries; may be NULL when the count is 0. Each native
    // import of the image must name one of them with the signature the image was linked against.
    const rvm_native *natives;
    size_t native_count;
    // RVM_UNTAGGED, RVM_RAW_POINTERS and RVM_RAW_CALLS, or 0
    uint32_t flags;
} rvm_options;

// rvm_load with `options`, or default options when `options` is NULL. RVM_ERR_ARGUMENT if `size` isn't the library's
// sizeof(rvm_options) or `flags` has a bit the library doesn't know.
rvm_status rvm_load_with(const uint8_t *image, size_t len, const rvm_options *options, rvm_program **program);

// Frees a program from rvm_load; NULL is ignored.
void rvm_free(rvm_program *program);

// Maps len zeroed read-write bytes at an address the runtime picks and stores that address in *addr.
rvm_status rvm_map(rvm_program *program, size_t len, uint64_t *addr);

// Unmaps the region that rvm_map mapped at addr.
rvm_status rvm_unmap(rvm_program *program, uint64_t addr);

// Copies len bytes at guest address addr into buf. The guest must be allowed to read them. buf may be NULL when len
// is 0.
rvm_status rvm_read(const rvm_program *program, uint64_t addr, uint8_t *buf, size_t len);

// Copies len bytes from buf to guest address addr. The guest must be allowed to write them. buf may be NULL when len
// is 0.
rvm_status rvm_write(rvm_program *program, uint64_t addr, const uint8_t *buf, size_t len);

// Calls the function `name` with up to 12 args and stores its r0 in *ret (or discards it if `ret` is NULL): the first
// five go in r1 to r5, the others where a caller passes them on its stack, so the function takes them as clang 23
// compiles a function with more than five parameters. name and args may be NULL when their length is 0.
rvm_status rvm_call(rvm_program *program, const char *name, size_t name_len, const uint64_t *args, size_t nargs,
                    uint64_t *ret);

// Functions have indices from 0 to rvm_function_count - 1, in name order. A call by index skips the name lookup.

// Stores the index of the function `name` in *index. name may be NULL when name_len is 0.
rvm_status rvm_func(const rvm_program *program, const char *name, size_t name_len, size_t *index);

// Calls the function at `index` like rvm_call (`ret` may be NULL); RVM_ERR_NOT_FOUND if index is out of range.
rvm_status rvm_call_func(rvm_program *program, size_t index, const uint64_t *args, size_t nargs, uint64_t *ret);

// Number of functions, or 0 if `program` is NULL.
size_t rvm_function_count(const rvm_program *program);

// Stores the name of the function at `index` in *name and *name_len; RVM_ERR_NOT_FOUND if index is out of range. The
// name is UTF-8, not NUL-terminated, and valid until the program is freed.
rvm_status rvm_function_name(const rvm_program *program, size_t index, const char **name, size_t *name_len);

#ifdef __cplusplus
}
#endif

#endif
