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
    // more than 5 call arguments, a length that can't be mapped, no free region to map, an address that rvm_map
    // didn't return, a name that isn't UTF-8, or an invalid rvm_native
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
// - take its `args` arguments, each an integer or pointer of up to 64 bits, in the Windows x64 convention and return
//   its result in rax;
// - never unwind: no C++ exception, SEH unwind or longjmp may leave it, unless the program is loaded with
//   RVM_CATCH_NATIVE (see rvm_load_with);
// - stay loaded while any program loaded with it may call it, and be safe to run on several threads at once;
// - stay sound for any argument values: the runtime checks only the pointers `kind` declares, so integer arguments
//   and the bytes behind pointers are the guest's choice.
// Before the call, each pointer argument is checked: the guest must be allowed to read the bytes (RVM_ARG_READ) or
// read and write them (RVM_ARG_WRITE), one byte at the pointer or as many as its length argument holds. The function
// then gets the host address of the bytes, and a failed check stops the guest's call with RVM_ERR_FAULT. Pointers
// inside guest memory keep the guest's region tags and don't resolve in native code; pointers the function returns
// don't resolve in the guest. Native time doesn't count against the instruction limit, and a native function can't
// fail the guest's call.
enum { RVM_ARG_INT = 0, RVM_ARG_READ = 1, RVM_ARG_WRITE = 2 };

typedef struct rvm_native {
    const char *name;
    size_t name_len;
    const void *func;
    // number of arguments, 0 to 5
    uint8_t args;
    // per argument: RVM_ARG_INT, RVM_ARG_READ or RVM_ARG_WRITE
    uint8_t kind[5];
    // per pointer argument: 0 to check one byte, or the number (1 to 5) of the integer argument that holds the
    // pointer's length in bytes
    uint8_t len_arg[5];
} rvm_native;

// rvm_load with the image's native imports bound to `natives`, `count` entries. Each import must name one of them
// with the signature the image was linked against.
rvm_status rvm_load_natives(const uint8_t *image, size_t len, const rvm_native *natives, size_t count,
                            rvm_program **program);

// The next two functions exist in a library built with its `seh` feature, on x86-64 Windows.
//
// Flags of rvm_load_with:
// - RVM_RAW_POINTERS: a guest address without a region tag, from 64 KiB up, is the host address, and the guest's
//   loads, stores and atomics there go straight to host memory, unchecked. Give a guest such a pointer only if every
//   access it may make through it is sound.
// - RVM_CATCH_NATIVE: an exception that leaves a native function fails the guest's call with RVM_ERR_FAULT instead
//   of ending the process: an access violation, a stack overflow or another hardware fault, a RaiseException
//   failure, a C++ exception. The system unwinds the function's frames first, which runs their __finally blocks and
//   C++ destructors as their compiler arranged them. rvm_last_exception tells which exception it was.
// - RVM_CATCH_RAW: with RVM_RAW_POINTERS, a guest access to a raw address that isn't mapped fails the call with
//   RVM_ERR_FAULT, as an access outside the guest's memory does.
// After a caught exception the program is callable as after any failed call. Everything else ends the process as
// before:
// - an exception in a native function that lies in the same executable or DLL as the runtime, as every native of a
//   host that links the static rvmrt.lib does unless it comes from another DLL, or in a native function that called
//   back into the runtime first;
// - an exception in a native function without unwind information;
// - breakpoints, single steps and other exception codes below 0xC0000000, which pass on to the debugger and the
//   host's handlers;
// - a fail-fast (__fastfail, a stack cookie check, abort) and heap corruption, which Windows gives to no handler.
// A caught exception leaves the native function's own state as it was at the exception: locks it held stay held,
// and C++ built without /EHa runs no destructors for a hardware fault. A debugger sees each caught exception as a
// first-chance exception. A native call costs about 25 instructions more with RVM_CATCH_NATIVE. With RVM_CATCH_RAW
// each call into the guest costs about 105 more, and each atomic about 18 more.
enum { RVM_RAW_POINTERS = 1, RVM_CATCH_NATIVE = 2, RVM_CATCH_RAW = 4 };

// rvm_load_natives with `flags`; RVM_ERR_ARGUMENT for a flag it doesn't know.
rvm_status rvm_load_with(const uint8_t *image, size_t len, const rvm_native *natives, size_t count, uint32_t flags,
                         rvm_program **program);

// Stores the code of the exception that failed the program's last call of a native function (an NTSTATUS, such as
// 0xC0000005 for an access violation) in *code and the address of the instruction that raised it in *address;
// RVM_ERR_NOT_FOUND if no call failed so.
rvm_status rvm_last_exception(const rvm_program *program, uint32_t *code, uint64_t *address);

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

// Calls the function `name` with args in r1 to r5 and stores its r0 in *ret. name and args may be NULL when their
// length is 0.
rvm_status rvm_call(rvm_program *program, const char *name, size_t name_len, const uint64_t *args, size_t nargs,
                    uint64_t *ret);

// Functions have indices from 0 to rvm_function_count - 1, in name order. A call by index skips the name lookup.

// Stores the index of the function `name` in *index. name may be NULL when name_len is 0.
rvm_status rvm_func(const rvm_program *program, const char *name, size_t name_len, size_t *index);

// Calls the function at `index` like rvm_call; RVM_ERR_NOT_FOUND if index is out of range.
rvm_status rvm_call_func(rvm_program *program, size_t index, const uint64_t *args, size_t nargs, uint64_t *ret);

size_t rvm_function_count(const rvm_program *program);

// Stores the name of the function at `index` in *name and *name_len; RVM_ERR_NOT_FOUND if index is out of range. The
// name is UTF-8, not NUL-terminated, and valid until the program is freed.
rvm_status rvm_function_name(const rvm_program *program, size_t index, const char **name, size_t *name_len);

#ifdef __cplusplus
}
#endif

#endif
