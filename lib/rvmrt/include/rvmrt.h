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
    // the image imports a helper or host function that the runtime doesn't have, or declares maps
    RVM_ERR_LINK = 2,
    // no function with this name
    RVM_ERR_NOT_FOUND = 3,
    // more than 5 call arguments, a region or length that can't be mapped, or a name that isn't UTF-8
    RVM_ERR_ARGUMENT = 4,
    // the call ran more than the runtime's limit of 1,000,000 instructions (rvm's DEFAULT_INSTRUCTION_LIMIT)
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

// Frees a program from rvm_load; NULL is ignored.
void rvm_free(rvm_program *program);

// Maps len zeroed read-write bytes as host region `region`, counted from 0, and stores the region's guest address in
// *addr. A region that is already mapped is replaced.
rvm_status rvm_map(rvm_program *program, size_t region, size_t len, uint64_t *addr);

// Unmaps host region `region`, counted from 0 as rvm_map counts it. A region that isn't mapped stays unmapped.
rvm_status rvm_unmap(rvm_program *program, size_t region);

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
