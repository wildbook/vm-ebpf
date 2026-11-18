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
    // a malformed image, or one written by another rvm version
    RVM_ERR_IMAGE = 1,
    // the image imports a helper or host function that the runtime doesn't have
    RVM_ERR_LINK = 2,
    // no function with this name
    RVM_ERR_NOT_FOUND = 3,
    // more than 5 call arguments, a region or length that can't be mapped, or a name that isn't UTF-8
    RVM_ERR_ARGUMENT = 4,
    // the call ran more instructions than the limit (1,000,000)
    RVM_ERR_LIMIT = 5,
    // an invalid instruction or memory access, or a call stack overflow
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

// Calls the function `name` with args in r1 to r5 and stores its r0 in *ret. name and args may be NULL when their
// length is 0.
rvm_status rvm_call(rvm_program *program, const char *name, size_t name_len, const uint64_t *args, size_t nargs,
                    uint64_t *ret);

#ifdef __cplusplus
}
#endif

#endif
