/*
 * Plugin exporting a_scale; a second build with FACTOR=3 tests hot reload.
 */
#include "rvm_bpf.h"
#ifndef FACTOR
#define FACTOR 2
#endif

u64 a_scale(u64 x) {
    return x * FACTOR;
}
