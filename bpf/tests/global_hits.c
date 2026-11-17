/*
 * A global named like the map in shared_counter.c, for linking the two together.
 */
#include "../rvm_bpf.h"

u64 hits = 5;

u64 get(void) {
    return hits;
}
