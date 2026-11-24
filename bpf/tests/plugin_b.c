/*
 * Plugin importing a_scale from plugin_a_v1 and a host function that calls back into
 * this plugin.
 */
#include "rvm_bpf.h"
extern u64 a_scale(u64 x);
extern u64 host_reenter(u64 x);

u64 b_run(u64 x) {
    return a_scale(x) + 1;
}

u64 b_reenter(u64 x) {
    return host_reenter(x);
}
