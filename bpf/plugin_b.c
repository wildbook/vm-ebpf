/*
 * Plugin importing a_scale from plugin_a and a host function that calls back into
 * this plugin.
 * Build: clang -target bpf -O2 -g -c bpf/plugin_b.c -o bpf/plugin_b.o
 */
typedef unsigned long long u64;

extern u64 a_scale(u64 x);
extern u64 host_reenter(u64 x);

u64 b_run(u64 x) {
    return a_scale(x) + 1;
}

u64 b_reenter(u64 x) {
    return host_reenter(x);
}
