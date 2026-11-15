/*
 * Plugin exporting a_scale. Build twice to test hot reload:
 *   clang -target bpf -O2 -g -c bpf/plugin_a.c -o bpf/plugin_a.o
 *   clang -target bpf -O2 -g -DFACTOR=3 -c bpf/plugin_a.c -o bpf/plugin_a3.o
 */
typedef unsigned long long u64;

#ifndef FACTOR
#define FACTOR 2
#endif

u64 a_scale(u64 x) {
    return x * FACTOR;
}
