/*
 * Plugin exporting a_scale. Build twice to test hot reload:
 *   clang -target bpf -mcpu=v4 -O2 -g -c bpf/tests/plugin_a.c -o bpf/tests/plugin_a.o
 *   clang -target bpf -mcpu=v4 -O2 -g -DFACTOR=3 -c bpf/tests/plugin_a.c -o bpf/tests/plugin_a3.o
 */
typedef unsigned long long u64;

#ifndef FACTOR
#define FACTOR 2
#endif

u64 a_scale(u64 x) {
    return x * FACTOR;
}
