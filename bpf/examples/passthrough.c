/*
 * Walks a linked list that the host in lib/rvm/examples/passthrough.rs owns, through the raw host pointers in its
 * structs. The host describes its own layout of both structs, which differs from the one here, and CO-RE patches each
 * field access to it.
 */
#include "rvm_bpf.h"

struct node {
    struct node *next;
    const char *name;
    s64 value;
    u32 visits;
} __attribute__((preserve_access_index));

struct scene {
    struct node *head;
    u64 walks;
} __attribute__((preserve_access_index));

/* Sums the node values, counts a visit on each node and a walk on the scene. */
s64 walk(struct scene *scene) {
    s64 sum = 0;
    for (struct node *n = scene->head; n; n = n->next) {
        sum += n->value;
        n->visits++;
    }
    __sync_fetch_and_add(&scene->walks, 1);
    return sum;
}

/* The first letters of up to 8 node names, packed from the low byte up. */
u64 initials(struct scene *scene) {
    u64 letters = 0;
    u32 shift = 0;
    for (struct node *n = scene->head; n && shift < 64; n = n->next, shift += 8)
        letters |= (u64)(u8)n->name[0] << shift;
    return letters;
}
