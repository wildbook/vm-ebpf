/*
 * A sorted singly linked list inside one byte arena, linked by 16-bit offsets instead of pointers as shared memory or a
 * serialized arena holds it: inserts in key order, walks the list, and unlinks every node with an odd key.
 */
#include "corpus.h"

#define NIL 0

struct node {
    u16 next;
    u16 len;
    u32 key;
    u8 payload[8];
};

static u8 arena[4096];

static struct node *at(u16 off) {
    return (struct node *)(arena + off);
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    u16 head = NIL, top = sizeof(struct node);
    for (u32 i = 0; i < 150; i++) {
        u64 r = rng_next(&rng);
        u16 off = top;
        top += sizeof(struct node);
        struct node *n = at(off);
        n->key = r % 10000;
        n->len = 1 + (r >> 16 & 7);
        for (u32 b = 0; b < n->len; b++)
            n->payload[b] = r >> (24 + 4 * b);

        u16 *link = &head;
        while (*link != NIL && at(*link)->key < n->key)
            link = &at(*link)->next;
        n->next = *link;
        *link = off;
    }

    u64 acc = 0, pos = 0;
    for (u16 off = head; off != NIL; off = at(off)->next, pos++) {
        const struct node *n = at(off);
        acc = acc * 31 + n->key * pos;
        for (u32 b = 0; b < n->len; b++)
            acc += n->payload[b];
    }
    u64 left = 0;
    for (u16 *link = &head; *link != NIL;) {
        struct node *n = at(*link);
        if (n->key & 1) {
            *link = n->next;
        } else {
            left += n->key;
            link = &n->next;
        }
    }
    return acc ^ left << 40;
}
