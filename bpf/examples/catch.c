/*
 * A plugin whose mistakes raise Windows exceptions in the host of lib/rvm/examples/catch.rs: it hands a bad pointer
 * to a native function, and reads through a raw host pointer that isn't mapped.
 */
#include "rvm_bpf.h"

struct item {
    u64 price;
    const char *label;
};

/* The C runtime's strlen, which the host registers as it is. */
extern u64 text_len(u64 text);

/* The length of an item's label. */
u64 label_len(const struct item *item) {
    return text_len((u64)item->label);
}

u64 price(const struct item *item) {
    return item->price;
}
