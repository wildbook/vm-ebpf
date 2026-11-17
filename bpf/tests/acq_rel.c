/*
 * Message passing through a host-shared region with load-acquire and store-release.
 */
#include "rvm_bpf.h"
#define WORDS 6

struct mailbox {
    u64 seq; /* last published message */
    u32 ack; /* last consumed message */
    u32 pad;
    u64 payload[WORDS];
};

/* Publishes message `n` once message `n - 1` was consumed. Returns whether it did. */
u64 publish(struct mailbox *box, u64 n) {
    if (__atomic_load_n(&box->ack, __ATOMIC_ACQUIRE) != (u32)(n - 1))
        return 0;
    for (int i = 0; i < WORDS; i++)
        box->payload[i] = n * WORDS + i;
    __atomic_store_n(&box->seq, n, __ATOMIC_RELEASE);
    return 1;
}

/* Consumes message `n` once it is published. Returns the payload sum, or 0 before then. */
u64 consume(struct mailbox *box, u64 n) {
    if (__atomic_load_n(&box->seq, __ATOMIC_ACQUIRE) != n)
        return 0;
    u64 sum = 0;
    for (int i = 0; i < WORDS; i++)
        sum += box->payload[i];
    __atomic_store_n(&box->ack, (u32)n, __ATOMIC_RELEASE);
    return sum;
}

u64 load_u64(u64 *p) {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

u64 store_u16(u16 *p, u64 value) {
    __atomic_store_n(p, (u16)value, __ATOMIC_RELEASE);
    return 0;
}
