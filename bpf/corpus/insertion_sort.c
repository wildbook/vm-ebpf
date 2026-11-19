/*
 * Insertion sort of small batches of (priority, id) records by priority, keeping equal priorities in arrival order,
 * as a scheduler or an event queue sorts a few dozen entries.
 */
#include "corpus.h"

#define COUNT 96

struct entry {
    u32 priority;
    u32 id;
};

static struct entry entries[COUNT];

static void sort(struct entry *a, u32 n) {
    for (u32 i = 1; i < n; i++) {
        struct entry e = a[i];
        u32 j = i;
        while (j > 0 && a[j - 1].priority > e.priority) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = e;
    }
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), acc = 0;
    for (u32 batch = 0; batch < 2; batch++) {
        for (u32 i = 0; i < COUNT; i++) {
            entries[i].priority = rng_next(&rng) % 1000;
            entries[i].id = i;
        }
        sort(entries, COUNT);
        for (u32 i = 0; i < COUNT; i++)
            acc = acc * 31 + (entries[i].priority ^ entries[i].id << 10);
        for (u32 i = 1; i < COUNT; i++)
            if (entries[i - 1].priority > entries[i].priority)
                return ~0ULL;
    }
    return acc;
}
