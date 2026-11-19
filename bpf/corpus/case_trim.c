/*
 * Request-line handling: trims spaces and tabs around each line, folds ASCII case, and matches the first word against
 * a list of HTTP methods without regard to case.
 */
#include "corpus.h"

#define LINES 64
#define WIDTH 24

static const char *const methods[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "GOT"};
static u8 lines[LINES][WIDTH];

static u8 fold(u8 c) {
    return c >= 'A' && c <= 'Z' ? c | 0x20 : c;
}

static int equal_fold(const u8 *s, u32 n, const char *word) {
    u32 i = 0;
    for (; i < n; i++)
        if (!word[i] || fold(s[i]) != fold(word[i]))
            return 0;
    return !word[i];
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), hash = 0;
    u32 hist[7] = {0};
    for (u32 l = 0; l < LINES; l++) {
        u64 r = rng_next(&rng);
        u8 *line = lines[l];
        u32 n = 0;
        for (u32 s = r & 3; s; s--)
            line[n++] = s & 1 ? ' ' : '\t';
        for (const char *m = methods[r >> 2 & 7]; *m; m++, r >>= 1)
            line[n++] = *m ^ (r >> 8 & 1 ? 0x20 : 0);
        line[n++] = ' ';
        line[n++] = '/';
        for (u32 s = r >> 40 & 3; s; s--)
            line[n++] = ' ';
        line[n] = 0;
    }

    for (u32 l = 0; l < LINES; l++) {
        const u8 *line = lines[l];
        u32 start = 0, end = 0, word = 0;
        while (line[end])
            end++;
        while (start < end && (line[start] == ' ' || line[start] == '\t'))
            start++;
        while (end > start && (line[end - 1] == ' ' || line[end - 1] == '\t'))
            end--;
        while (start + word < end && line[start + word] != ' ')
            word++;
        for (u32 m = 0; m < 7; m++)
            if (equal_fold(line + start, word, methods[m]))
                hist[m]++;
        for (u32 i = start; i < end; i++)
            hash = hash * 31 + fold(line[i]);
    }
    for (u32 m = 0; m < 7; m++)
        hash = hash << 5 ^ hash >> 59 ^ hist[m];
    return hash;
}
