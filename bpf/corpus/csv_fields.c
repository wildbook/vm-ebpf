/*
 * CSV with RFC 4180 quoting: formats rows of a name, a quantity and a price in cents, quoting names that hold a comma or
 * a quote, then splits the text back into fields and totals the columns.
 */
#include "corpus.h"

#define ROWS 48

static const char *const names[] = {"bolt", "nut, hex", "washer", "say \"hi\"", "pin", "gear"};
static u8 text[ROWS * 40];

static u32 put_u32(u8 *out, u32 v) {
    u8 digits[10];
    u32 n = 0;
    do {
        digits[n++] = '0' + v % 10;
        v /= 10;
    } while (v);
    for (u32 i = 0; i < n; i++)
        out[i] = digits[n - 1 - i];
    return n;
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    u32 len = 0;
    for (u32 row = 0; row < ROWS; row++) {
        const char *name = names[rng_next(&rng) % 6];
        u32 quote = 0;
        for (const char *p = name; *p; p++)
            quote |= *p == ',' || *p == '"';
        if (quote)
            text[len++] = '"';
        for (const char *p = name; *p; p++) {
            if (*p == '"')
                text[len++] = '"';
            text[len++] = *p;
        }
        if (quote)
            text[len++] = '"';
        text[len++] = ',';
        len += put_u32(text + len, rng_next(&rng) % 1000);
        text[len++] = ',';
        len += put_u32(text + len, rng_next(&rng) % 100000);
        text[len++] = '\n';
    }

    u64 name_hash = 0, field_hash = 0, total_qty = 0, total_cents = 0;
    u32 field = 0, quoted = 0, value = 0, qty = 0;
    for (u32 i = 0; i < len; i++) {
        u8 c = text[i];
        if (quoted) {
            if (c != '"')
                field_hash = field_hash * 31 + c;
            else if (i + 1 < len && text[i + 1] == '"')
                field_hash = field_hash * 31 + text[++i];
            else
                quoted = 0;
        } else if (c == '"') {
            quoted = 1;
        } else if (c == ',' || c == '\n') {
            if (field == 0)
                name_hash = name_hash * 0x100000001b3ULL ^ field_hash;
            else if (field == 1)
                total_qty += qty = value;
            else
                total_cents += (u64)value * qty;
            field = c == ',' ? field + 1 : 0;
            field_hash = 0;
            value = 0;
        } else if (field == 0) {
            field_hash = field_hash * 31 + c;
        } else {
            value = value * 10 + (c - '0');
        }
    }
    return name_hash ^ total_qty << 40 ^ total_cents;
}
