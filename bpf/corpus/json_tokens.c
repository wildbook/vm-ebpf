/*
 * A JSON tokenizer of the kind a config or event plugin carries: punctuation, strings with escapes, numbers with sign,
 * fraction and exponent, and bare words for true, false and null. The seed rewrites the digits of the document.
 */
#include "corpus.h"

static const char doc[] =
    "{\"id\": 4711, \"name\": \"sensor \\\"north\\\"\", \"tags\": [\"a\", \"bc\", \"def\"],\n"
    " \"active\": true, \"parent\": null, \"ratio\": -0.125, \"limits\": {\"lo\": -40, \"hi\": 125},\n"
    " \"samples\": [12, 15, 19, 23, 18, 1.5e3, -7, 0, 99, 1024], \"note\": \"tab\\there\", \"ok\": false}\n";

static u8 text[sizeof(doc)];

enum { PUNCT, STRING, NUMBER, WORD, ERROR, KINDS };

static int is_digit(u8 c) {
    return c >= '0' && c <= '9';
}

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), hash = 0;
    u32 counts[KINDS] = {0};
    for (u32 pass = 0; pass < 8; pass++) {
        for (u32 i = 0; i < sizeof(doc); i++) {
            u8 c = doc[i];
            text[i] = is_digit(c) ? '0' + rng_next(&rng) % 10 : c;
        }

        u32 pos = 0;
        while (text[pos]) {
            u8 c = text[pos];
            u64 value = 0;
            u32 kind;
            if (c == ' ' || c == '\n' || c == '\t' || c == '\r') {
                pos++;
                continue;
            } else if (c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',') {
                kind = PUNCT;
                value = c;
                pos++;
            } else if (c == '"') {
                kind = STRING;
                for (pos++; text[pos] && text[pos] != '"'; pos++) {
                    if (text[pos] == '\\' && text[pos + 1])
                        pos++;
                    value = value * 31 + text[pos];
                }
                if (text[pos])
                    pos++;
            } else if (c == '-' || is_digit(c)) {
                kind = NUMBER;
                u64 negative = c == '-', scale = 0, exp = 0;
                pos += negative;
                for (; is_digit(text[pos]); pos++)
                    value = value * 10 + (text[pos] - '0');
                if (text[pos] == '.')
                    for (pos++; is_digit(text[pos]); pos++, scale++)
                        value = value * 10 + (text[pos] - '0');
                if (text[pos] == 'e' || text[pos] == 'E') {
                    pos++;
                    if (text[pos] == '+' || text[pos] == '-')
                        pos++;
                    for (; is_digit(text[pos]); pos++)
                        exp = exp * 10 + (text[pos] - '0');
                }
                value = (negative ? -value : value) ^ scale << 48 ^ exp << 56;
            } else if (c >= 'a' && c <= 'z') {
                kind = WORD;
                for (; text[pos] >= 'a' && text[pos] <= 'z'; pos++)
                    value = value * 31 + text[pos];
            } else {
                kind = ERROR;
                pos++;
            }
            counts[kind]++;
            hash = (hash ^ value ^ kind) * 0x100000001b3ULL;
        }
    }
    return hash ^ (u64)counts[STRING] << 32 ^ counts[NUMBER] << 16 ^ counts[PUNCT] ^ counts[WORD] << 8;
}
