/*
 * An INI parser driven by a switch on sparse character values and a switch over four states, small enough that clang
 * lowers both to compare chains. It counts sections, keys and comments and hashes keys and values.
 */
#include "corpus.h"

enum state { LINE = 3, SECTION = 17, KEY = 40, VALUE = 99 };

static const char *const lines[] = {"[server]\n", "port = 8080\n", "; listen on all\n", "host=0.0.0.0\n",
                                    "# tuning\n", "[limits]\n", "rate = 250 \n", "  burst=  40\n", "bad line\n"};
static u8 text[2048];

u64 run(u64 seed) {
    u64 rng = rng_seed(seed);
    u32 len = 0;
    for (u32 l = 0; l < 96; l++)
        for (const char *p = lines[rng_next(&rng) % 9]; *p; p++)
            text[len++] = *p;

    enum state s = LINE;
    u64 sections = 0, keys = 0, comments = 0, errors = 0, hash = 0, token = 0;
    for (u32 i = 0; i < len; i++) {
        u8 c = text[i];
        switch (s) {
        case LINE:
            switch (c) {
            case ' ': case '\t': case '\n': break;
            case '[': s = SECTION; token = 0; break;
            case ';': case '#': comments++; s = VALUE; token = 0; break;
            case '=': case ']': errors++; break;
            default: s = KEY; token = c; break;
            }
            break;
        case SECTION:
            if (c == ']') {
                sections++;
                hash = hash * 31 + token;
                s = VALUE;
            } else if (c == '\n') {
                errors++;
                s = LINE;
            } else {
                token = token * 31 + c;
            }
            break;
        case KEY:
            if (c == '=') {
                keys++;
                hash ^= token;
                token = 0;
                s = VALUE;
            } else if (c == '\n') {
                errors++;
                s = LINE;
            } else if (c != ' ') {
                token = token * 31 + c;
            }
            break;
        case VALUE:
            if (c == '\n') {
                hash = hash * 0x100000001b3ULL + token;
                token = 0;
                s = LINE;
            } else if (c != ' ') {
                token = token * 33 + c;
            }
            break;
        }
    }
    return hash ^ sections << 56 ^ keys << 48 ^ comments << 40 ^ errors << 32;
}
