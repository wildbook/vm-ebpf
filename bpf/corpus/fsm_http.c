/*
 * An HTTP/1.1 request head parser in the style of http-parser: a character-at-a-time state machine over a dense state
 * enum, with one state per character of the version, which clang lowers to a jump table. It parses several requests
 * formatted from the seed and checksums methods, paths, versions and headers.
 */
#include "corpus.h"

enum state {
    METHOD, PATH, V_H, V_T1, V_T2, V_P, V_SLASH, V_MAJOR, V_DOT, V_MINOR, V_CR, LINE_LF,
    NAME_START, NAME, VALUE_SPACE, VALUE, VALUE_LF, END_LF, DONE, ERROR,
};

#define EXPECT(ch, next) s = c == (ch) ? (next) : ERROR

static const char *const parts[] = {"GET /index.html HTTP/1.1\r\n", "POST /api/v2/items HTTP/1.1\r\n",
                                    "Host: example.org\r\n", "Content-Length: 1234\r\n", "Accept: */*\r\n",
                                    "X-Trace: 0af7651916cd43dd\r\n", "Connection: keep-alive\r\n"};
static u8 text[1024];

u64 run(u64 seed) {
    u64 rng = rng_seed(seed), hash = 0, headers = 0, errors = 0;
    for (u32 req = 0; req < 8; req++) {
        u64 r = rng_next(&rng);
        u32 len = 0;
        for (u32 h = 0; h < 2 + (r & 7); h++, r >>= 3)
            for (const char *p = parts[h == 0 ? r >> 40 & 1 : 2 + r % 5]; *p; p++)
                text[len++] = *p;
        text[len++] = '\r';
        text[len++] = '\n';

        enum state s = METHOD;
        u64 token = 0, version = 0;
        for (u32 i = 0; i < len && s != DONE && s != ERROR; i++) {
            u8 c = text[i];
            switch (s) {
            case METHOD:
                if (c == ' ') { hash ^= token; token = 0; s = PATH; }
                else if (c >= 'A' && c <= 'Z') token = token * 31 + c;
                else s = ERROR;
                break;
            case PATH:
                if (c == ' ') { hash = hash * 7 + token; token = 0; s = V_H; }
                else token = token * 33 + c;
                break;
            case V_H: EXPECT('H', V_T1); break;
            case V_T1: EXPECT('T', V_T2); break;
            case V_T2: EXPECT('T', V_P); break;
            case V_P: EXPECT('P', V_SLASH); break;
            case V_SLASH: EXPECT('/', V_MAJOR); break;
            case V_MAJOR: version = c - '0'; s = version < 10 ? V_DOT : ERROR; break;
            case V_DOT: EXPECT('.', V_MINOR); break;
            case V_MINOR: version = version * 10 + c - '0'; s = c >= '0' && c <= '9' ? V_CR : ERROR; break;
            case V_CR: EXPECT('\r', LINE_LF); hash ^= version << 32; break;
            case LINE_LF: EXPECT('\n', NAME_START); break;
            case NAME_START:
                if (c == '\r') s = END_LF;
                else { token = c | 0x20; s = NAME; }
                break;
            case NAME: if (c == ':') s = VALUE_SPACE; else token = token * 31 + (c | 0x20); break;
            case VALUE_SPACE: if (c != ' ') { token = token * 31 + c; s = VALUE; } break;
            case VALUE: if (c == '\r') s = VALUE_LF; else token = token * 31 + c; break;
            case VALUE_LF: EXPECT('\n', NAME_START); hash ^= token + headers++; token = 0; break;
            case END_LF: EXPECT('\n', DONE); break;
            default: s = ERROR; break;
            }
        }
        errors += s != DONE;
    }
    return hash ^ headers << 48 ^ errors << 56;
}
