/*
 * Aggregates a stream of MessagePack log events into per-service stats, for
 * lib/rvm/examples/msgpack_logs.rs. An event is a map such as
 *   {"svc": "api", "lvl": "warn", "ms": 120, "bytes": 5120}
 * Other keys, and records that aren't maps, are skipped whatever they hold.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/examples/msgpack_logs.c -o bpf/examples/msgpack_logs.o
 */
typedef unsigned char u8;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define noinline __attribute__((noinline))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;

#define NAME_LEN 16
#define MAX_SERVICES 16

enum level { DEBUG, INFO, WARN, ERROR, LEVELS };

struct svc_stats {
    char name[NAME_LEN];
    u64 events;
    u64 by_level[LEVELS];
    u64 ms_total;
    u64 ms_max;
    u64 bytes;
};

struct totals {
    u64 events;
    u64 services;
    u64 skipped_fields;
    u64 other_records;
};

/* Service name to its index in `services`, in order of first appearance. */
struct {
    __uint(type, 1 /* BPF_MAP_TYPE_HASH */);
    __uint(max_entries, MAX_SERVICES);
    __type(key, char[NAME_LEN]);
    __type(value, u32);
} svc_ids SEC(".maps");

struct {
    __uint(type, 2 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, MAX_SERVICES);
    __type(key, u32);
    __type(value, struct svc_stats);
} services SEC(".maps");

struct {
    __uint(type, 2 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct totals);
} totals SEC(".maps");

/* Error codes; 0 is success. */
#define INCOMPLETE 1 /* the input ends inside a value */
#define NOT_EVENT 2  /* a complete record that isn't an event */

struct cursor {
    const u8 *p;
    const u8 *end;
};

/*
 * A decoded value. Arrays and maps are decoded as their header only; strings,
 * binaries and extension payloads point into the input.
 */
enum vtype { V_NIL, V_BOOL, V_INT, V_FLOAT, V_STR, V_BIN, V_EXT, V_ARRAY, V_MAP, V_INVALID };

struct value {
    u32 type;
    u32 len;
    u64 num;
    const u8 *data;
};

struct event {
    char svc[NAME_LEN];
    u32 level;
    u64 ms;
    u64 bytes;
    u64 skipped;
};

/* Reads an `n` byte big-endian unsigned integer, `n` at most 8. */
static inline int take_be(struct cursor *c, u32 n, u64 *out) {
    if (c->end - c->p < n)
        return INCOMPLETE;
    u64 x = 0;
    for (u32 i = 0; i < n; i++)
        x = x << 8 | c->p[i];
    c->p += n;
    *out = x;
    return 0;
}

static inline int take_signed(struct cursor *c, u32 n, struct value *v) {
    v->type = V_INT;
    int err = take_be(c, n, &v->num);
    if (!err && n < 8)
        v->num = (u64)((s64)(v->num << (64 - 8 * n)) >> (64 - 8 * n));
    return err;
}

/* Points `v` at the next `len` bytes and skips them. */
static inline int take_bytes(struct cursor *c, u64 len, struct value *v) {
    if (c->end - c->p < len)
        return INCOMPLETE;
    v->data = c->p;
    v->len = len;
    c->p += len;
    return 0;
}

/* A length field of `width` bytes, then that many bytes of payload. */
static inline int take_sized(struct cursor *c, u32 width, u32 type, struct value *v) {
    u64 len;
    v->type = type;
    return take_be(c, width, &len) ?: take_bytes(c, len, v);
}

/* An extension: a length field of `width` bytes, a type byte, then the payload. */
static inline int take_ext(struct cursor *c, u32 width, struct value *v) {
    u64 len;
    v->type = V_EXT;
    return take_be(c, width, &len) ?: take_be(c, 1, &v->num) ?: take_bytes(c, len, v);
}

static inline int take_fixext(struct cursor *c, u32 len, struct value *v) {
    v->type = V_EXT;
    return take_be(c, 1, &v->num) ?: take_bytes(c, len, v);
}

static inline int take_header(struct cursor *c, u32 width, u32 type, struct value *v) {
    u64 len;
    v->type = type;
    int err = take_be(c, width, &len);
    v->len = len;
    return err;
}

/* Decodes the value at the cursor; the tags from 0xc0 to 0xdf compile to a jump table. */
static noinline int read_value(struct cursor *c, struct value *v) {
    if (c->p >= c->end)
        return INCOMPLETE;
    u8 tag = *c->p++;

    if (tag <= 0x7f) {
        v->type = V_INT;
        v->num = tag;
        return 0;
    }
    if (tag <= 0x8f) {
        v->type = V_MAP;
        v->len = tag & 0x0f;
        return 0;
    }
    if (tag <= 0x9f) {
        v->type = V_ARRAY;
        v->len = tag & 0x0f;
        return 0;
    }
    if (tag <= 0xbf) {
        v->type = V_STR;
        return take_bytes(c, tag & 0x1f, v);
    }
    if (tag >= 0xe0) {
        v->type = V_INT;
        v->num = (u64)(s64)(s8)tag;
        return 0;
    }

    switch (tag) {
    case 0xc0: v->type = V_NIL; return 0;
    case 0xc2: v->type = V_BOOL; v->num = 0; return 0;
    case 0xc3: v->type = V_BOOL; v->num = 1; return 0;
    case 0xc4: return take_sized(c, 1, V_BIN, v);
    case 0xc5: return take_sized(c, 2, V_BIN, v);
    case 0xc6: return take_sized(c, 4, V_BIN, v);
    case 0xc7: return take_ext(c, 1, v);
    case 0xc8: return take_ext(c, 2, v);
    case 0xc9: return take_ext(c, 4, v);
    case 0xca: v->type = V_FLOAT; return take_be(c, 4, &v->num);
    case 0xcb: v->type = V_FLOAT; return take_be(c, 8, &v->num);
    case 0xcc: v->type = V_INT; return take_be(c, 1, &v->num);
    case 0xcd: v->type = V_INT; return take_be(c, 2, &v->num);
    case 0xce: v->type = V_INT; return take_be(c, 4, &v->num);
    case 0xcf: v->type = V_INT; return take_be(c, 8, &v->num);
    case 0xd0: return take_signed(c, 1, v);
    case 0xd1: return take_signed(c, 2, v);
    case 0xd2: return take_signed(c, 4, v);
    case 0xd3: return take_signed(c, 8, v);
    case 0xd4: return take_fixext(c, 1, v);
    case 0xd5: return take_fixext(c, 2, v);
    case 0xd6: return take_fixext(c, 4, v);
    case 0xd7: return take_fixext(c, 8, v);
    case 0xd8: return take_fixext(c, 16, v);
    case 0xd9: return take_sized(c, 1, V_STR, v);
    case 0xda: return take_sized(c, 2, V_STR, v);
    case 0xdb: return take_sized(c, 4, V_STR, v);
    case 0xdc: return take_header(c, 2, V_ARRAY, v);
    case 0xdd: return take_header(c, 4, V_ARRAY, v);
    case 0xde: return take_header(c, 2, V_MAP, v);
    case 0xdf: return take_header(c, 4, V_MAP, v);
    }
    v->type = V_INVALID; /* 0xc1 is reserved */
    return 0;
}

/* Skips the elements of a container `v` just read, however deeply they nest. */
static noinline int skip_contents(struct cursor *c, const struct value *v) {
    u64 pending = v->type == V_MAP ? 2 * (u64)v->len : v->type == V_ARRAY ? v->len : 0;
    while (pending) {
        struct value inner;
        int err = read_value(c, &inner);
        if (err)
            return err;
        pending--;
        if (inner.type == V_MAP)
            pending += 2 * (u64)inner.len;
        else if (inner.type == V_ARRAY)
            pending += inner.len;
    }
    return 0;
}

static int str_eq(const struct value *v, const char *s) {
    for (u32 i = 0; i < v->len; i++)
        if (!s[i] || v->data[i] != s[i])
            return 0;
    return !s[v->len];
}

/* Field handlers return 1 if they took the value, 0 to skip it. */
typedef int (*field_fn)(struct event *ev, const struct value *v);

static int on_svc(struct event *ev, const struct value *v) {
    if (v->type != V_STR || v->len == 0 || v->len >= NAME_LEN)
        return 0;
    for (u32 i = 0; i < v->len; i++)
        ev->svc[i] = v->data[i];
    return 1;
}

static const char level_names[LEVELS][8] = {"debug", "info", "warn", "error"};

static int on_lvl(struct event *ev, const struct value *v) {
    if (v->type != V_STR)
        return 0;
    for (u32 i = 0; i < LEVELS; i++) {
        if (str_eq(v, level_names[i])) {
            ev->level = i;
            return 1;
        }
    }
    return 0;
}

static int on_ms(struct event *ev, const struct value *v) {
    if (v->type != V_INT)
        return 0;
    ev->ms = v->num;
    return 1;
}

static int on_bytes(struct event *ev, const struct value *v) {
    if (v->type != V_INT)
        return 0;
    ev->bytes = v->num;
    return 1;
}

static const struct field {
    char name[8];
    field_fn handle;
} fields[] = {
    {"svc", on_svc},
    {"lvl", on_lvl},
    {"ms", on_ms},
    {"bytes", on_bytes},
};

static noinline const struct field *find_field(const struct value *key) {
    if (key->type != V_STR)
        return 0;
    for (u32 i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (str_eq(key, fields[i].name))
            return &fields[i];
    return 0;
}

/* Decodes one record into `ev`. An event is a map with at least a service name. */
static noinline int parse_event(struct cursor *c, struct event *ev) {
    struct value record;
    int err = read_value(c, &record);
    if (err)
        return err;
    if (record.type != V_MAP)
        return skip_contents(c, &record) ?: NOT_EVENT;

    for (u32 i = 0; i < record.len; i++) {
        struct value key, val;
        err = read_value(c, &key) ?: skip_contents(c, &key) ?: read_value(c, &val);
        if (err)
            return err;
        const struct field *field = find_field(&key);
        if (field && field->handle(ev, &val))
            continue;
        err = skip_contents(c, &val);
        if (err)
            return err;
        ev->skipped++;
    }
    return ev->svc[0] ? 0 : NOT_EVENT;
}

/* The stats slot for service `name`, added on first sight; NULL once all slots are taken. */
static noinline struct svc_stats *service(const char *name, struct totals *t) {
    u32 *id = bpf_map_lookup_elem(&svc_ids, name);
    if (id)
        return bpf_map_lookup_elem(&services, id);

    u32 next = t->services;
    if (next >= MAX_SERVICES || bpf_map_update_elem(&svc_ids, name, &next, 1 /* BPF_NOEXIST */))
        return 0;
    struct svc_stats *s = bpf_map_lookup_elem(&services, &next);
    if (!s)
        return 0;
    for (u32 i = 0; i < NAME_LEN; i++)
        s->name[i] = name[i];
    t->services++;
    return s;
}

/*
 * Aggregates the complete records at the start of `buf` and returns how many
 * bytes they took. The host passes the rest again with the next chunk.
 */
u64 parse(const u8 *buf, u64 len) {
    u32 zero = 0;
    struct totals *t = bpf_map_lookup_elem(&totals, &zero);
    if (!t)
        return 0;

    struct cursor c = {buf, buf + len};
    const u8 *done = buf;
    while (c.p < c.end) {
        struct event ev = {.level = INFO};
        int err = parse_event(&c, &ev);
        if (err == INCOMPLETE)
            break;
        done = c.p;
        t->skipped_fields += ev.skipped;
        if (err == NOT_EVENT) {
            t->other_records++;
            continue;
        }

        struct svc_stats *s = service(ev.svc, t);
        if (!s)
            continue;
        s->events++;
        s->by_level[ev.level]++;
        s->ms_total += ev.ms;
        s->ms_max = ev.ms > s->ms_max ? ev.ms : s->ms_max;
        s->bytes += ev.bytes;
        t->events++;
    }
    return done - buf;
}
