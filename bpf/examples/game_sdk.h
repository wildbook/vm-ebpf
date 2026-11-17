/*
 * Modding SDK for the game host in lib/rvm/examples/modding.rs: the types, host
 * functions and shared maps that plugins see.
 */
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define noinline __attribute__((noinline))

/* The callee reads the caller's buffer in place for one call; `len_arg` holds its size. */
#define BORROW_RO(len_arg) __attribute__((btf_decl_tag("borrow_ro:" #len_arg)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;

enum kind { HERO, GOBLIN, ORC, TROLL };

/*
 * The host's entity as this SDK version knew it. The host may reorder, resize
 * or drop fields; CO-RE patches each access at load time, so plugins built
 * against an older SDK keep working.
 */
struct entity {
    u32 id;
    u32 kind;
    s32 x;
    s32 y;
    s32 hp;
    s32 attack;
    s32 armor;
} __attribute__((preserve_access_index));

/* The host's array stride is its struct size, which may differ from ours. */
static inline struct entity *entity_at(struct entity *ents, u64 i) {
    u64 size = __builtin_preserve_type_info(*(struct entity *)0, 1 /* BPF_TYPE_SIZE */);
    return (struct entity *)((char *)ents + i * size);
}

static inline s32 armor_of(struct entity *e) {
    if (!__builtin_preserve_field_info(e->armor, 2 /* BPF_FIELD_EXISTS */))
        return 0;
    return e->armor;
}

/* A char table, not a switch: clang can't emit a lookup table of string pointers for BPF. */
static const char kind_names[][8] = {"hero", "goblin", "orc", "troll"};

static inline const char *kind_name(u32 kind) {
    return kind < sizeof(kind_names) / sizeof(kind_names[0]) ? kind_names[kind] : "?";
}

/* Host functions. */
extern u64 spawn(u64 kind, u64 x, u64 y); /* new entity's id, 0 if the world is full */
extern u64 damage(u64 id, u64 amount);   /* hit points left */
extern void print(const char *msg, u64 len); /* one line to the game log */

/* A log line for `print`, which takes bytes rather than a format string. */
struct line {
    u64 len;
    char text[64];
};

static inline void put_str(struct line *l, const char *s) {
    for (; *s && l->len < sizeof(l->text); s++)
        l->text[l->len++] = *s;
}

static inline void put_u64(struct line *l, u64 v) {
    char digits[20];
    u64 n = 0;
    do {
        digits[n++] = '0' + v % 10;
        v /= 10;
    } while (v);
    while (n && l->len < sizeof(l->text))
        l->text[l->len++] = digits[--n];
}

/* A kill, passed from combat to rules in bulk. */
struct kill {
    u32 hero;
    u32 victim_kind;
};

struct score {
    u64 points;
    u64 kills;
};

/* Points and kills per hero id. The host shares this map between all plugins. */
struct {
    __uint(type, 1 /* BPF_MAP_TYPE_HASH */);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, struct score);
} scores SEC(".maps");
