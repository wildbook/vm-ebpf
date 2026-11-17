/*
 * Game rules plugin for lib/rvm/examples/modding.rs: spawns monster waves and
 * keeps the score. The host swaps in version 2 mid-game, which adds orcs and a
 * troll; the RULES_V2 build is version 2.
 */
#include "game_sdk.h"

#define WAVE_EVERY 4

struct wave_state {
    u64 wave;
    u64 spawned;
};

/* Shared by the host, so the wave count survives a reload. */
struct {
    __uint(type, 2 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct wave_state);
} waves SEC(".maps");

static const u64 points[] = {[GOBLIN] = 10, [ORC] = 25, [TROLL] = 100};

static noinline u64 spawn_line(u64 kind, u64 count, u64 wave) {
    u64 spawned = 0;
    for (u64 i = 0; i < count; i++)
        spawned += spawn(kind, 9 + 2 * i, (wave + i) % 5) != 0;
    return spawned;
}

static noinline void log_wave(u64 wave, u64 spawned) {
    struct line l = {0};
#ifdef RULES_V2
    put_str(&l, "rules v2: wave ");
#else
    put_str(&l, "rules: wave ");
#endif
    put_u64(&l, wave);
    put_str(&l, ", ");
    put_u64(&l, spawned);
    put_str(&l, " monsters");
    print(l.text, l.len);
}

/* Called by the host every tick; returns the number of monsters spawned. */
u64 on_tick(u64 tick) {
    u32 key = 0;
    struct wave_state *state = bpf_map_lookup_elem(&waves, &key);
    if (!state || tick % WAVE_EVERY)
        return 0;

    u64 wave = ++state->wave;
    u64 spawned = spawn_line(GOBLIN, wave < 3 ? wave : 3, wave);
#ifdef RULES_V2
    spawned += spawn_line(ORC, 1, wave + 2);
    if (wave % 3 == 0)
        spawned += spawn_line(TROLL, 1, wave + 4);
#endif
    log_wave(wave, spawned);
    state->spawned += spawned;
    return spawned;
}

/* Exported to other plugins: credit each kill to its hero and return the points awarded. */
u64 record_kills(const struct kill *kills BORROW_RO(1), u64 len) {
    u64 total = 0;
    for (u64 i = 0; i < len / sizeof(*kills); i++) {
        u32 hero = kills[i].hero;
        u32 kind = kills[i].victim_kind;
        u64 award = kind < sizeof(points) / sizeof(points[0]) ? points[kind] : 0;

        struct score *score = bpf_map_lookup_elem(&scores, &hero);
        if (!score) {
            struct score fresh = {0};
            bpf_map_update_elem(&scores, &hero, &fresh, 0);
            score = bpf_map_lookup_elem(&scores, &hero);
            if (!score)
                continue;
        }
        score->points += award;
        score->kills++;
        total += award;
    }
    return total;
}
