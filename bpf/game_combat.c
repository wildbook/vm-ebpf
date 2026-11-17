/*
 * Combat plugin for lib/rvm/examples/modding.rs: moves monsters toward the
 * heroes, resolves attacks through the host's `damage`, and hands the tick's
 * kills to the rules plugin in one borrowed buffer.
 * Build: clang -target bpf -mcpu=v4 -O2 -g -c bpf/game_combat.c -o bpf/game_combat.o
 */
#include "game_sdk.h"

/* Exported by the rules plugin. */
extern u64 record_kills(const struct kill *kills, u64 len);

#define MAX_KILLS 16
#define VETERAN_KILLS 5

static noinline u64 distance(struct entity *a, struct entity *b) {
    s32 dx = a->x - b->x;
    s32 dy = a->y - b->y;
    dx = dx < 0 ? -dx : dx;
    dy = dy < 0 ? -dy : dy;
    return dx > dy ? dx : dy;
}

/* The nearest living entity on the other side from `self`, or NULL. */
static noinline struct entity *nearest_foe(struct entity *ents, u64 n, struct entity *self) {
    int hero = self->kind == HERO;
    struct entity *best = 0;
    u64 best_distance = ~0ULL;
    for (u64 i = 0; i < n; i++) {
        struct entity *e = entity_at(ents, i);
        if (e->hp <= 0 || (e->kind == HERO) == hero)
            continue;
        u64 d = distance(self, e);
        if (d < best_distance) {
            best = e;
            best_distance = d;
        }
    }
    return best;
}

static noinline void step_toward(struct entity *self, struct entity *target) {
    if (self->x != target->x)
        self->x += self->x < target->x ? 1 : -1;
    else if (self->y != target->y)
        self->y += self->y < target->y ? 1 : -1;
}

/* Heroes with enough kills, as the rules plugin counts them, hit harder. */
static noinline s32 attack_of(struct entity *e) {
    s32 attack = e->attack;
    if (e->kind == HERO) {
        u32 id = e->id;
        struct score *score = bpf_map_lookup_elem(&scores, &id);
        if (score && score->kills >= VETERAN_KILLS)
            attack += 2;
    }
    return attack;
}

/* Logs "<kind> <id> killed <kind> <id>". */
static noinline void log_kill(struct entity *killer, struct entity *victim) {
    struct line l = {0};
    put_str(&l, "combat: ");
    put_str(&l, kind_name(killer->kind));
    put_str(&l, " ");
    put_u64(&l, killer->id);
    put_str(&l, " killed ");
    put_str(&l, kind_name(victim->kind));
    put_str(&l, " ");
    put_u64(&l, victim->id);
    print(l.text, l.len);
}

/* Called by the host every tick with its entity array; returns the number of kills by heroes. */
u64 on_tick(struct entity *ents, u64 n) {
    struct kill kills[MAX_KILLS];
    u64 nkills = 0;

    for (u64 i = 0; i < n; i++) {
        struct entity *self = entity_at(ents, i);
        if (self->hp <= 0)
            continue;
        struct entity *foe = nearest_foe(ents, n, self);
        if (!foe)
            continue;

        u64 reach = self->kind == HERO ? 2 : 1;
        if (distance(self, foe) > reach) {
            if (self->kind != HERO)
                step_toward(self, foe);
            continue;
        }

        s32 hit = attack_of(self) - armor_of(foe);
        if (damage(foe->id, hit > 1 ? hit : 1) != 0)
            continue;
        log_kill(self, foe);
        if (self->kind == HERO && nkills < MAX_KILLS)
            kills[nkills++] = (struct kill){.hero = self->id, .victim_kind = foe->kind};
    }

    if (nkills)
        record_kills(kills, nkills * sizeof(kills[0]));
    return nkills;
}
