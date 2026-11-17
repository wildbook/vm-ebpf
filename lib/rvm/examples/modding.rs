//! A game that runs its mods as rvm plugins.
//!
//! - `bpf/examples/game_rules.c` spawns monster waves through the host function `spawn` and exports `record_kills`,
//!   which keeps each hero's score in a map.
//! - `bpf/examples/game_combat.c` moves monsters, attacks through the host function `damage`, and passes each tick's
//!   kills to `record_kills` in one buffer that the rules plugin borrows for the call.
//!
//! Both log through the host function `print`, which reads the line from the calling plugin's memory. The entities live
//! in a region that the host shares with every plugin and reads and writes field by field. The host describes its
//! `Entity` layout with `host_struct!`, and CO-RE patches the plugins' field offsets and array stride to match it:
//! `bpf/examples/game_sdk.h` declares the struct with other field order and size. `scores` and the rules plugin's
//! `waves` are maps that the VM shares, so they belong to the VM and keep their contents when the host replaces the
//! rules with `game_rules_v2.o` halfway through. The host links the combat plugin ahead of time into an image and loads
//! it from bytes, and calls both plugins every tick through function handles it looks up once; the rules handle follows
//! the reload.
//!
//! Rebuild the plugins with the CMake project in the repo root.
//!
//! Run with: cargo run -p rvm --example modding

use std::error::Error;
use std::mem::{offset_of, size_of};
use std::sync::{Arc, Mutex, MutexGuard};

use rvm::{MapError, MemoryError, Perms, Plugin, Scalar, SharedRegion, Vm};

const RULES: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/examples/game_rules.o"));
const RULES_V2: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/examples/game_rules_v2.o"));
const COMBAT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/examples/game_combat.o"));

const TICKS: u32 = 32;
const RELOAD_AT: u32 = 12;
const CAPACITY: usize = 64;

// `enum kind` in game_sdk.h
const HERO: u32 = 0;
const GOBLIN: u32 = 1;
const ORC: u32 = 2;
const TROLL: u32 = 3;

const HEROES: [(&str, Stats); 2] = [
    (
        "knight",
        Stats {
            hp: 150,
            attack: 12,
            armor: 3,
        },
    ),
    (
        "archer",
        Stats {
            hp: 90,
            attack: 7,
            armor: 1,
        },
    ),
];

fn main() -> Result<(), Box<dyn Error>> {
    let vm = Vm::new();
    // CO-RE patches the plugins' accesses to `struct entity` to match `Entity`
    rvm::host_struct!(vm.types(), Entity as "entity" { id, hp, armor, kind, x, y, attack });
    // SAFETY: plugins only run on this thread.
    unsafe {
        vm.share_map("scores", false);
        vm.share_map("waves", false);
    }

    let world = Arc::new(World::new(&vm)?);
    register_host_fns(&vm, &world);
    for (i, (_, stats)) in HEROES.iter().enumerate() {
        world.spawn(HERO, 0, 1 + 2 * i as i32, *stats);
    }

    let rules = vm.load_plugin("rules", RULES)?;
    vm.export(&rules, "record_kills")?;
    // A game would prepare the image when it installs the mod; this links the plugin against the host's externs and
    // entity layout.
    let combat_image = vm.prepare(COMBAT)?.to_bytes();
    let combat = vm.load_plugin_image("combat", &combat_image)?;

    run(&vm, &world, &rules, &combat)?;
    print_summary(&world, &rules)
}

fn register_host_fns(vm: &Vm, world: &Arc<World>) {
    let w = world.clone();
    vm.register_fn("spawn", move |(kind, x, y): (u64, u64, u64)| {
        let stats = match kind as u32 {
            GOBLIN => Stats {
                hp: 12,
                attack: 3,
                armor: 0,
            },
            ORC => Stats {
                hp: 30,
                attack: 6,
                armor: 2,
            },
            TROLL => Stats {
                hp: 80,
                attack: 10,
                armor: 4,
            },
            _ => return 0,
        };
        w.spawn(kind as u32, x as i32, y as i32, stats)
    });

    let w = world.clone();
    vm.register_fn("damage", move |(id, amount): (u64, u64)| w.damage(id as u32, amount as i32));

    let w = world.clone();
    vm.register_fn_with_memory("print", move |mem, (msg, len): (u64, u64)| {
        let line = mem.read_vec(msg, len as usize)?;
        println!("tick {:>2}  {}", w.tick(), String::from_utf8_lossy(&line));
        Ok::<_, MemoryError>(())
    });
}

/// Runs the game, swapping in the second version of the rules at `RELOAD_AT`.
fn run(vm: &Vm, world: &World, rules: &Plugin, combat: &Plugin) -> rvm::Result<()> {
    // a named function follows the rules into the program that replaces them
    let rules_tick = rules.named_func("on_tick")?;
    let combat_tick = combat.func("on_tick")?;

    for tick in 0..TICKS {
        world.set_tick(tick);
        if tick == RELOAD_AT {
            rules.replace(vm.load_elf(RULES_V2)?)?;
            println!("tick {tick:>2}  host: reloaded rules");
        }

        rules_tick.call(&[tick.into()])?;
        combat.call_func(combat_tick, &[world.base(), world.len() as u64])?;
        world.remove_dead();
    }
    Ok(())
}

fn print_summary(world: &World, rules: &Plugin) -> Result<(), Box<dyn Error>> {
    let mut rules = rules.lock()?;
    let alive = world.entities();

    // `struct wave_state` and `struct score` are two `u64`s each
    let waves = rules.map("waves").ok_or("rules has no waves map")?;
    let [wave, spawned]: [u64; 2] = waves.get_as(0u32)?;
    let monsters: Vec<_> = alive.iter().filter(|e| e.kind != HERO).collect();
    let oldest = monsters.iter().map(|e| e.spawned_at).min().unwrap_or(TICKS);
    let left = monsters.len();
    println!("{wave} waves, {spawned} monsters spawned, {left} left (oldest from tick {oldest})");

    let scores = rules.map("scores").ok_or("rules has no scores map")?;
    for (i, (name, _)) in HEROES.iter().enumerate() {
        let id = i as u32 + 1;
        let hp = alive.iter().find(|e| e.id == id).map_or(0, |e| e.hp);
        let [points, kills]: [u64; 2] = match scores.get_as(id) {
            Err(MapError::NotFound) => [0, 0],
            score => score?,
        };
        println!("{name}: {hp} hp, {points} points, {kills} kills");
    }
    Ok(())
}

/// The host's entity. Its field order and size differ from `struct entity` in `bpf/examples/game_sdk.h`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Entity {
    id: u32,
    hp: i32,
    armor: i32,
    kind: u32,
    x: i32,
    y: i32,
    attack: i32,
    spawned_at: u32,
}

#[derive(Clone, Copy)]
struct Stats {
    hp: i32,
    attack: i32,
    armor: i32,
}

/// Entities in a region shared with every plugin, as an array the host appends to and compacts.
struct World {
    base: u64,
    state: Mutex<WorldState>,
}

struct WorldState {
    region: SharedRegion,
    len: usize,
    next_id: u32,
    tick: u32,
}

impl World {
    fn new(vm: &Vm) -> rvm::Result<Self> {
        // SAFETY: plugins only run on this thread.
        let region = unsafe { vm.share_region(rvm::FIRST_FREE_REGION, CAPACITY * size_of::<Entity>(), Perms::RW)? };
        Ok(Self {
            base: region.base(),
            state: Mutex::new(WorldState {
                region,
                len: 0,
                next_id: 0,
                tick: 0,
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, WorldState> {
        self.state.lock().unwrap()
    }

    /// Guest address of the first entity.
    fn base(&self) -> u64 {
        self.base
    }

    fn len(&self) -> usize {
        self.state().len
    }

    fn entities(&self) -> Vec<Entity> {
        let state = self.state();
        (0..state.len).map(|slot| state.entity(slot)).collect()
    }

    fn tick(&self) -> u32 {
        self.state().tick
    }

    fn set_tick(&self, tick: u32) {
        self.state().tick = tick;
    }

    /// Adds an entity and returns its id, or 0 if the world is full.
    fn spawn(&self, kind: u32, x: i32, y: i32, stats: Stats) -> u32 {
        let mut state = self.state();
        if state.len == CAPACITY {
            return 0;
        }

        state.next_id += 1;
        let entity = Entity {
            id: state.next_id,
            hp: stats.hp,
            armor: stats.armor,
            kind,
            x,
            y,
            attack: stats.attack,
            spawned_at: state.tick,
        };
        let slot = state.len;
        state.set_entity(slot, entity);
        state.len += 1;
        entity.id
    }

    /// Takes `amount` hit points from entity `id` and returns how many it has left.
    fn damage(&self, id: u32, amount: i32) -> u32 {
        const ID: usize = offset_of!(Entity, id);
        const HP: usize = offset_of!(Entity, hp);
        let mut state = self.state();
        let Some(slot) = (0..state.len).find(|&slot| state.get::<u32>(slot, ID) == id) else {
            return 0;
        };
        let hp = (state.get::<i32>(slot, HP) - amount).max(0);
        state.set(slot, HP, hp);
        hp as u32
    }

    fn remove_dead(&self) {
        let mut state = self.state();
        let mut kept = 0;
        for slot in 0..state.len {
            let entity = state.entity(slot);
            if entity.hp > 0 {
                state.set_entity(kept, entity);
                kept += 1;
            }
        }
        state.len = kept;
    }
}

impl WorldState {
    /// Field at byte offset `field` of the entity in `slot`.
    fn get<T: Scalar>(&self, slot: usize, field: usize) -> T {
        let offset = slot * size_of::<Entity>() + field;
        self.region.read(offset).expect("slot inside the region")
    }

    fn set<T: Scalar>(&mut self, slot: usize, field: usize, value: T) {
        let offset = slot * size_of::<Entity>() + field;
        self.region.write(offset, value).expect("slot inside the region");
    }

    fn entity(&self, slot: usize) -> Entity {
        Entity {
            id: self.get(slot, offset_of!(Entity, id)),
            hp: self.get(slot, offset_of!(Entity, hp)),
            armor: self.get(slot, offset_of!(Entity, armor)),
            kind: self.get(slot, offset_of!(Entity, kind)),
            x: self.get(slot, offset_of!(Entity, x)),
            y: self.get(slot, offset_of!(Entity, y)),
            attack: self.get(slot, offset_of!(Entity, attack)),
            spawned_at: self.get(slot, offset_of!(Entity, spawned_at)),
        }
    }

    fn set_entity(&mut self, slot: usize, entity: Entity) {
        self.set(slot, offset_of!(Entity, id), entity.id);
        self.set(slot, offset_of!(Entity, hp), entity.hp);
        self.set(slot, offset_of!(Entity, armor), entity.armor);
        self.set(slot, offset_of!(Entity, kind), entity.kind);
        self.set(slot, offset_of!(Entity, x), entity.x);
        self.set(slot, offset_of!(Entity, y), entity.y);
        self.set(slot, offset_of!(Entity, attack), entity.attack);
        self.set(slot, offset_of!(Entity, spawned_at), entity.spawned_at);
    }
}
