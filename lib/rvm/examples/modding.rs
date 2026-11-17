//! A game that runs its mods as rvm plugins.
//!
//! - `bpf/game_rules.c` spawns monster waves through the host function `spawn`
//!   and exports `record_kills`, which keeps each hero's score in a map.
//! - `bpf/game_combat.c` moves monsters, attacks through the host function
//!   `damage`, and passes each tick's kills to `record_kills` in one buffer that
//!   the rules plugin borrows for the call.
//!
//! The entities live in a region that the host shares with every plugin. The host
//! describes its `Entity` layout with `Vm::types`, and CO-RE patches the plugins'
//! field offsets and array stride to match it: `bpf/game_sdk.h` declares the struct
//! with other field order and size. `scores` and the rules plugin's `waves` are maps
//! that the VM shares, so they belong to the VM and keep their contents when the
//! host replaces the rules with `game_rules_v2.o` halfway through. The host links
//! the combat plugin ahead of time into an image and loads it from bytes, and calls
//! both plugins every tick through function handles it looks up once.
//!
//! Rebuild the plugins with:
//!   clang -target bpf -mcpu=v4 -O2 -g -c bpf/game_rules.c -o bpf/game_rules.o
//!   clang -target bpf -mcpu=v4 -O2 -g -DRULES_V2 -c bpf/game_rules.c -o bpf/game_rules_v2.o
//!   clang -target bpf -mcpu=v4 -O2 -g -c bpf/game_combat.c -o bpf/game_combat.o
//!
//! Run with: cargo run -p rvm --example modding

use std::error::Error;
use std::mem::{offset_of, size_of};
use std::sync::{Arc, Mutex};

use rvm::{BtfBuilder, Perms, Plugin, SharedRegion, Vm};

const RULES: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/game_rules.o"));
const RULES_V2: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/game_rules_v2.o"));
const COMBAT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/game_combat.o"));

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
    let mut vm = Vm::new();
    describe_entity(vm.types());
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
    // A game would prepare the image when it installs the mod; this links the
    // plugin against the host's externs and entity layout.
    let combat_image = vm.prepare(COMBAT)?.to_bytes();
    let combat = vm.load_plugin_image("combat", &combat_image)?;

    run(&vm, &world, &rules, &combat)?;
    print_summary(&world, &rules)
}

/// Tells CO-RE where the host keeps each field of `struct entity`.
fn describe_entity(types: &mut BtfBuilder) {
    let int = types.int("int", 4, true);
    let uint = types.int("unsigned int", 4, false);
    let entity = types.add_struct("entity", size_of::<Entity>() as u32);
    let fields = [
        ("id", offset_of!(Entity, id), uint),
        ("hp", offset_of!(Entity, hp), int),
        ("armor", offset_of!(Entity, armor), int),
        ("kind", offset_of!(Entity, kind), uint),
        ("x", offset_of!(Entity, x), int),
        ("y", offset_of!(Entity, y), int),
        ("attack", offset_of!(Entity, attack), int),
    ];
    for (name, offset, ty) in fields {
        types.member(entity, name, offset as u32, ty);
    }
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
    vm.enable_print(move |line| println!("tick {:>2}  {line}", w.tick()));
}

/// Runs the game, swapping in the second version of the rules at `RELOAD_AT`.
fn run(vm: &Vm, world: &World, rules: &Plugin, combat: &Plugin) -> rvm::Result<()> {
    let mut rules_tick = rules.func("on_tick")?;
    let combat_tick = combat.func("on_tick")?;

    for tick in 0..TICKS {
        world.set_tick(tick);
        if tick == RELOAD_AT {
            rules.replace(vm.load_elf(RULES_V2)?);
            // handles into the replaced program fail, so look the function up again
            rules_tick = rules.func("on_tick")?;
            println!("tick {tick:>2}  host: reloaded rules");
        }

        rules.call_func(rules_tick, &[tick.into()])?;
        combat.call_func(combat_tick, &[world.base(), world.len() as u64])?;
        world.remove_dead();
    }
    Ok(())
}

fn print_summary(world: &World, rules: &Plugin) -> Result<(), Box<dyn Error>> {
    let mut rules = rules.lock()?;
    let alive = world.entities();

    let waves = rules.map("waves").ok_or("rules has no waves map")?;
    let [wave, spawned] = u64s(waves.get(&0u32.to_le_bytes()).ok_or("no wave state")?);
    let monsters: Vec<_> = alive.iter().filter(|e| e.kind != HERO).collect();
    let oldest = monsters.iter().map(|e| e.spawned_at).min().unwrap_or(TICKS);
    let left = monsters.len();
    println!("{wave} waves, {spawned} monsters spawned, {left} left (oldest from tick {oldest})");

    let scores = rules.map("scores").ok_or("rules has no scores map")?;
    for (i, (name, _)) in HEROES.iter().enumerate() {
        let id = i as u32 + 1;
        let hp = alive.iter().find(|e| e.id == id).map_or(0, |e| e.hp);
        let [points, kills] = scores.get(&id.to_le_bytes()).map_or([0, 0], u64s);
        println!("{name}: {hp} hp, {points} points, {kills} kills");
    }
    Ok(())
}

/// Reads `struct score` and `struct wave_state`, which are two `u64`s each.
fn u64s(bytes: &[u8]) -> [u64; 2] {
    let word = |i: usize| u64::from_le_bytes(bytes[i * 8..][..8].try_into().unwrap());
    [word(0), word(1)]
}

/// The host's entity. Its field order and size differ from `struct entity` in
/// `bpf/game_sdk.h`.
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

/// Entities in a region shared with every plugin, as an array the host appends to
/// and compacts.
struct World {
    region: SharedRegion,
    state: Mutex<WorldState>,
}

#[derive(Default)]
struct WorldState {
    len: usize,
    next_id: u32,
    tick: u32,
}

impl World {
    fn new(vm: &Vm) -> rvm::Result<Self> {
        // SAFETY: plugins only run on this thread, so they never access the region
        // while `with` holds a slice of it.
        let region = unsafe { vm.share_region(rvm::FIRST_FREE_REGION, CAPACITY * size_of::<Entity>(), Perms::RW)? };
        Ok(Self {
            region,
            state: Mutex::default(),
        })
    }

    /// Runs `f` on the state and all `CAPACITY` slots.
    fn with<R>(&self, f: impl FnOnce(&mut WorldState, &mut [Entity]) -> R) -> R {
        let mut state = self.state.lock().unwrap();
        let ptr = self.region.buffer().as_ptr().cast::<Entity>();
        // SAFETY: the buffer holds `CAPACITY` entities, is aligned to 64 bytes, and
        // any bytes form a valid `Entity`. The lock keeps host accesses apart, and
        // see `new` for the guests.
        let slots = unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), CAPACITY) };
        f(&mut state, slots)
    }

    /// Guest address of the first entity.
    fn base(&self) -> u64 {
        self.region.base()
    }

    fn len(&self) -> usize {
        self.with(|state, _| state.len)
    }

    fn entities(&self) -> Vec<Entity> {
        self.with(|state, slots| slots[..state.len].to_vec())
    }

    fn tick(&self) -> u32 {
        self.with(|state, _| state.tick)
    }

    fn set_tick(&self, tick: u32) {
        self.with(|state, _| state.tick = tick);
    }

    /// Adds an entity and returns its id, or 0 if the world is full.
    fn spawn(&self, kind: u32, x: i32, y: i32, stats: Stats) -> u32 {
        self.with(|state, slots| {
            let Some(slot) = slots.get_mut(state.len) else {
                return 0;
            };
            state.len += 1;
            state.next_id += 1;
            *slot = Entity {
                id: state.next_id,
                hp: stats.hp,
                armor: stats.armor,
                kind,
                x,
                y,
                attack: stats.attack,
                spawned_at: state.tick,
            };
            slot.id
        })
    }

    /// Takes `amount` hit points from entity `id` and returns how many it has left.
    fn damage(&self, id: u32, amount: i32) -> u32 {
        self.with(|state, slots| {
            let Some(e) = slots[..state.len].iter_mut().find(|e| e.id == id) else {
                return 0;
            };
            e.hp = (e.hp - amount).max(0);
            e.hp as u32
        })
    }

    fn remove_dead(&self) {
        self.with(|state, slots| {
            let mut kept = 0;
            for i in 0..state.len {
                if slots[i].hp > 0 {
                    slots[kept] = slots[i];
                    kept += 1;
                }
            }
            state.len = kept;
        });
    }
}
