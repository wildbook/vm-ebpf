//! Seeded mutations of the fixtures under `bpf/prebuilt/` and of the images prepared from them. Loading a mutated file
//! must return `Ok` or `Err`; a panic, an overflow or an allocation over [`ALLOC_CAP`] fails the test. The allocator
//! cap applies to the whole test binary.
//!
//! Inputs that ask for a large region or map are valid, so the VM runs with a memory limit of [`MEMORY_LIMIT`], and
//! linking and loading must reject them before they allocate.
//!
//! `RVM_FUZZ_ITERS` sets the cases per fixture. A failure prints its fixture and seed; `RVM_FUZZ_SEED=<seed>` runs only
//! that case for every fixture.

use std::alloc::{GlobalAlloc, Layout, System};
use std::backtrace::{Backtrace, BacktraceStatus};
use std::cell::{Cell, RefCell};
use std::ops::Range;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

use rvm::{Image, Module, VmConfig};

use crate::common::{host_vm_with, object};

/// Most memory one case's program may take.
const MEMORY_LIMIT: usize = 64 << 20;

/// The allocator refuses anything larger, which fails the case: no single allocation of a load within the limit comes
/// close.
const ALLOC_CAP: usize = 2 * MEMORY_LIMIT;

/// Cases per fixture and loader, about a second in a debug build.
const DEFAULT_ITERS: u64 = 1000;

fn limited_vm() -> rvm::Vm {
    host_vm_with(VmConfig {
        memory_limit: MEMORY_LIMIT,
        ..VmConfig::default()
    })
}

#[test]
fn mutated_images_load_or_fail() {
    let vm = limited_vm();
    let images: Vec<(String, Vec<u8>)> = fixtures()
        .into_iter()
        .filter_map(|(name, elf)| Some((name, vm.prepare(&elf).ok()?.to_bytes())))
        .collect();
    assert!(images.len() >= 15, "only {} fixtures prepare", images.len());

    let mut fuzz = Fuzz::new("image");
    for (fixture, image) in &images {
        let regions = image_regions(image);
        fuzz.run(fixture, image, &regions, |bytes| {
            if Image::from_bytes(bytes).is_err() {
                return Outcome::Rejected;
            }
            outcome(vm.load_image(bytes))
        });
    }
    fuzz.finish();
}

#[test]
fn mutated_elf_files_load_or_fail() {
    let vm = limited_vm();
    let mut fuzz = Fuzz::new("elf");
    for (fixture, elf) in &fixtures() {
        let regions = elf_regions(elf);
        fuzz.run(fixture, elf, &regions, |bytes| {
            let Ok(module) = Module::from_elf("main", bytes) else {
                return Outcome::Rejected;
            };
            let Ok(image) = vm.prepare_modules(&[&module]) else {
                return Outcome::Rejected;
            };
            outcome(vm.load_image(&image.to_bytes()))
        });
    }
    fuzz.finish();
}

/// Every `.o` in the directories under `bpf/prebuilt/`, by path relative to it.
fn fixtures() -> Vec<(String, Vec<u8>)> {
    let root = format!("{}/../../bpf/prebuilt", env!("CARGO_MANIFEST_DIR"));
    let mut names = Vec::new();
    for dir in std::fs::read_dir(root).unwrap() {
        let dir = dir.unwrap();
        if !dir.file_type().unwrap().is_dir() {
            continue;
        }
        let sub = dir.file_name().into_string().unwrap();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if name.ends_with(".o") {
                names.push(format!("{sub}/{name}"));
            }
        }
    }
    names.sort();
    names.into_iter().map(|name| (name.clone(), object(&name))).collect()
}

fn outcome(loaded: rvm::Result<rvm::Program>) -> Outcome {
    match loaded {
        Ok(_) => Outcome::Loaded,
        Err(_) => Outcome::Rejected,
    }
}

/// The image header and each length-prefixed section, so edits land in every section as often as in the code.
fn image_regions(image: &[u8]) -> Vec<Range<usize>> {
    let u32_at = |at: usize| u32::from_le_bytes(image[at..][..4].try_into().unwrap()) as usize;
    let u64_at = |at: usize| u64::from_le_bytes(image[at..][..8].try_into().unwrap()) as usize;

    // magic, format version, rvm version string
    let mut at = 12 + u32_at(8);
    let mut regions = vec![0..image.len(), 0..at];
    for _ in 0..6 {
        let len = 8 + u64_at(at);
        regions.push(at..at + len);
        at += len;
    }
    regions
}

/// The ELF header, the section header table and each section's contents (symbol table, relocations, `.BTF`, `.BTF.ext`,
/// `.maps`, code and data alike).
fn elf_regions(elf: &[u8]) -> Vec<Range<usize>> {
    let u16_at = |at: usize| u16::from_le_bytes(elf[at..][..2].try_into().unwrap()) as usize;
    let u32_at = |at: usize| u32::from_le_bytes(elf[at..][..4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(elf[at..][..8].try_into().unwrap()) as usize;
    const NOBITS: u32 = 8;

    let (shoff, shnum) = (u64_at(0x28), u16_at(0x3c));
    let mut regions = vec![0..elf.len(), 0..64, shoff..shoff + 64 * shnum];
    for i in 0..shnum {
        let header = shoff + 64 * i;
        let (typ, offset, size) = (u32_at(header + 4), u64_at(header + 0x18), u64_at(header + 0x20));
        if typ != NOBITS && size != 0 {
            regions.push(offset..offset + size);
        }
    }
    regions
}

enum Outcome {
    Loaded,
    Rejected,
}

struct Fuzz {
    loader: &'static str,
    counts: [u64; 2],
    failures: Vec<String>,
}

impl Fuzz {
    fn new(loader: &'static str) -> Self {
        install_hooks();
        Self {
            loader,
            counts: [0; 2],
            failures: Vec::new(),
        }
    }

    /// Run [`DEFAULT_ITERS`] or `RVM_FUZZ_ITERS` mutations of `original`, or the one case `RVM_FUZZ_SEED` names.
    fn run(&mut self, fixture: &str, original: &[u8], regions: &[Range<usize>], load: impl Fn(&[u8]) -> Outcome) {
        let seeds: Vec<u64> = match env_u64("RVM_FUZZ_SEED") {
            Some(seed) => vec![seed],
            None => {
                let iters = env_u64("RVM_FUZZ_ITERS").unwrap_or(DEFAULT_ITERS);
                let base = fnv1a(self.loader.as_bytes()) ^ fnv1a(fixture.as_bytes());
                (0..iters).map(|i| Rng(base ^ i).next()).collect()
            }
        };

        for seed in seeds {
            let mut bytes = original.to_vec();
            mutate(&mut Rng(seed), &mut bytes, regions);

            CAPTURING.set(true);
            let result = panic::catch_unwind(AssertUnwindSafe(|| load(&bytes)));
            CAPTURING.set(false);
            match result {
                Ok(outcome) => self.counts[outcome as usize] += 1,
                Err(_) => {
                    let panic = PANIC.take().unwrap_or_default();
                    let failure = format!("{fixture} RVM_FUZZ_SEED={seed:#x}: {panic}");
                    self.failures.push(failure);
                }
            }
        }
    }

    fn finish(self) {
        let [loaded, rejected] = self.counts;
        let failed = self.failures.len();
        println!("{}: {loaded} loaded, {rejected} rejected, {failed} failed", self.loader);
        assert!(failed == 0, "{failed} {} cases failed:\n{}", self.loader, self.failures.join("\n"));
    }
}

/// Apply one to four edits, fewer more often, each inside a random region of the original.
fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>, regions: &[Range<usize>]) {
    for _ in 0..1 + (rng.next() | 1 << 3).trailing_zeros() {
        let region = &regions[rng.below(regions.len())];
        let start = region.start.min(bytes.len());
        let end = region.end.clamp(start, bytes.len());
        let at = start + rng.below(end - start + 1);
        let room = bytes.len() - at;

        match rng.below(6) {
            0 if room > 0 => bytes[at] ^= 1 << rng.below(8),
            1 if room > 0 => bytes[at] = rng.next() as u8,
            2 => {
                let len = 1 + rng.below(16);
                let insert: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                bytes.splice(at..at, insert);
            }
            3 => {
                let len = (1 + rng.below(16)).min(room);
                bytes.drain(at..at + len);
            }
            4 => bytes.truncate(at),
            _ => {
                // overwrite an integer field, most often a length, offset or index; ELF and BTF fields sit at multiples
                // of their width in the region
                let width = [1, 2, 4, 8][rng.below(4)];
                let at = match rng.below(2) {
                    0 => start + (at - start) / width * width,
                    _ => at,
                };
                let width = width.min(bytes.len() - at);
                let field = &mut bytes[at..][..width];
                let mut le = [0; 8];
                le[..width].copy_from_slice(field);
                let old = u64::from_le_bytes(le);
                let max = if width == 8 { u64::MAX } else { (1 << (8 * width)) - 1 };
                let new = match rng.below(8) {
                    0 => 0,
                    1 => max,
                    2 => max / 2 + 1,
                    3 => rng.next() % 256,
                    4 => old.wrapping_add(1 + rng.next() % 8),
                    5 => old.wrapping_sub(1 + rng.next() % 8),
                    6 => old.wrapping_mul(2).wrapping_add(rng.next() % 2),
                    _ => rng.next(),
                };
                field.copy_from_slice(&new.to_le_bytes()[..width]);
            }
        }
    }
}

/// splitmix64
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let step = |hash: u64, &b: &u8| (hash ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, step)
}

fn env_u64(name: &str) -> Option<u64> {
    let value = std::env::var(name).ok()?;
    let parsed = match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    };
    Some(parsed.unwrap_or_else(|_| panic!("{name}={value} is not a number")))
}

thread_local! {
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
    static PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Record panics inside a case instead of printing them, with a backtrace under `RUST_BACKTRACE`, and turn a refused
/// allocation into a panic so it fails the case like any other.
fn install_hooks() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::alloc::set_alloc_error_hook(|layout| panic!("refused to allocate {} bytes", layout.size()));
        let default = panic::take_hook();
        panic::set_hook(Box::new(move |info| match CAPTURING.get() {
            true => {
                let backtrace = Backtrace::capture();
                let message = match backtrace.status() {
                    BacktraceStatus::Captured => format!("{info}\n{backtrace}"),
                    _ => info.to_string(),
                };
                PANIC.set(Some(message));
            }
            false => default(info),
        }));
    });
}

struct CappedAlloc;

#[global_allocator]
static ALLOC: CappedAlloc = CappedAlloc;

// SAFETY: forwards to `System`, refusing large requests with null as allowed.
unsafe impl GlobalAlloc for CappedAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match layout.size() > ALLOC_CAP {
            true => std::ptr::null_mut(),
            false => unsafe { System.alloc(layout) },
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        match layout.size() > ALLOC_CAP {
            true => std::ptr::null_mut(),
            false => unsafe { System.alloc_zeroed(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        match new_size > ALLOC_CAP {
            true => std::ptr::null_mut(),
            false => unsafe { System.realloc(ptr, layout, new_size) },
        }
    }
}
