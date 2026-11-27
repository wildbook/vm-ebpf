//! Dispatch: how control passes from the handler of one instruction to the handler of the next.
//!
//! Every opcode byte has a [`Handler`]. A handler runs the instruction in its slot, loads the next slot and tail-calls
//! the handler of that slot's opcode byte, which it finds in a [`Table`]. So a run is a chain of handlers, each with
//! indirect jumps of its own, and the branch predictor tracks the successors of every opcode separately. The chain
//! ends where a handler records a stop in the [`Interpreter`] and returns.
//!
//! The macros of this module are the ways a handler continues. Each one ends the handler that expands it:
//! - `become_next!` and `become_at!` continue in the block of the handler's slot;
//! - `become_enter!` continues at the start of another block, at a slot that needs no bounds check;
//! - `become_at_pc!` continues at a pc that has no proof, or stops there.
//!
//! A block ends at each slot whose handler may continue anywhere but at the next slot. The handlers that end a block
//! take a [`Fuel`], which charges a metered run for the block they enter ([`fuel`](crate::fuel)). No other handler
//! has anything for fuel.
//!
//! # Split dispatch
//!
//! The handlers of ALU instructions test the parity of the next opcode byte and continue through one of two indirect
//! jumps, each with its own copy of the handlers in the [`Table`]. It is a choice for the branch predictor of AMD
//! Zen 3.
//!
//! Zen 3 predicts an indirect jump with several targets from a global history in two parts. For each of the last 9
//! taken branches it keeps bits 3:2 of the address of the branch's last byte. For about 63 conditional branches it
//! keeps the direction, but it records only branches that have been taken at least once. A chain of handlers that
//! each end in one indirect jump gives this history little: two address bits per handler, often the same two bits for
//! different handlers, and no directions, because the checks in the handlers are never taken. Where the target of a
//! dispatch depends on more than the last nine handlers, as at a `callx` that cycles through several callees, the
//! predictor can't tell the cases apart. The parity branch goes both ways, so it puts one bit about each opcode that
//! follows an ALU instruction into the direction history, and that is enough to separate them. Two jumps through one
//! table would be the same code, which the compiler merges; the second copy keeps them apart.
//!
//! Measured on a Ryzen 5 5625U with and without fuel, in three code layouts each: the `callx` loop of the benchmarks
//! went from 7,500 indirect mispredicts per call to under 6 and ran 29% to 40% faster, a corpus of real programs went
//! from 80k to 136k mispredicts to 19k to 35k and ran 8% to 20% faster, and a hash function went from up to 2,400 to
//! under 10 and ran up to 30% faster. Without fuel, most other workloads changed by less than 2%, and none ran more
//! than about 5% slower in any layout. The cost is one more fused test and branch per ALU dispatch and 2 KB of table.
//!
//! Only the ALU handlers split. With every handler split, the direction history covers the last 63 dispatches instead
//! of the last 63 guest branches, and guest loops whose exit depends on a longer history mispredict more. With the
//! superinstructions split too, a sieve loop ran 6% to 8% slower.
//!
//! Other processors keep other history, so the gain there is unmeasured.

use std::marker::PhantomData;
use std::mem::MaybeUninit;

use crate::code::Slots;
use crate::fuel::{Fuel, Unmetered};
use crate::handler::{handler, jump};
use crate::opcode::{Class, OpCode};
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{args, fuse, native, transfer, windows, Context, Host, Interpreter, Memory};

/// Continues at `$ip`, in the block of the slot the handler runs: tail-calls the handler of its instruction. `$ip`
/// must lie in `0..=len`. A true `$split` makes the tail call one of two, as the module docs describe.
macro_rules! become_at {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $table:expr, $split:expr) => {{
        let ip = $ip;
        // SAFETY: the caller's (see `Ip`)
        let slot = unsafe { ip.get() };
        match $split && $crate::dispatch::odd(slot) {
            true => become $table.odd(slot)($ctx, $code, ip, $interp, $table, $crate::dispatch::SPARE, slot),
            false => become $table.of(slot)($ctx, $code, ip, $interp, $table, $crate::dispatch::SPARE, slot),
        }
    }};
}

/// Continues at the slot after `$ip`, in the same block, as `become_at!` does. `$ip` must lie below `len`, as the
/// ip of every handler but the guard's does, and must not end its block.
macro_rules! become_next {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $table:expr) => {
        become_next!($ctx, $code, $ip, $interp, $table, false)
    };
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $table:expr, $split:expr) => {
        become_at!($ctx, $code, $ip.offset(1), $interp, $table, $split)
    };
}

/// Enters the block at `$ip` ([`Fuel::enter`]) and continues there as `become_at!` does, or in [`Fuel::step`] if the
/// fuel can't pay for the block. The handler's generic parameters must be `M`, `H` and `F`. `$ip` must lie in
/// `0..=len`: the slot after one below `len`, or a target that [`transfer::bound`] proves.
macro_rules! become_enter {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $table:expr) => {{
        let ip = $ip;
        if !F::enter($interp, $code, ip) {
            core::hint::cold_path();
            let slot = $crate::slot::Slot::UNREAD;
            become F::step::<M, H>($ctx, $code, ip, $interp, $table, $crate::dispatch::SPARE, slot)
        }
        become_at!($ctx, $code, ip, $interp, $table, false)
    }};
}

/// Continues at `$pc`, which no proof covers: enters its block there as `become_enter!` does, or stops with
/// [`Reason::BadPc`](crate::Reason::BadPc) if the code has no slot there. The handler's generic parameters are named
/// as for `become_enter!`.
macro_rules! become_at_pc {
    ($ctx:expr, $code:expr, $pc:expr, $interp:expr, $table:expr) => {{
        let pc = $pc;
        match $crate::dispatch::fetch_checked::<M, H, F>($table, $code, pc, $interp) {
            Some((next, slot, ip)) => become next($ctx, $code, ip, $interp, $table, $crate::dispatch::SPARE, slot),
            None => return $interp.stop.at_pc(pc, $crate::Reason::BadPc),
        }
    }};
}

/// Runs the instruction `slot` at `ip` in `code` and continues with the next one, until a handler stops the run in
/// `interp.stop`. `table` is the [`Table`] the run dispatches through.
///
/// The handler of opcode byte `OP` runs only slots in the layout of `OP` ([`slot::LAYOUTS`](crate::slot::LAYOUTS)),
/// and reads their fields with [`Ip::view`]: from `slot` where one instruction extracts them, else from the code.
///
/// `preserve_none` passes all arguments in registers (the Windows x64 C convention has four) and saves no registers, so
/// a tail call between handlers is a jump. It passes them in R12, R13, R14, R15, RDI, RSI, RDX, RCX ... in order, and
/// `code` takes two:
/// - `interp` and `table` are in RDI and RSI, which a host function preserves, so a handler that calls one needn't
///   save them;
/// - the [`Spare`] is in RDX, which `div` and `mul` write: nothing is there to save around them;
/// - `slot` comes eighth and lands in RCX: a single `movzx` reads its second byte from CH, and a shift by its `imm`
///   takes the count from CL.
pub type Handler<M, H> =
    extern "rust-preserve-none" fn(&mut Context<M>, Slots, Ip, &mut Interpreter<M, H>, &Table<M, H>, Spare, Slot);

/// The argument of a [`Handler`] that carries nothing: it takes the register before that of `slot`. Every caller
/// passes [`SPARE`], which costs no instruction, and no handler reads it.
pub type Spare = MaybeUninit<u64>;

pub const SPARE: Spare = Spare::uninit();

/// The handler of every opcode byte, and the copy of them that split dispatch continues through.
pub struct Table<M: Memory, H>(pub [Handler<M, H>; 256], pub [Handler<M, H>; 256]);

impl<M: Memory, H> Table<M, H> {
    /// The handler of `slot`.
    #[inline(always)]
    pub fn of(&self, slot: Slot) -> Handler<M, H> {
        self.0[usize::from(slot.byte())]
    }

    /// The handler of `slot`, from the second copy.
    #[inline(always)]
    pub fn odd(&self, slot: Slot) -> Handler<M, H> {
        self.1[usize::from(slot.byte())]
    }
}

/// Whether the handler of opcode byte `op` splits its dispatch.
pub const fn splits(op: u8) -> bool {
    matches!(OpCode(op).class(), Class::Alu32 | Class::Alu64)
}

/// Whether a split dispatch to `slot` takes the second copy of the [`Table`].
// LLVM takes the branch on even parity; with the branch taken on odd parity, the corpus ran 2% to 6% slower
#[inline(always)]
pub fn odd(slot: Slot) -> bool {
    slot.byte().count_ones() % 2 != 0
}

/// The tables of the handlers for the memory `M` and the host `H`.
pub struct Tables<M, H>(PhantomData<(M, H)>);

impl<M: Memory, H: Host<M>> Tables<M, H> {
    /// The table of a run without a limit.
    pub const PLAIN: Table<M, H> = table::<M, H, Unmetered>();
}

/// The table of the runs that meter with `F`. It differs between two `F` only in the handlers that end a block.
///
/// Each handler runs [`step`](crate::step::step) with its opcode as a constant, so the class, operation, source, mode
/// and size matches fold away; the bytes of superinstructions and r10 accesses get theirs from [`fuse::install`], the
/// guard and far jumps from [`transfer::install`], and the plain loads and stores from [`windows::install`].
pub const fn table<M: Memory, H: Host<M>, F: Fuel>() -> Table<M, H> {
    macro_rules! table {
        ($($op:literal)*) => {
            [$(by_class::<M, H, F, $op>(),)*]
        };
    }

    let mut table = table!(
        0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
        0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f
        0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28 0x29 0x2a 0x2b 0x2c 0x2d 0x2e 0x2f
        0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x39 0x3a 0x3b 0x3c 0x3d 0x3e 0x3f
        0x40 0x41 0x42 0x43 0x44 0x45 0x46 0x47 0x48 0x49 0x4a 0x4b 0x4c 0x4d 0x4e 0x4f
        0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x59 0x5a 0x5b 0x5c 0x5d 0x5e 0x5f
        0x60 0x61 0x62 0x63 0x64 0x65 0x66 0x67 0x68 0x69 0x6a 0x6b 0x6c 0x6d 0x6e 0x6f
        0x70 0x71 0x72 0x73 0x74 0x75 0x76 0x77 0x78 0x79 0x7a 0x7b 0x7c 0x7d 0x7e 0x7f
        0x80 0x81 0x82 0x83 0x84 0x85 0x86 0x87 0x88 0x89 0x8a 0x8b 0x8c 0x8d 0x8e 0x8f
        0x90 0x91 0x92 0x93 0x94 0x95 0x96 0x97 0x98 0x99 0x9a 0x9b 0x9c 0x9d 0x9e 0x9f
        0xa0 0xa1 0xa2 0xa3 0xa4 0xa5 0xa6 0xa7 0xa8 0xa9 0xaa 0xab 0xac 0xad 0xae 0xaf
        0xb0 0xb1 0xb2 0xb3 0xb4 0xb5 0xb6 0xb7 0xb8 0xb9 0xba 0xbb 0xbc 0xbd 0xbe 0xbf
        0xc0 0xc1 0xc2 0xc3 0xc4 0xc5 0xc6 0xc7 0xc8 0xc9 0xca 0xcb 0xcc 0xcd 0xce 0xcf
        0xd0 0xd1 0xd2 0xd3 0xd4 0xd5 0xd6 0xd7 0xd8 0xd9 0xda 0xdb 0xdc 0xdd 0xde 0xdf
        0xe0 0xe1 0xe2 0xe3 0xe4 0xe5 0xe6 0xe7 0xe8 0xe9 0xea 0xeb 0xec 0xed 0xee 0xef
        0xf0 0xf1 0xf2 0xf3 0xf4 0xf5 0xf6 0xf7 0xf8 0xf9 0xfa 0xfb 0xfc 0xfd 0xfe 0xff
    );
    fuse::install::<M, H, F>(&mut table);
    transfer::install::<M, H, F>(&mut table);
    windows::install::<M, H>(&mut table);
    native::install::<M, H, F>(&mut table);
    args::install::<M, H, F>(&mut table);
    Table(table, table)
}

/// The handler of opcode `OP`: [`jump`] for the jump classes, whose instructions end a block, and [`handler`] for the
/// others.
const fn by_class<M: Memory, H: Host<M>, F: Fuel, const OP: u8>() -> Handler<M, H> {
    match OpCode(OP).is_jump() {
        true => jump::<M, H, F, OP>,
        false => handler::<M, H, OP>,
    }
}

/// The handler, slot and ip at `pc`, which no proof covers, as the handler enters the block there ([`Fuel::enter`]).
/// `None` if the code has no slot at `pc`.
#[inline(always)]
pub fn fetch_checked<M: Memory, H: Host<M>, F: Fuel>(
    table: &Table<M, H>,
    code: Slots,
    pc: u64,
    interp: &mut Interpreter<M, H>,
) -> Option<Checked<M, H>> {
    let slot = code.get(pc)?;
    let ip = Ip::at(code, pc);
    let paid = F::enter(interp, code, ip);
    let next = table.of(slot);
    // a `cmov`, as a branch would take a jump on the common side
    let next = core::hint::select_unpredictable(paid, next, F::step::<M, H> as Handler<M, H>);
    Some((next, slot, ip))
}

/// The handler, slot and ip at the pc [`fetch_checked`] checked.
pub type Checked<M, H> = (Handler<M, H>, Slot, Ip);
