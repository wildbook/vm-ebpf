//! Dispatch: how control passes from the handler of one instruction to the handler of the next.
//!
//! A [`Code`](crate::Code) compiles lazily into a 16-byte direct-threaded [`ThreadedSlot`](crate::code::ThreadedSlot)
//! stream per mode ([`Tables`]). Each handler runs its slot, loads the next 8-byte slot into `RCX` in parallel with
//! jumping directly to the next handler pointer at `[ip]`.
//!
//! The macros of this module are the ways a handler continues. Each one ends the handler that expands it:
//! - `become_next!` and `become_at!` continue in the block of the handler's slot;
//! - `become_enter!` continues at the start of another block, at a slot that needs no bounds check;
//! - `become_at_pc!` continues at a pc that has no proof, or stops there.

use std::marker::PhantomData;
use std::mem::MaybeUninit;

use crate::code::Slots;
use crate::fuel::{Fuel, RestsPtr, Unmetered};
use crate::handler::{self, alu3_imm, alu3_reg, handler, ja_scaled, jump, jump_unscaled, local_call_scaled};
use crate::opcode::OpCode;
use crate::slot::Slot;
use crate::threaded::{self, FoldTable};
use crate::transfer::Ip;
use crate::{args, fuse, native, transfer, windows, Context, Host, Interpreter, Memory};

/// Continues at `$ip`, in the block of the slot the handler runs: tail-calls the handler stored at `$ip`. `$ip` must
/// lie in `0..=len`.
macro_rules! become_at {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $rests:expr) => {{
        let ip = $ip;
        // SAFETY: the caller's (see `Ip`)
        let (next, slot) = unsafe { ip.fetch::<M, H>() };
        become next($ctx, $code, ip, $interp, $rests, $crate::dispatch::SPARE, slot)
    }};
}

/// Continues at the slot after `$ip`, in the same block, as `become_at!` does. `$ip` must lie below `len`, as the ip
/// of every handler but the guard's does, and must not end its block.
macro_rules! become_next {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $rests:expr) => {
        become_at!($ctx, $code, $ip.offset(1), $interp, $rests)
    };
}

/// Enters the block at `$ip` ([`Fuel::enter`]) and continues there as `become_at!` does, or in [`Fuel::step`] if the
/// fuel can't pay for the block. The handler's generic parameters must be `M`, `H` and `F`. `$ip` must lie in
/// `0..=len`: the slot after one below `len`, or a target that [`transfer::bound`] proves.
macro_rules! become_enter {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $rests:expr) => {{
        let ip = $ip;
        if !F::enter($interp, $code, ip, $rests) {
            core::hint::cold_path();
            let slot = $crate::slot::Slot::UNREAD;
            become F::step::<M, H>($ctx, $code, ip, $interp, $rests, $crate::dispatch::SPARE, slot)
        }
        become_at!($ctx, $code, ip, $interp, $rests)
    }};
}

/// Enters the block at `$ip` by charging a pre-decoded block length `$rest` directly instead of reading `$rests`.
macro_rules! become_enter_rest {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $rests:expr, $rest:expr) => {{
        let ip = $ip;
        if !F::enter_rest($interp, $rest) {
            core::hint::cold_path();
            let slot = $crate::slot::Slot::UNREAD;
            become F::step::<M, H>($ctx, $code, ip, $interp, $rests, $crate::dispatch::SPARE, slot)
        }
        become_at!($ctx, $code, ip, $interp, $rests)
    }};
}

/// Continues at `$pc`, which no proof covers: enters its block there as `become_enter!` does, or stops with
/// [`Reason::BadPc`](crate::Reason::BadPc) if the code has no slot there. The handler's generic parameters are named
/// as for `become_enter!`.
macro_rules! become_at_pc {
    ($ctx:expr, $code:expr, $pc:expr, $interp:expr, $rests:expr) => {{
        let pc = $pc;
        match $crate::dispatch::fetch_checked::<M, H, F>($code, pc, $interp, $rests) {
            Some((next, slot, ip)) => become next($ctx, $code, ip, $interp, $rests, $crate::dispatch::SPARE, slot),
            None => return $interp.stop.at_pc(pc, $crate::Reason::BadPc),
        }
    }};
}

/// Runs the instruction `slot` at `ip` in `code` and continues with the next one, until a handler stops the run in
/// `interp.stop`. `rests` holds the per-slot block-length table in metered runs (null otherwise).
///
/// `preserve_none` passes all arguments in registers (the Windows x64 C convention has four) and saves no registers, so
/// a tail call between handlers is a jump. It passes them in R12, R13, R14, R15, RDI, RSI, RDX, RCX ... in order, and
/// `code` takes two:
/// - `interp` and `rests` are in RDI and RSI, which a Windows x64 host function preserves so a handler calling one
///   needn't save them (on SysV x64 they are caller-saved, so LLVM spills and reloads them around calls);
/// - the [`Spare`] is in RDX, which `div` and `mul` write: nothing is there to save around them;
/// - `slot` comes eighth and lands in RCX: a single `movzx` reads its second byte from CH and its first from CL.
pub type Handler<M, H> =
    extern "rust-preserve-none" fn(&mut Context<M>, Slots, Ip, &mut Interpreter<M, H>, RestsPtr, Spare, Slot);

/// The argument of a [`Handler`] that carries nothing: it takes the register before that of `slot`. Every caller
/// passes [`SPARE`], which costs no instruction, and no handler reads it.
pub type Spare = MaybeUninit<u64>;

pub const SPARE: Spare = Spare::uninit();

/// Handlers for 3-operand folded ALU instructions (`mov dst, src1; alu dst, rhs`), indexed by `[alu64][op_idx]`.
pub struct Alu3Table<M: Memory, H> {
    pub imm: [[Handler<M, H>; 9]; 2],
    pub reg: [[Handler<M, H>; 9]; 2],
}

/// The handlers used to compile a [`Code`](crate::Code) into a direct-threaded stream for one execution mode.
pub struct DispatchTable<M: Memory, H> {
    pub handlers: [Handler<M, H>; 256],
    pub alu3: Alu3Table<M, H>,
    pub folds: FoldTable<M, H>,
    pub ja_scaled: Handler<M, H>,
    pub local_call_scaled: Handler<M, H>,
    pub jump_unscaled: Handler<M, H>,
    #[cfg(feature = "fuel")]
    pub metered: bool,
}

/// The dispatch tables of the handlers for memory `M` and host `H`.
pub struct Tables<M, H>(PhantomData<(M, H)>);

impl<M: Memory, H: Host<M>> Tables<M, H> {
    /// The table of a run without a limit.
    pub const PLAIN: DispatchTable<M, H> = table::<M, H, Unmetered>();
}

const fn alu3_table<M: Memory, H: Host<M>>() -> Alu3Table<M, H> {
    Alu3Table {
        imm: [
            [
                alu3_imm::<M, H, false, 0>,
                alu3_imm::<M, H, false, 1>,
                alu3_imm::<M, H, false, 2>,
                alu3_imm::<M, H, false, 3>,
                alu3_imm::<M, H, false, 4>,
                alu3_imm::<M, H, false, 5>,
                alu3_imm::<M, H, false, 6>,
                alu3_imm::<M, H, false, 7>,
                alu3_imm::<M, H, false, 8>,
            ],
            [
                alu3_imm::<M, H, true, 0>,
                alu3_imm::<M, H, true, 1>,
                alu3_imm::<M, H, true, 2>,
                alu3_imm::<M, H, true, 3>,
                alu3_imm::<M, H, true, 4>,
                alu3_imm::<M, H, true, 5>,
                alu3_imm::<M, H, true, 6>,
                alu3_imm::<M, H, true, 7>,
                alu3_imm::<M, H, true, 8>,
            ],
        ],
        reg: [
            [
                alu3_reg::<M, H, false, 0>,
                alu3_reg::<M, H, false, 1>,
                alu3_reg::<M, H, false, 2>,
                alu3_reg::<M, H, false, 3>,
                alu3_reg::<M, H, false, 4>,
                alu3_reg::<M, H, false, 5>,
                alu3_reg::<M, H, false, 6>,
                alu3_reg::<M, H, false, 7>,
                alu3_reg::<M, H, false, 8>,
            ],
            [
                alu3_reg::<M, H, true, 0>,
                alu3_reg::<M, H, true, 1>,
                alu3_reg::<M, H, true, 2>,
                alu3_reg::<M, H, true, 3>,
                alu3_reg::<M, H, true, 4>,
                alu3_reg::<M, H, true, 5>,
                alu3_reg::<M, H, true, 6>,
                alu3_reg::<M, H, true, 7>,
                alu3_reg::<M, H, true, 8>,
            ],
        ],
    }
}

/// The dispatch table of runs that meter with `F`.
pub const fn table<M: Memory, H: Host<M>, F: Fuel>() -> DispatchTable<M, H> {
    macro_rules! table {
        ($($op:literal)*) => {
            [$(by_class::<M, H, F, $op>(),)*]
        };
    }

    let mut handlers = table!(
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
    handler::install::<M, H, F>(&mut handlers);
    fuse::install::<M, H, F>(&mut handlers);
    transfer::install::<M, H, F>(&mut handlers);
    windows::install::<M, H>(&mut handlers);
    native::install::<M, H, F>(&mut handlers);
    args::install::<M, H, F>(&mut handlers);
    DispatchTable {
        handlers,
        alu3: alu3_table::<M, H>(),
        folds: threaded::table::<M, H, F>(),
        ja_scaled: ja_scaled::<M, H, F>,
        local_call_scaled: local_call_scaled::<M, H, F>,
        jump_unscaled: jump_unscaled::<M, H, F>,
        #[cfg(feature = "fuel")]
        metered: F::IS_METERED,
    }
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
    code: Slots,
    pc: u64,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
) -> Option<Checked<M, H>> {
    if pc >= code.total_len() as u64 {
        return None;
    }
    let ip = Ip::at(code, pc);
    let paid = F::enter(interp, code, ip, rests);
    // SAFETY: `pc < code.total_len()`, so `ip` lies in `code`.
    let (next, slot) = unsafe { ip.fetch::<M, H>() };
    // a `cmov`, as a branch would take a jump on the common side
    let next = core::hint::select_unpredictable(paid, next, F::step::<M, H> as Handler<M, H>);
    Some((next, slot, ip))
}

/// The handler, slot and ip at the pc [`fetch_checked`] checked.
pub type Checked<M, H> = (Handler<M, H>, Slot, Ip);
