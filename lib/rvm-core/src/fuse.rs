//! Superinstructions: common instruction sequences that a run executes with one dispatch.
//!
//! The second pass of [`Code::new`](crate::Code::new), [`fuse`], gives the first slot of each sequence it recognises
//! the opcode byte of a superinstruction, one of the bytes that no slot holds after the first pass (see
//! [`bytes`](crate::bytes)). The other slots keep what they hold, so a jump into the middle of a sequence runs its
//! instructions one by one. A superinstruction behaves exactly like its sequence:
//! - it lies in one of the blocks that fuel is charged for ([`fuel`](crate::fuel)), and where the fuel runs out inside
//!   its block, its instructions run one at a time;
//! - an instruction that faults stops execution at its own pc, with the effects of the instructions before it;
//! - a load or store that misses its data window ([`windows::data_step`]) continues the sequence unfused from itself.
//!
//! The pass also gives the loads and stores through r10 that [`windows::stack_access`] runs their bytes.

mod handler;
mod supers;

pub use supers::{Super, SUPERS};

use crate::dispatch::Handler;
use crate::fuel::Fuel;
use crate::opcode::LD_IMM64;
use crate::{transfer, windows, Host, Instruction, Memory};

/// Runs the pass on `code`, which the first pass ([`rewrite`](crate::rewrite)) has run on.
pub fn fuse(code: &mut [Instruction]) {
    // A superinstruction or r10 access changes only the opcode byte of its first slot. So the code from slot `i` on is
    // still as loaded but for opcode bytes, and a handler, which reads the other fields of its sequence's slots, later
    // reads the fields `encode` checked, and the slots of its sequence that `transfer::fits` keeps as they are. A
    // sequence whose branch leaves the code gives way to the next candidate, as `transfer::bound` would run it unfused.
    // The second slot of each LD_IMM64 left holds the byte `MISSING`, which starts no sequence.
    for i in 0..code.len() {
        let window = &code[i..];
        // most candidates differ from the code in their last opcode, which this tests without a call
        let fused = |(byte, sup): &(u8, Super)| {
            let last = sup.len() - 1;
            let ends = window.get(last).is_some_and(|insn| insn.byte() == sup.opcode(last));
            ends.then(|| sup.encode(*byte, window))
                .flatten()
                .filter(|_| transfer::fits(sup, code, i))
        };
        let found = candidates(window).iter().find_map(|&k| fused(&SUPERS[usize::from(k)]));
        debug_assert_eq!(found, SUPERS.iter().find_map(fused));
        if let Some(slot) = found {
            code[i] = slot;
        } else if let Some(byte) = windows::stack_byte(code[i]) {
            code[i] = code[i].with_byte(byte);
        }
    }
}

/// The indexes of [`SUPERS`] grouped by their first two opcodes, each group in [`SUPERS`] order, so that the first
/// match is the same.
const BY_PAIR: [u8; SUPERS.len()] = {
    const fn pair(index: u8) -> u16 {
        let sup = SUPERS[index as usize].1;
        (sup.opcode(0) as u16) << 8 | sup.second() as u16
    }

    // a stable insertion sort
    let mut sorted = [0; SUPERS.len()];
    const_for!(i in 0..SUPERS.len() => {
        let mut j = i;
        while j > 0 && pair(sorted[j - 1]) > pair(i as u8) {
            sorted[j] = sorted[j - 1];
            j -= 1;
        }
        sorted[j] = i as u8;
    });
    sorted
};

/// The superinstruction at index `i` of [`BY_PAIR`].
const fn by_pair(i: usize) -> Super {
    SUPERS[BY_PAIR[i] as usize].1
}

/// The number of opcodes that start a superinstruction.
const FIRSTS: usize = {
    let mut n = 1;
    const_for!(i in 1..BY_PAIR.len() => n += (by_pair(i).opcode(0) != by_pair(i - 1).opcode(0)) as usize);
    n
};

/// For each opcode byte, the row of [`GROUPS`] for the superinstructions that start with it: 0 if none does.
const ROWS: [u8; 256] = {
    let mut rows = [0; 256];
    let mut row = 0;
    const_for!(i in 0..BY_PAIR.len() => {
        let first = by_pair(i).opcode(0) as usize;
        if rows[first] == 0 {
            row += 1;
            rows[first] = row;
        }
    });
    rows
};

/// For each opcode byte, the column of [`GROUPS`] for the superinstructions whose second opcode it is: 0 if none's is.
const COLS: [u8; 256] = {
    let mut cols = [0; 256];
    let mut col = 0;
    const_for!(i in 0..BY_PAIR.len() => {
        let second = by_pair(i).second() as usize;
        if cols[second] == 0 {
            col += 1;
            cols[second] = col;
        }
    });
    cols
};

/// The number of opcodes that are the second of a superinstruction.
const SECONDS: usize = {
    let mut n = 0;
    const_for!(col in COLS => n = if col as usize > n { col as usize } else { n });
    n
};

/// For each row of [`ROWS`] and column of [`COLS`], the range of [`BY_PAIR`] whose superinstructions start with those
/// two opcodes. Row 0 and column 0 are empty.
const GROUPS: [[(u8, u8); 1 + SECONDS]; 1 + FIRSTS] = {
    let mut groups = [[(0, 0); 1 + SECONDS]; 1 + FIRSTS];
    const_for!(i in 0..BY_PAIR.len() => {
        let sup = by_pair(i);
        let group = &mut groups[ROWS[sup.opcode(0) as usize] as usize][COLS[sup.second() as usize] as usize];
        if group.1 == 0 {
            group.0 = i as u8;
        }
        group.1 += 1;
    });
    groups
};

/// The [`SUPERS`] indexes of the superinstructions that start with the first two opcodes of `window`, in the order
/// [`fuse`] tries them.
fn candidates(window: &[Instruction]) -> &'static [u8] {
    let Some(first) = window.first() else {
        return &[];
    };
    let row = ROWS[usize::from(first.byte())];
    // most slots start none
    if row == 0 {
        return &[];
    }
    // the second instruction follows the upper half of an LD_IMM64
    let Some(second) = window.get(1 + usize::from(first.byte() == LD_IMM64)) else {
        return &[];
    };
    let (start, len) = GROUPS[row as usize][usize::from(COLS[usize::from(second.byte())])];
    &BY_PAIR[start as usize..][..len as usize]
}

/// Give each superinstruction byte its handler.
pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
    supers::install::<M, H, F>(table);
}
