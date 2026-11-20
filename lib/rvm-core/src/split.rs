//! Split dispatch: where [`SPLIT`] is set, the handlers of ALU instructions test the parity of the next opcode byte
//! and continue through one of two indirect jumps, each with its own copy of the [`Table`]. It is a choice for the
//! branch predictor of AMD Zen 3.
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
//! Measured without fuel on a Ryzen 5 5625U, in three code layouts: the `callx` loop of the benchmarks went from 7,500
//! indirect mispredicts per call to 1 and ran 37% to 40% faster, a corpus of real programs went from 80k to 130k
//! mispredicts to 20k to 35k and ran 11% to 20% faster, and a hash function went from up to 2,400 to under 10 and ran
//! up to 30% faster. Most other workloads changed by less than 2%, and none ran more than about 5% slower in any
//! layout. The cost is one more fused test and branch per ALU dispatch and 2 KB of table. Only the ALU handlers split:
//! with every handler split, the direction history covers the last 63 dispatches instead of the last 63 guest
//! branches, and guest loops whose exit depends on a longer history mispredict more.
//!
//! Other processors keep other history, so the gain there is unmeasured.

use crate::op::Op;
use crate::opcode::{Class, OpCode};
use crate::{Handler, Memory, Table, METERED};

/// Whether the ALU handlers split their dispatch. The handlers that meter fuel don't: in most superinstructions their
/// fuel test is a taken branch that already gives the history a bit, and with the split some workloads ran up to 14%
/// slower.
const SPLIT: bool = !METERED;

/// The number of handlers in the second copy of the [`Table`]: all of them, or none without [`SPLIT`].
pub const COPY: usize = if SPLIT { 256 } else { 0 };

/// Whether the handler of opcode byte `op` splits its dispatch.
pub const fn splits(op: u8) -> bool {
    SPLIT && matches!(OpCode(op).class(), Class::Alu32 | Class::Alu64)
}

/// Whether a split dispatch to `op` takes the second copy of the [`Table`].
// LLVM takes the branch on even parity; with the branch taken on odd parity, the corpus ran 2% to 6% slower
#[inline(always)]
pub fn odd(op: Op) -> bool {
    op.byte().count_ones() % 2 != 0
}

/// The second copy of `table`, as long as [`COPY`].
pub const fn second<T: Copy>(table: &[T; 256]) -> [T; COPY] {
    *table.first_chunk().unwrap()
}

impl<M: Memory, H> Table<M, H> {
    /// The handler of `op`, from the second copy.
    #[inline(always)]
    pub fn odd(&self, op: Op) -> Handler<M, H> {
        self.1[usize::from(op.byte())]
    }
}
