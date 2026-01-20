//! eBPF instruction mnemonics.
//!
//! This module defines all eBPF instruction mnemonics, categorized by type:
//! - ALU operations (32-bit and 64-bit)
//! - Jump/branch operations
//! - Memory load/store operations
//! - Special instructions (call, exit, etc.)

use std::fmt;

/// eBPF instruction mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mnemonic {
    // ==================== ALU64 operations ====================
    /// 64-bit addition: dst += src
    Add64,
    /// 64-bit subtraction: dst -= src
    Sub64,
    /// 64-bit multiplication: dst *= src
    Mul64,
    /// 64-bit unsigned division: dst /= src
    Div64,
    /// 64-bit signed division: dst /= src (signed)
    SDiv64,
    /// 64-bit bitwise OR: dst |= src
    Or64,
    /// 64-bit bitwise AND: dst &= src
    And64,
    /// 64-bit left shift: dst <<= src
    Lsh64,
    /// 64-bit logical right shift: dst >>= src
    Rsh64,
    /// 64-bit negation: dst = -dst
    Neg64,
    /// 64-bit unsigned modulo: dst %= src
    Mod64,
    /// 64-bit signed modulo: dst %= src (signed)
    SMod64,
    /// 64-bit bitwise XOR: dst ^= src
    Xor64,
    /// 64-bit move: dst = src
    Mov64,
    /// 64-bit arithmetic right shift: dst >>= src (signed)
    Arsh64,

    // ==================== ALU32 operations ====================
    /// 32-bit addition: dst += src
    Add32,
    /// 32-bit subtraction: dst -= src
    Sub32,
    /// 32-bit multiplication: dst *= src
    Mul32,
    /// 32-bit unsigned division: dst /= src
    Div32,
    /// 32-bit signed division: dst /= src (signed)
    SDiv32,
    /// 32-bit bitwise OR: dst |= src
    Or32,
    /// 32-bit bitwise AND: dst &= src
    And32,
    /// 32-bit left shift: dst <<= src
    Lsh32,
    /// 32-bit logical right shift: dst >>= src
    Rsh32,
    /// 32-bit negation: dst = -dst
    Neg32,
    /// 32-bit unsigned modulo: dst %= src
    Mod32,
    /// 32-bit signed modulo: dst %= src (signed)
    SMod32,
    /// 32-bit bitwise XOR: dst ^= src
    Xor32,
    /// 32-bit move: dst = src
    Mov32,
    /// 32-bit arithmetic right shift: dst >>= src (signed)
    Arsh32,

    // ==================== Byte swap operations ====================
    /// Convert to little-endian (16-bit)
    Le16,
    /// Convert to little-endian (32-bit)
    Le32,
    /// Convert to little-endian (64-bit)
    Le64,
    /// Convert to big-endian (16-bit)
    Be16,
    /// Convert to big-endian (32-bit)
    Be32,
    /// Convert to big-endian (64-bit)
    Be64,

    // ==================== Jump operations (64-bit comparison) ====================
    /// Unconditional jump
    Ja,
    /// Jump if equal: if dst == src goto +off
    Jeq,
    /// Jump if greater than (unsigned): if dst > src goto +off
    Jgt,
    /// Jump if greater or equal (unsigned): if dst >= src goto +off
    Jge,
    /// Jump if less than (unsigned): if dst < src goto +off
    Jlt,
    /// Jump if less or equal (unsigned): if dst <= src goto +off
    Jle,
    /// Jump if bits set: if dst & src goto +off
    Jset,
    /// Jump if not equal: if dst != src goto +off
    Jne,
    /// Jump if greater than (signed): if dst > src goto +off
    Jsgt,
    /// Jump if greater or equal (signed): if dst >= src goto +off
    Jsge,
    /// Jump if less than (signed): if dst < src goto +off
    Jslt,
    /// Jump if less or equal (signed): if dst <= src goto +off
    Jsle,

    // ==================== Jump operations (32-bit comparison) ====================
    /// Unconditional jump (32-bit encoding, uses imm for offset)
    Ja32,
    /// Jump if equal (32-bit): if dst == src goto +off
    Jeq32,
    /// Jump if greater than (unsigned, 32-bit): if dst > src goto +off
    Jgt32,
    /// Jump if greater or equal (unsigned, 32-bit): if dst >= src goto +off
    Jge32,
    /// Jump if less than (unsigned, 32-bit): if dst < src goto +off
    Jlt32,
    /// Jump if less or equal (unsigned, 32-bit): if dst <= src goto +off
    Jle32,
    /// Jump if bits set (32-bit): if dst & src goto +off
    Jset32,
    /// Jump if not equal (32-bit): if dst != src goto +off
    Jne32,
    /// Jump if greater than (signed, 32-bit): if dst > src goto +off
    Jsgt32,
    /// Jump if greater or equal (signed, 32-bit): if dst >= src goto +off
    Jsge32,
    /// Jump if less than (signed, 32-bit): if dst < src goto +off
    Jslt32,
    /// Jump if less or equal (signed, 32-bit): if dst <= src goto +off
    Jsle32,

    // ==================== Memory operations ====================
    /// Load double word (64-bit) from memory
    Ldxdw,
    /// Load word (32-bit) from memory
    Ldxw,
    /// Load half word (16-bit) from memory
    Ldxh,
    /// Load byte (8-bit) from memory
    Ldxb,

    /// Load double word (64-bit) with sign extension
    Ldxsdw,
    /// Load word (32-bit) with sign extension
    Ldxsw,
    /// Load half word (16-bit) with sign extension
    Ldxsh,
    /// Load byte (8-bit) with sign extension
    Ldxsb,

    /// Store double word (64-bit) from register
    Stxdw,
    /// Store word (32-bit) from register
    Stxw,
    /// Store half word (16-bit) from register
    Stxh,
    /// Store byte (8-bit) from register
    Stxb,

    /// Store double word (64-bit) immediate
    Stdw,
    /// Store word (32-bit) immediate
    Stw,
    /// Store half word (16-bit) immediate
    Sth,
    /// Store byte (8-bit) immediate
    Stb,

    // ==================== Special instructions ====================
    /// Load 64-bit immediate (2-instruction sequence)
    Lddw,
    /// Call helper function
    Call,
    /// Call program-local function (BPF-to-BPF call)
    CallLocal,
    /// Exit program
    Exit,

    // ==================== Atomic operations ====================
    /// Atomic add (64-bit)
    AtomicAdd64,
    /// Atomic add (32-bit)
    AtomicAdd32,
    /// Atomic or (64-bit)
    AtomicOr64,
    /// Atomic or (32-bit)
    AtomicOr32,
    /// Atomic and (64-bit)
    AtomicAnd64,
    /// Atomic and (32-bit)
    AtomicAnd32,
    /// Atomic xor (64-bit)
    AtomicXor64,
    /// Atomic xor (32-bit)
    AtomicXor32,
    /// Atomic exchange (64-bit)
    AtomicXchg64,
    /// Atomic exchange (32-bit)
    AtomicXchg32,
    /// Atomic compare-and-exchange (64-bit)
    AtomicCmpxchg64,
    /// Atomic compare-and-exchange (32-bit)
    AtomicCmpxchg32,
    /// Atomic fetch-add (64-bit)
    AtomicFetchAdd64,
    /// Atomic fetch-add (32-bit)
    AtomicFetchAdd32,
    /// Atomic fetch-or (64-bit)
    AtomicFetchOr64,
    /// Atomic fetch-or (32-bit)
    AtomicFetchOr32,
    /// Atomic fetch-and (64-bit)
    AtomicFetchAnd64,
    /// Atomic fetch-and (32-bit)
    AtomicFetchAnd32,
    /// Atomic fetch-xor (64-bit)
    AtomicFetchXor64,
    /// Atomic fetch-xor (32-bit)
    AtomicFetchXor32,

    /// Unknown/invalid instruction
    Unknown,
}

impl Mnemonic {
    /// Check if this is an ALU operation.
    #[inline]
    pub const fn is_alu(self) -> bool {
        matches!(
            self,
            Mnemonic::Add64
                | Mnemonic::Sub64
                | Mnemonic::Mul64
                | Mnemonic::Div64
                | Mnemonic::SDiv64
                | Mnemonic::Or64
                | Mnemonic::And64
                | Mnemonic::Lsh64
                | Mnemonic::Rsh64
                | Mnemonic::Neg64
                | Mnemonic::Mod64
                | Mnemonic::SMod64
                | Mnemonic::Xor64
                | Mnemonic::Mov64
                | Mnemonic::Arsh64
                | Mnemonic::Add32
                | Mnemonic::Sub32
                | Mnemonic::Mul32
                | Mnemonic::Div32
                | Mnemonic::SDiv32
                | Mnemonic::Or32
                | Mnemonic::And32
                | Mnemonic::Lsh32
                | Mnemonic::Rsh32
                | Mnemonic::Neg32
                | Mnemonic::Mod32
                | Mnemonic::SMod32
                | Mnemonic::Xor32
                | Mnemonic::Mov32
                | Mnemonic::Arsh32
        )
    }

    /// Check if this is a 64-bit ALU operation.
    #[inline]
    pub const fn is_alu64(self) -> bool {
        matches!(
            self,
            Mnemonic::Add64
                | Mnemonic::Sub64
                | Mnemonic::Mul64
                | Mnemonic::Div64
                | Mnemonic::SDiv64
                | Mnemonic::Or64
                | Mnemonic::And64
                | Mnemonic::Lsh64
                | Mnemonic::Rsh64
                | Mnemonic::Neg64
                | Mnemonic::Mod64
                | Mnemonic::SMod64
                | Mnemonic::Xor64
                | Mnemonic::Mov64
                | Mnemonic::Arsh64
        )
    }

    /// Check if this is a 32-bit ALU operation.
    #[inline]
    pub const fn is_alu32(self) -> bool {
        matches!(
            self,
            Mnemonic::Add32
                | Mnemonic::Sub32
                | Mnemonic::Mul32
                | Mnemonic::Div32
                | Mnemonic::SDiv32
                | Mnemonic::Or32
                | Mnemonic::And32
                | Mnemonic::Lsh32
                | Mnemonic::Rsh32
                | Mnemonic::Neg32
                | Mnemonic::Mod32
                | Mnemonic::SMod32
                | Mnemonic::Xor32
                | Mnemonic::Mov32
                | Mnemonic::Arsh32
        )
    }

    /// Check if this is a jump/branch operation.
    #[inline]
    pub const fn is_jump(self) -> bool {
        matches!(
            self,
            Mnemonic::Ja
                | Mnemonic::Jeq
                | Mnemonic::Jgt
                | Mnemonic::Jge
                | Mnemonic::Jlt
                | Mnemonic::Jle
                | Mnemonic::Jset
                | Mnemonic::Jne
                | Mnemonic::Jsgt
                | Mnemonic::Jsge
                | Mnemonic::Jslt
                | Mnemonic::Jsle
                | Mnemonic::Ja32
                | Mnemonic::Jeq32
                | Mnemonic::Jgt32
                | Mnemonic::Jge32
                | Mnemonic::Jlt32
                | Mnemonic::Jle32
                | Mnemonic::Jset32
                | Mnemonic::Jne32
                | Mnemonic::Jsgt32
                | Mnemonic::Jsge32
                | Mnemonic::Jslt32
                | Mnemonic::Jsle32
        )
    }

    /// Check if this is a conditional jump.
    #[inline]
    pub const fn is_conditional_jump(self) -> bool {
        self.is_jump() && !matches!(self, Mnemonic::Ja | Mnemonic::Ja32)
    }

    /// Check if this is a memory load operation.
    #[inline]
    pub const fn is_load(self) -> bool {
        matches!(
            self,
            Mnemonic::Ldxdw
                | Mnemonic::Ldxw
                | Mnemonic::Ldxh
                | Mnemonic::Ldxb
                | Mnemonic::Ldxsdw
                | Mnemonic::Ldxsw
                | Mnemonic::Ldxsh
                | Mnemonic::Ldxsb
                | Mnemonic::Lddw
        )
    }

    /// Check if this is a memory store operation.
    #[inline]
    pub const fn is_store(self) -> bool {
        matches!(
            self,
            Mnemonic::Stxdw
                | Mnemonic::Stxw
                | Mnemonic::Stxh
                | Mnemonic::Stxb
                | Mnemonic::Stdw
                | Mnemonic::Stw
                | Mnemonic::Sth
                | Mnemonic::Stb
        )
    }

    /// Check if this is a byte swap operation.
    #[inline]
    pub const fn is_endian(self) -> bool {
        matches!(
            self,
            Mnemonic::Le16 | Mnemonic::Le32 | Mnemonic::Le64 | Mnemonic::Be16 | Mnemonic::Be32 | Mnemonic::Be64
        )
    }

    /// Check if this is an atomic operation.
    #[inline]
    pub const fn is_atomic(self) -> bool {
        matches!(
            self,
            Mnemonic::AtomicAdd64
                | Mnemonic::AtomicAdd32
                | Mnemonic::AtomicOr64
                | Mnemonic::AtomicOr32
                | Mnemonic::AtomicAnd64
                | Mnemonic::AtomicAnd32
                | Mnemonic::AtomicXor64
                | Mnemonic::AtomicXor32
                | Mnemonic::AtomicXchg64
                | Mnemonic::AtomicXchg32
                | Mnemonic::AtomicCmpxchg64
                | Mnemonic::AtomicCmpxchg32
                | Mnemonic::AtomicFetchAdd64
                | Mnemonic::AtomicFetchAdd32
                | Mnemonic::AtomicFetchOr64
                | Mnemonic::AtomicFetchOr32
                | Mnemonic::AtomicFetchAnd64
                | Mnemonic::AtomicFetchAnd32
                | Mnemonic::AtomicFetchXor64
                | Mnemonic::AtomicFetchXor32
        )
    }

    /// Check if this instruction modifies the destination register.
    #[inline]
    pub const fn writes_dst(self) -> bool {
        self.is_alu() || self.is_load() || self.is_endian() || matches!(self, Mnemonic::Call | Mnemonic::CallLocal)
    }

    /// Check if this is a wide instruction (16 bytes, 2 slots).
    #[inline]
    pub const fn is_wide(self) -> bool {
        matches!(self, Mnemonic::Lddw)
    }

    /// Get the mnemonic name as a string.
    pub const fn name(self) -> &'static str {
        match self {
            Mnemonic::Add64 => "add64",
            Mnemonic::Sub64 => "sub64",
            Mnemonic::Mul64 => "mul64",
            Mnemonic::Div64 => "div64",
            Mnemonic::SDiv64 => "sdiv64",
            Mnemonic::Or64 => "or64",
            Mnemonic::And64 => "and64",
            Mnemonic::Lsh64 => "lsh64",
            Mnemonic::Rsh64 => "rsh64",
            Mnemonic::Neg64 => "neg64",
            Mnemonic::Mod64 => "mod64",
            Mnemonic::SMod64 => "smod64",
            Mnemonic::Xor64 => "xor64",
            Mnemonic::Mov64 => "mov64",
            Mnemonic::Arsh64 => "arsh64",
            Mnemonic::Add32 => "add32",
            Mnemonic::Sub32 => "sub32",
            Mnemonic::Mul32 => "mul32",
            Mnemonic::Div32 => "div32",
            Mnemonic::SDiv32 => "sdiv32",
            Mnemonic::Or32 => "or32",
            Mnemonic::And32 => "and32",
            Mnemonic::Lsh32 => "lsh32",
            Mnemonic::Rsh32 => "rsh32",
            Mnemonic::Neg32 => "neg32",
            Mnemonic::Mod32 => "mod32",
            Mnemonic::SMod32 => "smod32",
            Mnemonic::Xor32 => "xor32",
            Mnemonic::Mov32 => "mov32",
            Mnemonic::Arsh32 => "arsh32",
            Mnemonic::Le16 => "le16",
            Mnemonic::Le32 => "le32",
            Mnemonic::Le64 => "le64",
            Mnemonic::Be16 => "be16",
            Mnemonic::Be32 => "be32",
            Mnemonic::Be64 => "be64",
            Mnemonic::Ja => "ja",
            Mnemonic::Jeq => "jeq",
            Mnemonic::Jgt => "jgt",
            Mnemonic::Jge => "jge",
            Mnemonic::Jlt => "jlt",
            Mnemonic::Jle => "jle",
            Mnemonic::Jset => "jset",
            Mnemonic::Jne => "jne",
            Mnemonic::Jsgt => "jsgt",
            Mnemonic::Jsge => "jsge",
            Mnemonic::Jslt => "jslt",
            Mnemonic::Jsle => "jsle",
            Mnemonic::Ja32 => "ja32",
            Mnemonic::Jeq32 => "jeq32",
            Mnemonic::Jgt32 => "jgt32",
            Mnemonic::Jge32 => "jge32",
            Mnemonic::Jlt32 => "jlt32",
            Mnemonic::Jle32 => "jle32",
            Mnemonic::Jset32 => "jset32",
            Mnemonic::Jne32 => "jne32",
            Mnemonic::Jsgt32 => "jsgt32",
            Mnemonic::Jsge32 => "jsge32",
            Mnemonic::Jslt32 => "jslt32",
            Mnemonic::Jsle32 => "jsle32",
            Mnemonic::Ldxdw => "ldxdw",
            Mnemonic::Ldxw => "ldxw",
            Mnemonic::Ldxh => "ldxh",
            Mnemonic::Ldxb => "ldxb",
            Mnemonic::Ldxsdw => "ldxsdw",
            Mnemonic::Ldxsw => "ldxsw",
            Mnemonic::Ldxsh => "ldxsh",
            Mnemonic::Ldxsb => "ldxsb",
            Mnemonic::Stxdw => "stxdw",
            Mnemonic::Stxw => "stxw",
            Mnemonic::Stxh => "stxh",
            Mnemonic::Stxb => "stxb",
            Mnemonic::Stdw => "stdw",
            Mnemonic::Stw => "stw",
            Mnemonic::Sth => "sth",
            Mnemonic::Stb => "stb",
            Mnemonic::Lddw => "lddw",
            Mnemonic::Call => "call",
            Mnemonic::CallLocal => "call",
            Mnemonic::Exit => "exit",
            Mnemonic::AtomicAdd64 => "lock add64",
            Mnemonic::AtomicAdd32 => "lock add32",
            Mnemonic::AtomicOr64 => "lock or64",
            Mnemonic::AtomicOr32 => "lock or32",
            Mnemonic::AtomicAnd64 => "lock and64",
            Mnemonic::AtomicAnd32 => "lock and32",
            Mnemonic::AtomicXor64 => "lock xor64",
            Mnemonic::AtomicXor32 => "lock xor32",
            Mnemonic::AtomicXchg64 => "lock xchg64",
            Mnemonic::AtomicXchg32 => "lock xchg32",
            Mnemonic::AtomicCmpxchg64 => "lock cmpxchg64",
            Mnemonic::AtomicCmpxchg32 => "lock cmpxchg32",
            Mnemonic::AtomicFetchAdd64 => "lock fadd64",
            Mnemonic::AtomicFetchAdd32 => "lock fadd32",
            Mnemonic::AtomicFetchOr64 => "lock for64",
            Mnemonic::AtomicFetchOr32 => "lock for32",
            Mnemonic::AtomicFetchAnd64 => "lock fand64",
            Mnemonic::AtomicFetchAnd32 => "lock fand32",
            Mnemonic::AtomicFetchXor64 => "lock fxor64",
            Mnemonic::AtomicFetchXor32 => "lock fxor32",
            Mnemonic::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
