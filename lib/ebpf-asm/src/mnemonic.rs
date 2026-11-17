//! eBPF instruction mnemonics.
//!
//! This module defines all eBPF instruction mnemonics, categorized by type:
//! - ALU operations (32-bit and 64-bit)
//! - Jump/branch operations
//! - Memory load/store operations
//! - Special instructions (call, exit, etc.)

use std::fmt;

/// Declares the `Mnemonic` enum together with its `name()` method, so each variant's display name sits next to its
/// definition instead of in a separate match.
macro_rules! mnemonics {
    ($( $variant:ident = $name:literal ),+ $(,)?) => {
        /// eBPF instruction mnemonic.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Mnemonic {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )+
        }

        impl Mnemonic {
            /// Get the mnemonic name as a string.
            pub const fn name(self) -> &'static str {
                match self {
                    $( Mnemonic::$variant => $name, )+
                }
            }
        }
    };
}

mnemonics! {
    // ALU64 operations
    Add64 = "add64", Sub64 = "sub64", Mul64 = "mul64", Div64 = "div64", SDiv64 = "sdiv64",
    Or64 = "or64", And64 = "and64", Lsh64 = "lsh64", Rsh64 = "rsh64", Neg64 = "neg64",
    Mod64 = "mod64", SMod64 = "smod64", Xor64 = "xor64", Mov64 = "mov64", Arsh64 = "arsh64",

    // ALU32 operations
    Add32 = "add32", Sub32 = "sub32", Mul32 = "mul32", Div32 = "div32", SDiv32 = "sdiv32",
    Or32 = "or32", And32 = "and32", Lsh32 = "lsh32", Rsh32 = "rsh32", Neg32 = "neg32",
    Mod32 = "mod32", SMod32 = "smod32", Xor32 = "xor32", Mov32 = "mov32", Arsh32 = "arsh32",

    // Byte swap operations
    Le16 = "le16", Le32 = "le32", Le64 = "le64", Be16 = "be16", Be32 = "be32", Be64 = "be64",
    Bswap16 = "bswap16", Bswap32 = "bswap32", Bswap64 = "bswap64",

    // Sign-extending moves: source width, then destination width
    Movsx832 = "movsx832", Movsx1632 = "movsx1632",
    Movsx864 = "movsx864", Movsx1664 = "movsx1664", Movsx3264 = "movsx3264",

    // Jump operations (64-bit comparison)
    Ja = "ja", Jeq = "jeq", Jgt = "jgt", Jge = "jge", Jlt = "jlt", Jle = "jle",
    Jset = "jset", Jne = "jne", Jsgt = "jsgt", Jsge = "jsge", Jslt = "jslt", Jsle = "jsle",

    // Jump operations (32-bit comparison)
    Ja32 = "ja32", Jeq32 = "jeq32", Jgt32 = "jgt32", Jge32 = "jge32", Jlt32 = "jlt32", Jle32 = "jle32",
    Jset32 = "jset32", Jne32 = "jne32", Jsgt32 = "jsgt32", Jsge32 = "jsge32", Jslt32 = "jslt32", Jsle32 = "jsle32",

    // Memory operations
    Ldxdw = "ldxdw", Ldxw = "ldxw", Ldxh = "ldxh", Ldxb = "ldxb",
    Ldxsw = "ldxsw", Ldxsh = "ldxsh", Ldxsb = "ldxsb",
    Stxdw = "stxdw", Stxw = "stxw", Stxh = "stxh", Stxb = "stxb",
    Stdw = "stdw", Stw = "stw", Sth = "sth", Stb = "stb",

    // Legacy packet loads: absolute offset in imm, or src_reg plus imm
    Ldabsw = "ldabsw", Ldabsh = "ldabsh", Ldabsb = "ldabsb",
    Ldindw = "ldindw", Ldindh = "ldindh", Ldindb = "ldindb",

    // Special instructions
    Lddw = "lddw", LdPseudo = "ld_pseudo",
    Call = "call", CallLocal = "call", CallKfunc = "call kfunc", Callx = "callx", Gotox = "gotox",
    Exit = "exit", MayGoto = "may_goto", AddrSpaceCast = "addr_space_cast",

    // Atomic operations
    AtomicAdd64 = "lock add64", AtomicAdd32 = "lock add32",
    AtomicOr64 = "lock or64", AtomicOr32 = "lock or32",
    AtomicAnd64 = "lock and64", AtomicAnd32 = "lock and32",
    AtomicXor64 = "lock xor64", AtomicXor32 = "lock xor32",
    AtomicXchg64 = "lock xchg64", AtomicXchg32 = "lock xchg32",
    AtomicCmpxchg64 = "lock cmpxchg64", AtomicCmpxchg32 = "lock cmpxchg32",
    AtomicFetchAdd64 = "lock fadd64", AtomicFetchAdd32 = "lock fadd32",
    AtomicFetchOr64 = "lock for64", AtomicFetchOr32 = "lock for32",
    AtomicFetchAnd64 = "lock fand64", AtomicFetchAnd32 = "lock fand32",
    AtomicFetchXor64 = "lock fxor64", AtomicFetchXor32 = "lock fxor32",

    Unknown = "unknown",
}

impl Mnemonic {
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
                | Mnemonic::MayGoto
        )
    }

    /// Check if this is a jump that compares `dst` with a register or immediate.
    #[inline]
    pub const fn is_conditional_jump(self) -> bool {
        self.is_jump() && !matches!(self, Mnemonic::Ja | Mnemonic::Ja32 | Mnemonic::MayGoto)
    }

    /// Check if this is a byte swap operation.
    #[inline]
    pub const fn is_endian(self) -> bool {
        matches!(
            self,
            Mnemonic::Le16
                | Mnemonic::Le32
                | Mnemonic::Le64
                | Mnemonic::Be16
                | Mnemonic::Be32
                | Mnemonic::Be64
                | Mnemonic::Bswap16
                | Mnemonic::Bswap32
                | Mnemonic::Bswap64
        )
    }

    /// Check if this is a wide instruction (16 bytes, 2 slots).
    #[inline]
    pub const fn is_wide(self) -> bool {
        matches!(self, Mnemonic::Lddw | Mnemonic::LdPseudo)
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
