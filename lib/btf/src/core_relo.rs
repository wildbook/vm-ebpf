//! CO-RE (Compile Once - Run Everywhere) relocation support.
//!
//! This module parses `.BTF.ext` sections and applies CO-RE relocations to eBPF instructions the way libbpf does
//! against kernel BTF: the host's types are a "target" BTF, the eBPF program's own debug info is the "local" BTF, and a
//! relocation's access string names a path through the local type that gets re-resolved against whichever matching type
//! the target actually has.

use crate::parse::{word, Btf, BtfError, MAX_RESOLVE_DEPTH};
use crate::raw::{BtfKind, BTF_INT_SIGNED};
use crate::strings::BtfStrings;
use crate::types::{BtfTypeInfo, Member};

/// CO-RE relocation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CoreReloKind {
    /// Field byte offset.
    FieldByteOffset = 0,
    /// Field byte size.
    FieldByteSize = 1,
    /// Field existence (0 or 1).
    FieldExists = 2,
    /// Field signedness (0 or 1).
    FieldSigned = 3,
    /// Field left shift for reading/writing.
    FieldLShiftU64 = 4,
    /// Field right shift for reading/writing.
    FieldRShiftU64 = 5,
    /// Type ID (local BTF).
    TypeIdLocal = 6,
    /// Type ID (target BTF).
    TypeIdTarget = 7,
    /// Type existence (0 or 1).
    TypeExists = 8,
    /// Type size.
    TypeSize = 9,
    /// Enum value existence.
    EnumvalExists = 10,
    /// Enum value.
    EnumvalValue = 11,
    /// Type matches (0 or 1).
    TypeMatches = 12,
}

impl CoreReloKind {
    /// Parse from raw value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::FieldByteOffset),
            1 => Some(Self::FieldByteSize),
            2 => Some(Self::FieldExists),
            3 => Some(Self::FieldSigned),
            4 => Some(Self::FieldLShiftU64),
            5 => Some(Self::FieldRShiftU64),
            6 => Some(Self::TypeIdLocal),
            7 => Some(Self::TypeIdTarget),
            8 => Some(Self::TypeExists),
            9 => Some(Self::TypeSize),
            10 => Some(Self::EnumvalExists),
            11 => Some(Self::EnumvalValue),
            12 => Some(Self::TypeMatches),
            _ => None,
        }
    }

    /// Check if this is a field-based relocation.
    pub fn is_field_relo(self) -> bool {
        matches!(
            self,
            Self::FieldByteOffset
                | Self::FieldByteSize
                | Self::FieldExists
                | Self::FieldSigned
                | Self::FieldLShiftU64
                | Self::FieldRShiftU64
        )
    }

    /// Check if this is a type-based relocation.
    pub fn is_type_relo(self) -> bool {
        matches!(self, Self::TypeIdLocal | Self::TypeIdTarget | Self::TypeExists | Self::TypeSize | Self::TypeMatches)
    }

    /// Check if this is an enum-based relocation.
    pub fn is_enum_relo(self) -> bool {
        matches!(self, Self::EnumvalExists | Self::EnumvalValue)
    }
}

/// A single CO-RE relocation entry.
#[derive(Debug, Clone)]
pub struct CoreRelo {
    /// Instruction offset (in bytes from section start).
    pub insn_off: u32,
    /// BTF type ID in the local (program) BTF.
    pub type_id: u32,
    /// Access string offset in BTF strings.
    pub access_str_off: u32,
    /// Relocation kind.
    pub kind: CoreReloKind,
}

impl CoreRelo {
    pub const SIZE: usize = 16;

    /// Parse from bytes. Fails on a relocation kind this crate doesn't know, since skipping it would leave the
    /// instruction with its compile-time value.
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        if data.len() < Self::SIZE {
            return Err(BtfError::TooShort);
        }
        let raw_kind = word(data, 3);
        let kind = CoreReloKind::from_u32(raw_kind).ok_or(BtfError::UnknownReloKind(raw_kind))?;

        Ok(Self {
            insn_off: word(data, 0),
            type_id: word(data, 1),
            access_str_off: word(data, 2),
            kind,
        })
    }
}

/// Minimum size of a `.BTF.ext` header: magic, version, flags, hdr_len, and the (unused) func_info/line_info
/// offset/length fields.
const BTF_EXT_HDR_MIN_SIZE: usize = 24;
/// Header size once the (optional, added later) CO-RE relocation fields are present.
const BTF_EXT_HDR_SIZE_WITH_CORE: usize = 32;

/// CO-RE relocations for a specific section.
#[derive(Debug, Clone)]
pub struct SectionCoreRelos<'a> {
    /// Section name.
    pub section_name: &'a str,
    /// Relocations for this section.
    pub relos: Vec<CoreRelo>,
}

/// Parsed BTF.ext data.
#[derive(Debug, Clone)]
pub struct BtfExt<'a> {
    /// CO-RE relocations grouped by section.
    pub core_relos: Vec<SectionCoreRelos<'a>>,
}

impl<'a> BtfExt<'a> {
    /// Parse BTF.ext from raw bytes.
    ///
    /// Requires the BTF strings table for resolving section names.
    pub fn parse(data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Self, BtfError> {
        if data.len() < BTF_EXT_HDR_MIN_SIZE {
            return Err(BtfError::TooShort);
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != crate::raw::BTF_MAGIC {
            return Err(BtfError::BadMagic(magic));
        }
        let hdr_len = word(data, 1) as usize;

        // older headers end before the CO-RE relocation fields
        let (core_relo_off, core_relo_len) =
            if hdr_len >= BTF_EXT_HDR_SIZE_WITH_CORE && data.len() >= BTF_EXT_HDR_SIZE_WITH_CORE {
                (word(data, 6), word(data, 7))
            } else {
                (0, 0)
            };

        let core_relos = if core_relo_len > 0 {
            Self::parse_core_relos(data, hdr_len, core_relo_off, core_relo_len, strings)?
        } else {
            Vec::new()
        };

        Ok(Self { core_relos })
    }

    fn parse_core_relos(
        data: &'a [u8],
        hdr_len: usize,
        core_relo_off: u32,
        core_relo_len: u32,
        strings: &BtfStrings<'a>,
    ) -> Result<Vec<SectionCoreRelos<'a>>, BtfError> {
        let start = hdr_len + core_relo_off as usize;
        if core_relo_len as usize > data.len().saturating_sub(start) || start >= data.len() {
            return Err(BtfError::SectionOverflow);
        }

        let relo_data = &data[start..][..core_relo_len as usize];
        if relo_data.len() < 4 {
            return Ok(Vec::new());
        }

        // First 4 bytes: record size
        let rec_size = word(relo_data, 0) as usize;
        if rec_size < CoreRelo::SIZE {
            return Err(BtfError::InvalidType(0));
        }

        let mut offset = 4;
        let mut sections = Vec::new();

        while offset + 8 <= relo_data.len() {
            // Section header: sec_name_off (4) + num_info (4)
            let sec_name_off = u32::from_le_bytes(relo_data[offset..][..4].try_into().unwrap());
            let num_info = u32::from_le_bytes(relo_data[offset + 4..][..4].try_into().unwrap());
            offset += 8;

            let section_name = strings.get_or_empty(sec_name_off);
            let records = (num_info as usize)
                .checked_mul(rec_size)
                .filter(|&len| len <= relo_data.len() - offset)
                .ok_or(BtfError::SectionOverflow)?;
            let relos = relo_data[offset..][..records]
                .chunks_exact(rec_size)
                .map(CoreRelo::parse)
                .collect::<Result<_, _>>()?;
            offset += records;

            sections.push(SectionCoreRelos { section_name, relos });
        }

        Ok(sections)
    }

    /// Get CO-RE relocations for a specific section.
    pub fn relos_for_section(&self, section_name: &str) -> Option<&[CoreRelo]> {
        self.core_relos
            .iter()
            .find(|s| s.section_name == section_name)
            .map(|s| s.relos.as_slice())
    }
}

/// Error during CO-RE relocation application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreReloError {
    /// The relocation's instruction offset doesn't land on an instruction.
    InstructionOutOfBounds(u32),
    /// A BTF type ID doesn't name a type in the BTF it was looked up in.
    InvalidTypeId(u32),
    /// The access string attached to the relocation is malformed.
    InvalidAccessString(String),
    /// A relocation that needs target candidates refers to an anonymous local type; libbpf can't look those up by name
    /// either.
    AnonymousRootType(CoreReloKind),
    /// A struct/union/array access path nests deeper than CO-RE supports.
    SpecTooDeep,
    /// Multiple target candidates resolved the relocation to different offsets or values.
    Ambiguous { insn_off: u32 },
    /// The instruction's encoded value doesn't match what the local BTF implies it should be.
    UnexpectedValue { insn_off: u32, expected: u64, found: u64 },
    /// The relocated offset doesn't fit in the instruction's 16-bit `off` field.
    OffsetTooLarge { insn_off: u32, value: u64 },
    /// A bitfield is too wide to read even with a 64-bit load.
    BitfieldTooWide,
    /// The instruction's opcode isn't one CO-RE relocations know how to patch.
    UnpatchableInstruction(u32),
    /// Relocation kind not recognized, or not applicable to an array-element accessor.
    UnsupportedRelo(CoreReloKind),
    /// Nothing in the target BTF matched the local type (and field, for field relocations); stored in [`Unresolved`]
    /// rather than failing the whole load.
    NoMatchingTarget { type_name: String, access_str: String },
    /// The target field has a different size and isn't an unsigned integer or pointer on both sides, so the memory
    /// access can't be resized safely; stored in [`Unresolved`] rather than failing the whole load.
    IncompatibleFieldSize { type_name: String, access_str: String },
}

impl core::fmt::Display for CoreReloError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InstructionOutOfBounds(off) => write!(f, "instruction offset out of bounds: {off}"),
            Self::InvalidTypeId(id) => write!(f, "invalid BTF type ID: {id}"),
            Self::InvalidAccessString(s) => write!(f, "invalid access string: {s}"),
            Self::AnonymousRootType(kind) => write!(f, "{kind:?} relocation doesn't support anonymous local types"),
            Self::SpecTooDeep => write!(f, "struct/union/array access nests too deep"),
            Self::Ambiguous { insn_off } => write!(f, "relocation at instruction offset {insn_off} is ambiguous"),
            Self::UnexpectedValue {
                insn_off,
                expected,
                found,
            } => {
                write!(f, "instruction at offset {insn_off} has value {found}, expected {expected}")
            }
            Self::OffsetTooLarge { insn_off, value } => {
                write!(f, "relocated offset {value} at instruction {insn_off} doesn't fit in 16 bits")
            }
            Self::BitfieldTooWide => write!(f, "bitfield can't be read even with a 64-bit load"),
            Self::UnpatchableInstruction(off) => write!(f, "instruction at offset {off} can't be CO-RE patched"),
            Self::UnsupportedRelo(kind) => write!(f, "unsupported relocation kind: {kind:?}"),
            Self::NoMatchingTarget { type_name, access_str } => {
                write!(f, "no target type matches '{type_name}' (accessing '{access_str}')")
            }
            Self::IncompatibleFieldSize { type_name, access_str } => {
                write!(f, "field '{access_str}' of '{type_name}' changed to a size that can't be read safely")
            }
        }
    }
}

impl std::error::Error for CoreReloError {}

/// Helper ID that unresolved relocations call, as in libbpf: running such an instruction must fail, while a program
/// that never reaches it still works.
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// A relocation whose instruction was poisoned: either the target BTF had nothing matching the local type (and field,
/// for field relocations), or a matching field had an incompatible type or size. The program still loads; only running
/// the instruction fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// Byte offset of the poisoned instruction in its section.
    pub insn_off: u32,
    /// Why the relocation couldn't be resolved against the target.
    pub error: CoreReloError,
}

/// Apply CO-RE relocations to eBPF instructions, resolving `local`'s access paths against the matching types in
/// `target` (the host's types), exactly as libbpf resolves a BPF program's debug BTF against the kernel's BTF.
pub fn apply_core_relocations(
    instructions: &mut [u64],
    local: &Btf<'_>,
    target: &Btf<'_>,
    relos: &[CoreRelo],
) -> Result<Vec<Unresolved>, CoreReloError> {
    let mut unresolved = Vec::new();
    for relo in relos {
        let res = resolve_relocation(local, target, relo)?;
        if patch_instruction(instructions, relo, &res)? {
            let access_str = local.strings().get(relo.access_str_off).unwrap_or("");
            let type_name = local.type_by_id(relo.type_id).and_then(BtfTypeInfo::name).unwrap_or("");
            let (type_name, access_str) = (type_name.to_string(), access_str.to_string());
            let error = if res.poison {
                CoreReloError::NoMatchingTarget { type_name, access_str }
            } else {
                CoreReloError::IncompatibleFieldSize { type_name, access_str }
            };
            unresolved.push(Unresolved {
                insn_off: relo.insn_off,
                error,
            });
        }
    }
    Ok(unresolved)
}

/// The two values and flags a relocation resolves to, mirroring libbpf's `bpf_core_relo_res`: `orig_val` is what the
/// instruction should already encode (given `local`), `new_val` is what it gets patched to (given `target`).
struct ResolvedRelo {
    orig_val: u64,
    new_val: u64,
    /// The field, type, or enum value this relocation refers to doesn't exist in `target`, so the instruction is
    /// poisoned instead of patched.
    poison: bool,
    /// The field's size changed in a way a memory access can't be adjusted for (libbpf's `fail_memsz_adjust`). Only a
    /// load or store is poisoned for this; an instruction that only computes the offset is patched as usual.
    fail_memsz_adjust: bool,
    /// Whether `orig_val` must match what's already encoded in the instruction.
    validate: bool,
    /// For `FieldByteOffset`, the memory access size (and its BTF type) implied by `local`.
    orig_sz: Option<u32>,
    /// Same, implied by whichever target candidate matched.
    new_sz: Option<u32>,
}

/// Relocations that resolve to "does it exist" patch to `0` when nothing in `target` matches, rather than poisoning the
/// instruction: the compiled check still runs, it just comes back false. Type-based relocations (`TYPE_ID_TARGET`,
/// `TYPE_SIZE`, ...) do the same for every kind, not just the existence ones: libbpf's `bpf_core_calc_type_relo`
/// returns `0` unconditionally when no candidate matched, since a missing type can't even provide a byte size to poison
/// a size mismatch against.
fn poisons_on_missing(kind: CoreReloKind) -> bool {
    if kind.is_type_relo() {
        return false;
    }
    !matches!(kind, CoreReloKind::FieldExists | CoreReloKind::EnumvalExists)
}

fn resolve_relocation(local: &Btf<'_>, target: &Btf<'_>, relo: &CoreRelo) -> Result<ResolvedRelo, CoreReloError> {
    let access_str = local
        .strings()
        .get(relo.access_str_off)
        .ok_or_else(|| CoreReloError::InvalidAccessString(format!("offset {}", relo.access_str_off)))?;
    let local_spec = parse_spec(local, relo, access_str)?;

    // TYPE_ID_LOCAL never needs a target: the local type ID is both the expected and the patched value (its encoded imm
    // may simply be stale after linking).
    if relo.kind == CoreReloKind::TypeIdLocal {
        let v = u64::from(relo.type_id);
        return Ok(ResolvedRelo {
            orig_val: v,
            new_val: v,
            poison: false,
            fail_memsz_adjust: false,
            validate: false,
            orig_sz: None,
            new_sz: None,
        });
    }

    let orig = calc_half(relo.kind, &local_spec, local)?;

    let local_type = local
        .type_by_id(relo.type_id)
        .ok_or(CoreReloError::InvalidTypeId(relo.type_id))?;
    let local_name = local_type.name().unwrap_or("");
    if local_name.is_empty() {
        return Err(CoreReloError::AnonymousRootType(relo.kind));
    }

    let mut agreed: Option<(u64, u64)> = None;
    let mut matched: Option<Half> = None;
    for cand_id in find_candidates(target, local_name, local_type.kind()) {
        let Some(cand_spec) = spec_match(local, &local_spec, target, cand_id)? else {
            continue;
        };
        let cand_half = calc_half(relo.kind, &cand_spec, target)?;
        match agreed {
            None => {
                agreed = Some((cand_spec.bit_offset, cand_half.val));
                matched = Some(cand_half);
            }
            Some((bit_offset, value)) if bit_offset == cand_spec.bit_offset && value == cand_half.val => {}
            Some(_) => {
                return Err(CoreReloError::Ambiguous {
                    insn_off: relo.insn_off,
                })
            }
        }
    }

    let (new_val, poison, new_mem) = match matched {
        Some(half) => (half.val, false, half.mem),
        None => (0, poisons_on_missing(relo.kind), None),
    };

    // A field that moved between an unsigned integer (or pointer) of a different size can be read with an adjusted
    // memory access size without changing its value; any other size change fails a load or store rather than risk
    // reading the wrong bytes or sign-extending wrongly.
    let mut fail_memsz_adjust = false;
    if let (Some((orig_sz, orig_tid)), Some((new_sz, new_tid))) = (orig.mem, new_mem) {
        if orig_sz != new_sz {
            let orig_t = local
                .type_by_id(orig_tid)
                .ok_or(CoreReloError::InvalidTypeId(orig_tid))?;
            let new_t = target
                .type_by_id(new_tid)
                .ok_or(CoreReloError::InvalidTypeId(new_tid))?;
            let safe_adjust = (matches!(orig_t, BtfTypeInfo::Ptr { .. }) && matches!(new_t, BtfTypeInfo::Ptr { .. }))
                || (is_unsigned_int(orig_t) && is_unsigned_int(new_t));
            fail_memsz_adjust = !safe_adjust;
        }
    }

    Ok(ResolvedRelo {
        orig_val: orig.val,
        new_val,
        poison,
        fail_memsz_adjust,
        validate: orig.validate,
        orig_sz: orig.mem.map(|(sz, _)| sz),
        new_sz: new_mem.map(|(sz, _)| sz),
    })
}

fn is_unsigned_int(t: &BtfTypeInfo<'_>) -> bool {
    matches!(t, BtfTypeInfo::Int { encoding, .. } if encoding & BTF_INT_SIGNED == 0)
}

/// Patch the relocated value into an instruction, as libbpf's `bpf_core_patch_insn` does. Returns whether the
/// instruction was poisoned instead (for the caller's `Unresolved` list).
fn patch_instruction(instructions: &mut [u64], relo: &CoreRelo, res: &ResolvedRelo) -> Result<bool, CoreReloError> {
    const CLASS_MASK: u8 = 0x07;
    const ALU: u8 = 0x04;
    const ALU64: u8 = 0x07;
    const LDX: u8 = 0x01;
    const ST: u8 = 0x02;
    const STX: u8 = 0x03;
    const LD: u8 = 0x00;
    const BPF_SRC_X: u8 = 0x08;
    const BPF_LD_IMM64: u8 = 0x18;
    const IMM_MASK: u64 = 0xFFFF_FFFF_0000_0000;
    const OFF_MASK: u64 = 0x0000_0000_FFFF_0000;
    const SRC_REG_MASK: u64 = 0x0000_0000_0000_F000;

    if relo.insn_off % 8 != 0 {
        return Err(CoreReloError::InstructionOutOfBounds(relo.insn_off));
    }
    let idx = (relo.insn_off / 8) as usize;
    let insn = *instructions
        .get(idx)
        .ok_or(CoreReloError::InstructionOutOfBounds(relo.insn_off))?;
    let opcode = insn as u8;

    match opcode & CLASS_MASK {
        ALU | ALU64 => {
            if opcode & BPF_SRC_X != 0 {
                return Err(CoreReloError::UnpatchableInstruction(relo.insn_off));
            }
            if res.poison {
                poison_insn(instructions, idx, 1);
                return Ok(true);
            }
            let imm = i64::from((insn >> 32) as u32 as i32) as u64;
            if res.validate && imm != res.orig_val {
                return Err(CoreReloError::UnexpectedValue {
                    insn_off: relo.insn_off,
                    expected: res.orig_val,
                    found: imm,
                });
            }
            instructions[idx] = (insn & !IMM_MASK) | (u64::from(res.new_val as u32) << 32);
            Ok(false)
        }
        LDX | ST | STX => {
            if res.poison {
                poison_insn(instructions, idx, 1);
                return Ok(true);
            }
            let off = i64::from((insn >> 16) as u16 as i16) as u64;
            if res.validate && off != res.orig_val {
                return Err(CoreReloError::UnexpectedValue {
                    insn_off: relo.insn_off,
                    expected: res.orig_val,
                    found: off,
                });
            }
            if res.new_val > i16::MAX as u64 {
                return Err(CoreReloError::OffsetTooLarge {
                    insn_off: relo.insn_off,
                    value: res.new_val,
                });
            }
            if res.fail_memsz_adjust {
                poison_insn(instructions, idx, 1);
                return Ok(true);
            }
            instructions[idx] = (insn & !OFF_MASK) | (res.new_val << 16);

            if res.new_sz != res.orig_sz {
                let (Some(orig_sz), Some(new_sz)) = (res.orig_sz, res.new_sz) else {
                    return Err(CoreReloError::UnpatchableInstruction(relo.insn_off));
                };
                let encoded_sz = mem_size_bytes(opcode).ok_or(CoreReloError::UnpatchableInstruction(relo.insn_off))?;
                if encoded_sz != orig_sz {
                    return Err(CoreReloError::UnexpectedValue {
                        insn_off: relo.insn_off,
                        expected: u64::from(orig_sz),
                        found: u64::from(encoded_sz),
                    });
                }
                let new_mode_size =
                    bytes_to_mem_size(new_sz).ok_or(CoreReloError::UnpatchableInstruction(relo.insn_off))?;
                let new_opcode = (opcode & 0xE0) | new_mode_size | (opcode & CLASS_MASK);
                instructions[idx] = (instructions[idx] & !0xFF) | u64::from(new_opcode);
            }
            Ok(false)
        }
        LD => {
            let hi = *instructions
                .get(idx + 1)
                .ok_or(CoreReloError::InstructionOutOfBounds(relo.insn_off + 8))?;
            let well_formed =
                opcode == BPF_LD_IMM64 && insn & SRC_REG_MASK == 0 && insn & OFF_MASK == 0 && hi & 0xFFFF_FFFF == 0;
            if !well_formed {
                return Err(CoreReloError::UnpatchableInstruction(relo.insn_off));
            }
            if res.poison {
                poison_insn(instructions, idx, 2);
                return Ok(true);
            }
            let imm = (insn >> 32) | ((hi >> 32) << 32);
            if res.validate && imm != res.orig_val {
                return Err(CoreReloError::UnexpectedValue {
                    insn_off: relo.insn_off,
                    expected: res.orig_val,
                    found: imm,
                });
            }
            instructions[idx] = (insn & !IMM_MASK) | ((res.new_val & 0xFFFF_FFFF) << 32);
            instructions[idx + 1] = (hi & !IMM_MASK) | ((res.new_val >> 32) << 32);
            Ok(false)
        }
        _ => Err(CoreReloError::UnpatchableInstruction(relo.insn_off)),
    }
}

fn poison_insn(instructions: &mut [u64], idx: usize, count: usize) {
    const BPF_CALL: u64 = 0x85;
    for slot in &mut instructions[idx..][..count] {
        *slot = BPF_CALL | (u64::from(CORE_POISON_HELPER) << 32);
    }
}

fn mem_size_bytes(opcode: u8) -> Option<u32> {
    match opcode & 0x18 {
        0x18 => Some(8),
        0x00 => Some(4),
        0x08 => Some(2),
        0x10 => Some(1),
        _ => None,
    }
}

fn bytes_to_mem_size(bytes: u32) -> Option<u8> {
    match bytes {
        8 => Some(0x18),
        4 => Some(0x00),
        2 => Some(0x08),
        1 => Some(0x10),
        _ => None,
    }
}

/// One step of a resolved access path: a named struct/union field, or an unnamed array index (including the implicit
/// `[idx]` on the root type).
struct Accessor {
    /// The field/array-element type (or, for an enum accessor, the enum type).
    type_id: u32,
    /// Field or array index.
    idx: u32,
    /// Field name, or `None` for an array accessor.
    name: Option<String>,
}

/// A parsed CO-RE access spec: libbpf's `bpf_core_spec`, minus the raw low-level path (we bound recursion depth with a
/// counter instead of a fixed-size array, see [`MAX_SPEC_DEPTH`]).
struct Spec {
    kind: CoreReloKind,
    /// For a local spec, `relo.type_id` unresolved; for a target spec, the matched candidate's ID unresolved. Either
    /// way this is what `TYPE_ID_TARGET`/`TYPE_SIZE` read back.
    root_type_id: u32,
    accessors: Vec<Accessor>,
    bit_offset: u64,
}

/// Matches libbpf's `BPF_CORE_SPEC_MAX_LEN`: how many struct/union/array levels (including ones hidden behind anonymous
/// members) a single access path may nest.
const MAX_SPEC_DEPTH: usize = 64;

/// Parse a relocation's access string against its local type (`bpf_core_parse_spec`).
fn parse_spec(local: &Btf<'_>, relo: &CoreRelo, access_str: &str) -> Result<Spec, CoreReloError> {
    if access_str.is_empty() || access_str.starts_with(':') {
        return Err(invalid_access(access_str));
    }

    if relo.kind.is_type_relo() {
        if access_str != "0" {
            return Err(invalid_access(access_str));
        }
        return Ok(Spec {
            kind: relo.kind,
            root_type_id: relo.type_id,
            accessors: Vec::new(),
            bit_offset: 0,
        });
    }

    let raw: Vec<u32> = access_str
        .split(':')
        .map(|s| s.parse::<u32>().map_err(|_| invalid_access(access_str)))
        .collect::<Result<_, _>>()?;

    let (mut id, root_t) = local
        .resolve_type(relo.type_id)
        .ok_or(CoreReloError::InvalidTypeId(relo.type_id))?;
    let root_idx = raw[0];

    if relo.kind.is_enum_relo() {
        if raw.len() > 1 {
            return Err(invalid_access(access_str));
        }
        let name = match root_t {
            BtfTypeInfo::Enum { variants, .. } => variants.get(root_idx as usize).map(|v| v.name),
            _ => return Err(invalid_access(access_str)),
        }
        .ok_or_else(|| invalid_access(access_str))?;
        return Ok(Spec {
            kind: relo.kind,
            root_type_id: relo.type_id,
            accessors: vec![Accessor {
                type_id: id,
                idx: root_idx,
                name: Some(name.to_string()),
            }],
            bit_offset: 0,
        });
    }

    let mut accessors = vec![Accessor {
        type_id: id,
        idx: root_idx,
        name: None,
    }];
    let mut bit_offset = elem_bits(root_idx, resolve_size(local, id)?).ok_or_else(|| invalid_access(access_str))?;

    for &idx in &raw[1..] {
        let (nid, t) = local.resolve_type(id).ok_or_else(|| invalid_access(access_str))?;
        id = nid;
        match t {
            BtfTypeInfo::Struct { members, .. } | BtfTypeInfo::Union { members, .. } => {
                let m = members.get(idx as usize).ok_or_else(|| invalid_access(access_str))?;
                bit_offset = bit_offset
                    .checked_add(u64::from(m.bit_offset))
                    .ok_or_else(|| invalid_access(access_str))?;
                if !m.name.is_empty() {
                    accessors.push(Accessor {
                        type_id: id,
                        idx,
                        name: Some(m.name.to_string()),
                    });
                }
                id = m.type_id;
            }
            BtfTypeInfo::Array { elem_type, nelems, .. } => {
                let (eid, _) = local
                    .resolve_type(*elem_type)
                    .ok_or_else(|| invalid_access(access_str))?;
                let flex = is_flex_array(local, accessors.last(), *nelems);
                if !flex && idx >= *nelems {
                    return Err(invalid_access(access_str));
                }
                accessors.push(Accessor {
                    type_id: eid,
                    idx,
                    name: None,
                });
                id = eid;
                bit_offset = elem_bits(idx, resolve_size(local, eid)?)
                    .and_then(|bits| bit_offset.checked_add(bits))
                    .ok_or_else(|| invalid_access(access_str))?;
            }
            _ => return Err(invalid_access(access_str)),
        }
    }

    Ok(Spec {
        kind: relo.kind,
        root_type_id: relo.type_id,
        accessors,
        bit_offset,
    })
}

fn invalid_access(access_str: &str) -> CoreReloError {
    CoreReloError::InvalidAccessString(access_str.to_string())
}

/// Bits spanned by `idx` elements of `size` bytes, or `None` past `u64::MAX`.
fn elem_bits(idx: u32, size: u64) -> Option<u64> {
    u64::from(idx).checked_mul(size)?.checked_mul(8)
}

/// A trailing, size-0 array that is the last member of its enclosing struct: clang's encoding of a C flexible array
/// member, which isn't bounds-checked against `nelems`.
fn is_flex_array(btf: &Btf<'_>, prev: Option<&Accessor>, nelems: u32) -> bool {
    let Some(prev) = prev else { return false };
    if prev.name.is_none() || nelems > 0 {
        return false;
    }
    let Some(owner) = btf.type_by_id(prev.type_id) else {
        return false;
    };
    let Some(members) = members_of(owner) else { return false };
    prev.idx as usize + 1 == members.len()
}

/// Find every type in `target` with the same essential name (and a compatible kind) as `local`'s root type: libbpf's
/// `bpf_core_add_cands`.
fn find_candidates(target: &Btf<'_>, local_name: &str, local_kind: BtfKind) -> Vec<u32> {
    target
        .types()
        .filter_map(|(id, t)| {
            let name = t.name().unwrap_or("");
            let eligible = !name.is_empty() && kind_core_compat(t.kind(), local_kind) && names_match(name, local_name);
            eligible.then_some(id)
        })
        .collect()
}

/// Try to match a local spec against one target candidate, producing the equivalent target spec on success
/// (`bpf_core_spec_match`). `Ok(None)` means the candidate doesn't match; errors are malformed BTF, not mismatches.
fn spec_match(
    local: &Btf<'_>,
    local_spec: &Spec,
    target: &Btf<'_>,
    cand_id: u32,
) -> Result<Option<Spec>, CoreReloError> {
    let kind = local_spec.kind;

    if kind.is_type_relo() {
        let matched = if kind == CoreReloKind::TypeMatches {
            types_match(local, local_spec.root_type_id, target, cand_id)?
        } else {
            types_are_compat(local, local_spec.root_type_id, target, cand_id)?
        };
        return Ok(matched.then(|| Spec {
            kind,
            root_type_id: cand_id,
            accessors: Vec::new(),
            bit_offset: 0,
        }));
    }

    if kind.is_enum_relo() {
        return match_enumval(local_spec, target, cand_id);
    }

    let mut targ_id = cand_id;
    let mut spec = Spec {
        kind,
        root_type_id: cand_id,
        accessors: Vec::new(),
        bit_offset: 0,
    };
    let mut depth = 0usize;

    for (i, local_acc) in local_spec.accessors.iter().enumerate() {
        let (tid, tt) = target
            .resolve_type(targ_id)
            .ok_or(CoreReloError::InvalidTypeId(targ_id))?;
        targ_id = tid;

        if let Some(name) = local_acc.name.as_deref() {
            match match_member(local, local_acc, name, target, targ_id, &mut spec, &mut depth)? {
                Some(next) => targ_id = next,
                None => return Ok(None),
            }
            continue;
        }

        if i > 0 {
            let BtfTypeInfo::Array { elem_type, nelems, .. } = tt else {
                return Ok(None);
            };
            let flex = is_flex_array(target, spec.accessors.last(), *nelems);
            if !flex && local_acc.idx >= *nelems {
                return Ok(None);
            }
            let (eid, _) = target
                .resolve_type(*elem_type)
                .ok_or(CoreReloError::InvalidTypeId(*elem_type))?;
            targ_id = eid;
        }

        depth += 1;
        if depth > MAX_SPEC_DEPTH {
            return Err(CoreReloError::SpecTooDeep);
        }
        spec.accessors.push(Accessor {
            type_id: targ_id,
            idx: local_acc.idx,
            name: None,
        });
        // a local index can place the element past the end of the target's address space
        let bits = elem_bits(local_acc.idx, resolve_size(target, targ_id)?);
        let Some(bit_offset) = bits.and_then(|bits| spec.bit_offset.checked_add(bits)) else {
            return Ok(None);
        };
        spec.bit_offset = bit_offset;
    }

    Ok(Some(spec))
}

/// Find a target enum variant with the same essential name as the local one (`bpf_core_spec_match`'s enum-value
/// branch).
fn match_enumval(local_spec: &Spec, target: &Btf<'_>, cand_id: u32) -> Result<Option<Spec>, CoreReloError> {
    let (resolved_id, t) = target
        .resolve_type(cand_id)
        .ok_or(CoreReloError::InvalidTypeId(cand_id))?;
    let names: Vec<&str> = match t {
        BtfTypeInfo::Enum { variants, .. } => variants.iter().map(|v| v.name).collect(),
        _ => return Ok(None),
    };

    let local_name = local_spec.accessors[0].name.as_deref().unwrap_or("");
    for (i, name) in names.into_iter().enumerate() {
        if !names_match(name, local_name) {
            continue;
        }
        return Ok(Some(Spec {
            kind: local_spec.kind,
            root_type_id: cand_id,
            accessors: vec![Accessor {
                type_id: resolved_id,
                idx: i as u32,
                name: Some(name.to_string()),
            }],
            bit_offset: 0,
        }));
    }
    Ok(None)
}

/// Find a target struct/union member matching `local_name`, recursing into anonymous members (`bpf_core_match_member`).
/// Returns the member's type ID on success.
fn match_member(
    local: &Btf<'_>,
    local_acc: &Accessor,
    local_name: &str,
    target: &Btf<'_>,
    targ_id: u32,
    spec: &mut Spec,
    depth: &mut usize,
) -> Result<Option<u32>, CoreReloError> {
    let (owner_id, targ_t) = target
        .resolve_type(targ_id)
        .ok_or(CoreReloError::InvalidTypeId(targ_id))?;
    let Some(targ_members) = members_of(targ_t) else {
        return Ok(None);
    };

    let local_owner = local
        .type_by_id(local_acc.type_id)
        .ok_or(CoreReloError::InvalidTypeId(local_acc.type_id))?;
    let local_member = members_of(local_owner)
        .and_then(|m| m.get(local_acc.idx as usize))
        .ok_or(CoreReloError::InvalidTypeId(local_acc.type_id))?;

    for (i, m) in targ_members.iter().enumerate() {
        *depth += 1;
        if *depth > MAX_SPEC_DEPTH {
            return Err(CoreReloError::SpecTooDeep);
        }
        let Some(bit_offset) = spec.bit_offset.checked_add(u64::from(m.bit_offset)) else {
            *depth -= 1;
            continue;
        };
        spec.bit_offset = bit_offset;

        let found = if m.name.is_empty() {
            match_member(local, local_acc, local_name, target, m.type_id, spec, depth)?
        } else if m.name == local_name && fields_are_compat(local, local_member.type_id, target, m.type_id)? {
            spec.accessors.push(Accessor {
                type_id: owner_id,
                idx: i as u32,
                name: Some(m.name.to_string()),
            });
            Some(m.type_id)
        } else {
            None
        };

        if found.is_some() {
            return Ok(found);
        }
        spec.bit_offset -= u64::from(m.bit_offset);
        *depth -= 1;
    }
    Ok(None)
}

/// A relocation's value for one side (local or a matched target candidate): libbpf's
/// `bpf_core_calc_field_relo`/`_type_relo`/`_enumval_relo`, combined.
struct Half {
    val: u64,
    validate: bool,
    /// For `FieldByteOffset`, the memory access size and type the instruction reads.
    mem: Option<(u32, u32)>,
}

fn calc_half(kind: CoreReloKind, spec: &Spec, btf: &Btf<'_>) -> Result<Half, CoreReloError> {
    if kind.is_field_relo() {
        calc_field_half(kind, spec, btf)
    } else if kind.is_type_relo() {
        calc_type_half(kind, spec, btf)
    } else {
        calc_enumval_half(kind, spec, btf)
    }
}

fn calc_field_half(kind: CoreReloKind, spec: &Spec, btf: &Btf<'_>) -> Result<Half, CoreReloError> {
    if kind == CoreReloKind::FieldExists {
        return Ok(Half {
            val: 1,
            validate: true,
            mem: None,
        });
    }

    let acc = spec
        .accessors
        .last()
        .expect("a field spec always has at least its root accessor");

    let Some(_) = &acc.name else {
        return match kind {
            CoreReloKind::FieldByteOffset => {
                let elem_id = unwrap_arrays(btf, acc.type_id)?;
                let sz = resolve_size(btf, elem_id)? as u32;
                Ok(Half {
                    val: spec.bit_offset / 8,
                    validate: true,
                    mem: Some((sz, elem_id)),
                })
            }
            CoreReloKind::FieldByteSize => Ok(Half {
                val: resolve_size(btf, acc.type_id)?,
                validate: true,
                mem: None,
            }),
            _ => Err(CoreReloError::UnsupportedRelo(kind)),
        };
    };

    let owner = btf
        .type_by_id(acc.type_id)
        .ok_or(CoreReloError::InvalidTypeId(acc.type_id))?;
    let m = members_of(owner)
        .and_then(|members| members.get(acc.idx as usize))
        .ok_or(CoreReloError::InvalidTypeId(acc.type_id))?;
    let (field_type_id, field_t) = btf
        .resolve_type(m.type_id)
        .ok_or(CoreReloError::InvalidTypeId(m.type_id))?;

    let bit_off = spec.bit_offset;
    let is_bitfield = m.bitfield_size > 0;
    let (byte_sz, byte_off, bit_sz) = if is_bitfield {
        let size = field_t.size().filter(|&size| size != 0);
        let mut byte_sz = u64::from(size.ok_or(CoreReloError::InvalidTypeId(field_type_id))?);
        let mut byte_off = bit_off / 8 / byte_sz * byte_sz;
        while bit_off - byte_off * 8 + u64::from(m.bitfield_size) > byte_sz * 8 {
            if byte_sz >= 8 {
                return Err(CoreReloError::BitfieldTooWide);
            }
            byte_sz *= 2;
            byte_off = bit_off / 8 / byte_sz * byte_sz;
        }
        (byte_sz as u32, byte_off, u64::from(m.bitfield_size))
    } else {
        let sz = resolve_size(btf, field_type_id)? as u32;
        (sz, bit_off / 8, u64::from(sz) * 8)
    };
    // Bitfields are ambiguous about which exact bytes the compiler loads, so only signedness (checked explicitly below)
    // is validated against the instruction.
    let validate = !is_bitfield;

    match kind {
        CoreReloKind::FieldByteOffset => {
            let mem = (!is_bitfield)
                .then(|| unwrap_arrays(btf, field_type_id).and_then(|eid| Ok((resolve_size(btf, eid)? as u32, eid))))
                .transpose()?;
            Ok(Half {
                val: byte_off,
                validate,
                mem,
            })
        }
        CoreReloKind::FieldByteSize => Ok(Half {
            val: u64::from(byte_sz),
            validate,
            mem: None,
        }),
        CoreReloKind::FieldSigned => {
            let signed = match field_t {
                BtfTypeInfo::Enum { is_signed, .. } => *is_signed,
                BtfTypeInfo::Int { encoding, .. } => encoding & BTF_INT_SIGNED != 0,
                _ => false,
            };
            Ok(Half {
                val: u64::from(signed),
                validate: true,
                mem: None,
            })
        }
        // Unsigned wraparound for fields wider than 64 bits, as in libbpf.
        CoreReloKind::FieldLShiftU64 => Ok(Half {
            val: 64u64.wrapping_sub(bit_off - byte_off * 8 + bit_sz),
            validate,
            mem: None,
        }),
        CoreReloKind::FieldRShiftU64 => Ok(Half {
            val: 64u64.wrapping_sub(bit_sz),
            validate: true,
            mem: None,
        }),
        _ => unreachable!("FieldExists handled above; the rest are filtered by is_field_relo"),
    }
}

fn calc_type_half(kind: CoreReloKind, spec: &Spec, btf: &Btf<'_>) -> Result<Half, CoreReloError> {
    match kind {
        CoreReloKind::TypeIdTarget => {
            // The type ID embedded in the instruction can change again during linking, so it's never validated against
            // what's already there.
            Ok(Half {
                val: u64::from(spec.root_type_id),
                validate: false,
                mem: None,
            })
        }
        CoreReloKind::TypeExists | CoreReloKind::TypeMatches => Ok(Half {
            val: 1,
            validate: true,
            mem: None,
        }),
        CoreReloKind::TypeSize => Ok(Half {
            val: resolve_size(btf, spec.root_type_id)?,
            validate: true,
            mem: None,
        }),
        _ => unreachable!("TypeIdLocal is resolved before candidate search"),
    }
}

fn calc_enumval_half(kind: CoreReloKind, spec: &Spec, btf: &Btf<'_>) -> Result<Half, CoreReloError> {
    match kind {
        CoreReloKind::EnumvalExists => Ok(Half {
            val: 1,
            validate: true,
            mem: None,
        }),
        CoreReloKind::EnumvalValue => {
            let acc = &spec.accessors[0];
            let t = btf
                .type_by_id(acc.type_id)
                .ok_or(CoreReloError::InvalidTypeId(acc.type_id))?;
            let val = match t {
                BtfTypeInfo::Enum { variants, .. } => variants.get(acc.idx as usize).map(|v| v.value as u64),
                _ => None,
            }
            .ok_or(CoreReloError::InvalidTypeId(acc.type_id))?;
            Ok(Half {
                val,
                validate: true,
                mem: None,
            })
        }
        _ => unreachable!("only enum-based kinds reach here"),
    }
}

/// Follow nested array element types down to the innermost non-array type: the memory access size CO-RE cares about for
/// arrays is always the element's, never the array's.
fn unwrap_arrays(btf: &Btf<'_>, id: u32) -> Result<u32, CoreReloError> {
    let (mut id, mut t) = btf.resolve_type(id).ok_or(CoreReloError::InvalidTypeId(id))?;
    for _ in 0..=MAX_RESOLVE_DEPTH {
        let BtfTypeInfo::Array { elem_type, .. } = t else {
            return Ok(id);
        };
        (id, t) = btf
            .resolve_type(*elem_type)
            .ok_or(CoreReloError::InvalidTypeId(*elem_type))?;
    }
    Err(CoreReloError::SpecTooDeep)
}

/// Byte size of a type, resolving through typedefs/modifiers/arrays, like libbpf's `btf__resolve_size`.
fn resolve_size(btf: &Btf<'_>, id: u32) -> Result<u64, CoreReloError> {
    btf.resolve_size(id).ok_or(CoreReloError::InvalidTypeId(id))
}

fn members_of<'a, 'b>(t: &'b BtfTypeInfo<'a>) -> Option<&'b [Member<'a>]> {
    match t {
        BtfTypeInfo::Struct { members, .. } | BtfTypeInfo::Union { members, .. } => Some(members),
        _ => None,
    }
}

fn is_composite(k: BtfKind) -> bool {
    matches!(k, BtfKind::Struct | BtfKind::Union)
}

fn is_any_enum(k: BtfKind) -> bool {
    matches!(k, BtfKind::Enum | BtfKind::Enum64)
}

/// `btf_kind_core_compat`: struct and union are never interchangeable for candidate search, but 32- and 64-bit enums
/// are.
fn kind_core_compat(a: BtfKind, b: BtfKind) -> bool {
    a == b || (is_any_enum(a) && is_any_enum(b))
}

/// `X___Y` flavor separator: `X` and `Y` must themselves not start/end with an underscore.
fn is_flavor_sep(s: &[u8]) -> bool {
    s.len() >= 5 && s[0] != b'_' && s[1] == b'_' && s[2] == b'_' && s[3] == b'_' && s[4] != b'_'
}

/// Length of a type name before its last `___flavor` suffix, or the whole name if it has none
/// (`bpf_core_essential_name_len`).
fn essential_name_len(name: &str) -> usize {
    let bytes = name.as_bytes();
    if bytes.len() < 5 {
        return bytes.len();
    }
    (0..=bytes.len() - 5)
        .rev()
        .find(|&i| is_flavor_sep(&bytes[i..]))
        .map_or(bytes.len(), |i| i + 1)
}

/// Two type/field names match if they have the same name ignoring flavor suffixes (`bpf_core_names_match`); two empty
/// (anonymous) names also match each other.
fn names_match(a: &str, b: &str) -> bool {
    let la = essential_name_len(a);
    let lb = essential_name_len(b);
    la == lb && a.as_bytes()[..la] == b.as_bytes()[..lb]
}

/// Whether a local and target name match for `FWD`/`ENUM` field-type compatibility: either side being anonymous is
/// itself a match, since an anonymous enum or forward declaration is compatible with anything of the same kind.
fn fwd_or_enum_names_match(a: &str, b: &str) -> bool {
    essential_name_len(a) == 0 || essential_name_len(b) == 0 || names_match(a, b)
}

/// Whether a local field and a target field of the given types can be relocated onto each other
/// (`bpf_core_fields_are_compat`): looser than [`types_match`], e.g. any two structs (or two pointers, or two floats)
/// are compatible regardless of their contents.
fn fields_are_compat(
    local: &Btf<'_>,
    mut local_id: u32,
    target: &Btf<'_>,
    mut targ_id: u32,
) -> Result<bool, CoreReloError> {
    let mut depth = 32i32;
    loop {
        depth -= 1;
        if depth < 0 {
            return Err(CoreReloError::SpecTooDeep);
        }
        let (_, lt) = local
            .resolve_type(local_id)
            .ok_or(CoreReloError::InvalidTypeId(local_id))?;
        let (_, tt) = target
            .resolve_type(targ_id)
            .ok_or(CoreReloError::InvalidTypeId(targ_id))?;

        if is_composite(lt.kind()) && is_composite(tt.kind()) {
            return Ok(true);
        }
        if !kind_core_compat(lt.kind(), tt.kind()) {
            return Ok(false);
        }

        match lt {
            BtfTypeInfo::Ptr { .. } | BtfTypeInfo::Float { .. } => return Ok(true),
            BtfTypeInfo::Fwd { name, .. } | BtfTypeInfo::Enum { name, .. } => {
                return Ok(fwd_or_enum_names_match(name, tt.name().unwrap_or("")));
            }
            BtfTypeInfo::Int { offset, .. } => {
                let BtfTypeInfo::Int {
                    offset: targ_offset, ..
                } = tt
                else {
                    unreachable!()
                };
                return Ok(*offset == 0 && *targ_offset == 0);
            }
            BtfTypeInfo::Array { elem_type, .. } => {
                let BtfTypeInfo::Array {
                    elem_type: targ_elem, ..
                } = tt
                else {
                    unreachable!()
                };
                local_id = *elem_type;
                targ_id = *targ_elem;
            }
            _ => return Ok(false),
        }
    }
}

/// Whether a local and target type are compatible for `TYPE_ID_TARGET`/`TYPE_EXISTS`/`TYPE_SIZE`
/// (`bpf_core_types_are_compat`): same shallow checks as [`fields_are_compat`] but entered via a kind check on the
/// *un*resolved root types, and recursing through function pointers too.
fn types_are_compat(local: &Btf<'_>, local_id: u32, target: &Btf<'_>, targ_id: u32) -> Result<bool, CoreReloError> {
    let lt0 = local
        .type_by_id(local_id)
        .ok_or(CoreReloError::InvalidTypeId(local_id))?;
    let tt0 = target
        .type_by_id(targ_id)
        .ok_or(CoreReloError::InvalidTypeId(targ_id))?;
    if !kind_core_compat(lt0.kind(), tt0.kind()) {
        return Ok(false);
    }
    types_are_compat_at(local, local_id, target, targ_id, 32)
}

fn types_are_compat_at(
    local: &Btf<'_>,
    mut local_id: u32,
    target: &Btf<'_>,
    mut targ_id: u32,
    level: i32,
) -> Result<bool, CoreReloError> {
    let mut depth = 32i32;
    loop {
        depth -= 1;
        if depth < 0 {
            return Err(CoreReloError::SpecTooDeep);
        }
        let (_, lt) = local
            .resolve_type(local_id)
            .ok_or(CoreReloError::InvalidTypeId(local_id))?;
        let (_, tt) = target
            .resolve_type(targ_id)
            .ok_or(CoreReloError::InvalidTypeId(targ_id))?;
        if !kind_core_compat(lt.kind(), tt.kind()) {
            return Ok(false);
        }

        match lt {
            BtfTypeInfo::Void
            | BtfTypeInfo::Struct { .. }
            | BtfTypeInfo::Union { .. }
            | BtfTypeInfo::Enum { .. }
            | BtfTypeInfo::Fwd { .. } => return Ok(true),
            BtfTypeInfo::Int { offset, .. } => {
                let BtfTypeInfo::Int {
                    offset: targ_offset, ..
                } = tt
                else {
                    unreachable!()
                };
                return Ok(*offset == 0 && *targ_offset == 0);
            }
            BtfTypeInfo::Ptr { pointee_type } => {
                let BtfTypeInfo::Ptr {
                    pointee_type: targ_pointee,
                } = tt
                else {
                    unreachable!()
                };
                local_id = *pointee_type;
                targ_id = *targ_pointee;
            }
            BtfTypeInfo::Array { elem_type, .. } => {
                let BtfTypeInfo::Array {
                    elem_type: targ_elem, ..
                } = tt
                else {
                    unreachable!()
                };
                local_id = *elem_type;
                targ_id = *targ_elem;
            }
            BtfTypeInfo::FuncProto { return_type, params } => {
                let BtfTypeInfo::FuncProto {
                    return_type: targ_return,
                    params: targ_params,
                } = tt
                else {
                    unreachable!()
                };
                if params.len() != targ_params.len() {
                    return Ok(false);
                }
                if level <= 0 {
                    return Err(CoreReloError::SpecTooDeep);
                }
                for (p, targ_p) in params.iter().zip(targ_params.iter()) {
                    let (pid, _) = local
                        .resolve_type(p.type_id)
                        .ok_or(CoreReloError::InvalidTypeId(p.type_id))?;
                    let (targ_pid, _) = target
                        .resolve_type(targ_p.type_id)
                        .ok_or(CoreReloError::InvalidTypeId(targ_p.type_id))?;
                    if !types_are_compat_at(local, pid, target, targ_pid, level - 1)? {
                        return Ok(false);
                    }
                }
                local_id = *return_type;
                targ_id = *targ_return;
            }
            _ => return Ok(false),
        }
    }
}

/// Whether a local and target type structurally match for `TYPE_MATCHES` (`__bpf_core_types_match`): unlike
/// [`types_are_compat`], member names (modulo flavor suffix) are checked recursively and enums must agree in size and
/// enumerator names, though only shallowly once behind a pointer (to avoid chasing self-referential structs forever).
fn types_match(local: &Btf<'_>, local_id: u32, target: &Btf<'_>, targ_id: u32) -> Result<bool, CoreReloError> {
    types_match_at(local, local_id, target, targ_id, false, 32)
}

fn types_match_at(
    local: &Btf<'_>,
    mut local_id: u32,
    target: &Btf<'_>,
    mut targ_id: u32,
    mut behind_ptr: bool,
    level: i32,
) -> Result<bool, CoreReloError> {
    if level <= 0 {
        return Err(CoreReloError::SpecTooDeep);
    }
    let mut depth = 32i32;
    loop {
        depth -= 1;
        if depth < 0 {
            return Err(CoreReloError::SpecTooDeep);
        }
        let (_, lt) = local
            .resolve_type(local_id)
            .ok_or(CoreReloError::InvalidTypeId(local_id))?;
        let (_, tt) = target
            .resolve_type(targ_id)
            .ok_or(CoreReloError::InvalidTypeId(targ_id))?;
        if !names_match(lt.name().unwrap_or(""), tt.name().unwrap_or("")) {
            return Ok(false);
        }
        let (lk, tk) = (lt.kind(), tt.kind());

        match lt {
            BtfTypeInfo::Void => return Ok(lk == tk),
            BtfTypeInfo::Fwd {
                is_union: local_union, ..
            } => {
                let BtfTypeInfo::Fwd {
                    is_union: targ_union, ..
                } = tt
                else {
                    return Ok(if behind_ptr {
                        (tk == BtfKind::Struct && !local_union) || (tk == BtfKind::Union && *local_union)
                    } else {
                        false
                    });
                };
                return Ok(local_union == targ_union);
            }
            BtfTypeInfo::Enum { .. } => {
                return Ok(is_any_enum(tk) && enums_match(lt, tt));
            }
            BtfTypeInfo::Struct { .. } | BtfTypeInfo::Union { .. } => {
                if behind_ptr {
                    if lk == tk {
                        return Ok(true);
                    }
                    let BtfTypeInfo::Fwd {
                        is_union: targ_union, ..
                    } = tt
                    else {
                        return Ok(false);
                    };
                    return Ok((lk == BtfKind::Union) == *targ_union);
                }
                if lk != tk {
                    return Ok(false);
                }
                return composites_match(local, lt, target, tt, behind_ptr, level);
            }
            BtfTypeInfo::Int { size, encoding, .. } => {
                let BtfTypeInfo::Int {
                    size: targ_size,
                    encoding: targ_encoding,
                    ..
                } = tt
                else {
                    return Ok(false);
                };
                return Ok(size == targ_size && (encoding & BTF_INT_SIGNED) == (targ_encoding & BTF_INT_SIGNED));
            }
            BtfTypeInfo::Ptr { pointee_type } => {
                let BtfTypeInfo::Ptr {
                    pointee_type: targ_pointee,
                } = tt
                else {
                    return Ok(false);
                };
                behind_ptr = true;
                local_id = *pointee_type;
                targ_id = *targ_pointee;
            }
            BtfTypeInfo::Array { elem_type, nelems, .. } => {
                let BtfTypeInfo::Array {
                    elem_type: targ_elem,
                    nelems: targ_nelems,
                    ..
                } = tt
                else {
                    return Ok(false);
                };
                if nelems != targ_nelems {
                    return Ok(false);
                }
                local_id = *elem_type;
                targ_id = *targ_elem;
            }
            BtfTypeInfo::FuncProto { return_type, params } => {
                let BtfTypeInfo::FuncProto {
                    return_type: targ_return,
                    params: targ_params,
                } = tt
                else {
                    return Ok(false);
                };
                if params.len() != targ_params.len() {
                    return Ok(false);
                }
                for (p, targ_p) in params.iter().zip(targ_params.iter()) {
                    if !types_match_at(local, p.type_id, target, targ_p.type_id, behind_ptr, level - 1)? {
                        return Ok(false);
                    }
                }
                local_id = *return_type;
                targ_id = *targ_return;
            }
            _ => return Ok(false),
        }
    }
}

fn composites_match(
    local: &Btf<'_>,
    local_t: &BtfTypeInfo<'_>,
    target: &Btf<'_>,
    targ_t: &BtfTypeInfo<'_>,
    behind_ptr: bool,
    level: i32,
) -> Result<bool, CoreReloError> {
    let local_members = members_of(local_t).expect("caller checked both types are struct/union");
    let targ_members = members_of(targ_t).expect("caller checked both types are struct/union");
    if local_members.len() > targ_members.len() {
        return Ok(false);
    }
    for lm in local_members {
        let mut matched = false;
        for tm in targ_members {
            if !names_match(lm.name, tm.name) {
                continue;
            }
            if types_match_at(local, lm.type_id, target, tm.type_id, behind_ptr, level - 1)? {
                matched = true;
                break;
            }
        }
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

fn enums_match(local_t: &BtfTypeInfo<'_>, targ_t: &BtfTypeInfo<'_>) -> bool {
    fn parts<'a>(t: &'a BtfTypeInfo<'_>) -> Option<(u32, Vec<&'a str>)> {
        match t {
            BtfTypeInfo::Enum { size, variants, .. } => Some((*size, variants.iter().map(|v| v.name).collect())),
            _ => None,
        }
    }
    let Some((local_size, local_names)) = parts(local_t) else {
        return false;
    };
    let Some((targ_size, targ_names)) = parts(targ_t) else {
        return false;
    };
    local_size == targ_size
        && local_names.len() <= targ_names.len()
        && local_names
            .iter()
            .all(|ln| targ_names.iter().any(|tn| names_match(ln, tn)))
}
