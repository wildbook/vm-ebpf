//! End-to-end CO-RE relocation tests: a local (compile-time) BTF is relocated against a
//! target (host) BTF, exactly like a BPF program's debug info gets relocated against the
//! kernel's BTF. Both are hand-encoded with [`TestBtf`] so each test controls, and can
//! hand-derive, the exact offsets/values the relocation must produce.

use crate::core_relo::{apply_core_relocations, CoreRelo, CoreReloError, CoreReloKind, Unresolved, CORE_POISON_HELPER};
use crate::parse::Btf;
use crate::raw::{BTF_MAGIC, BTF_VERSION};

/// Minimal BTF encoder: each method appends one type and returns its ID (IDs start at 1,
/// matching [`Btf::parse`]'s numbering).
#[derive(Default)]
struct TestBtf {
    strings: Vec<u8>,
    types: Vec<u32>,
    next_id: u32,
}

/// A struct/union member: name, member type ID, bit offset.
type Field<'a> = (&'a str, u32, u32);
/// A bitfield member: name, member type ID, bit offset, bit size.
type Bitfield<'a> = (&'a str, u32, u32, u32);

impl TestBtf {
    fn new() -> Self {
        Self { strings: vec![0], next_id: 1, types: Vec::new() }
    }

    fn name(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0);
        off
    }

    fn push(&mut self, name_off: u32, info: u32, size_or_type: u32, extra: &[u32]) -> u32 {
        self.types.push(name_off);
        self.types.push(info);
        self.types.push(size_or_type);
        self.types.extend_from_slice(extra);
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn int(&mut self, name: &str, size: u32, signed: bool) -> u32 {
        let n = self.name(name);
        let enc = u32::from(signed);
        self.push(n, 1 << 24, size, &[(enc << 24) | (size * 8)])
    }

    fn array(&mut self, elem: u32, nelems: u32) -> u32 {
        self.push(0, 3 << 24, 0, &[elem, 0, nelems])
    }

    fn composite(&mut self, kind: u32, kind_flag: bool, name: &str, size: u32, members: &[u32]) -> u32 {
        let n = self.name(name);
        let vlen = (members.len() / 3) as u32;
        let info = (kind << 24) | (u32::from(kind_flag) << 31) | vlen;
        self.push(n, info, size, members)
    }

    fn struct_(&mut self, name: &str, size: u32, fields: &[Field<'_>]) -> u32 {
        let mut members = Vec::new();
        for (fname, ftype, boff) in fields {
            let n = self.name(fname);
            members.extend_from_slice(&[n, *ftype, *boff]);
        }
        self.composite(4, false, name, size, &members)
    }

    fn union_(&mut self, name: &str, size: u32, fields: &[Field<'_>]) -> u32 {
        let mut members = Vec::new();
        for (fname, ftype, boff) in fields {
            let n = self.name(fname);
            members.extend_from_slice(&[n, *ftype, *boff]);
        }
        self.composite(5, false, name, size, &members)
    }

    fn bitfield_struct(&mut self, name: &str, size: u32, fields: &[Bitfield<'_>]) -> u32 {
        let mut members = Vec::new();
        for (fname, ftype, boff, bsz) in fields {
            let n = self.name(fname);
            members.extend_from_slice(&[n, *ftype, (bsz << 24) | boff]);
        }
        self.composite(4, true, name, size, &members)
    }

    fn enum_(&mut self, name: &str, variants: &[(&str, i32)]) -> u32 {
        let n = self.name(name);
        let mut extra = Vec::new();
        for (vname, val) in variants {
            let vn = self.name(vname);
            extra.push(vn);
            extra.push(*val as u32);
        }
        self.push(n, (6 << 24) | variants.len() as u32, 4, &extra)
    }

    fn encode(&self) -> Vec<u8> {
        let types: Vec<u8> = self.types.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut btf = Vec::new();
        btf.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        btf.extend_from_slice(&[BTF_VERSION, 0]);
        for w in [24, 0, types.len() as u32, types.len() as u32, self.strings.len() as u32] {
            btf.extend_from_slice(&w.to_le_bytes());
        }
        btf.extend_from_slice(&types);
        btf.extend_from_slice(&self.strings);
        btf
    }
}

/// Encode a single `CoreRelo` whose access string is appended to a scratch `TestBtf`'s
/// string table (CO-RE access strings live in the *local* BTF's strings).
fn relo(local: &mut TestBtf, type_id: u32, access_str: &str, kind: CoreReloKind) -> CoreRelo {
    let access_str_off = local.name(access_str);
    CoreRelo { insn_off: 0, type_id, access_str_off, kind }
}

fn insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    u64::from(opcode) | u64::from(dst) << 8 | u64::from(src) << 12 | u64::from(off as u16) << 16 | u64::from(imm as u32) << 32
}

fn off_of(i: u64) -> i16 {
    (i >> 16) as u16 as i16
}

fn imm_of(i: u64) -> i32 {
    (i >> 32) as u32 as i32
}

const LDX_W: u8 = 0x61; // BPF_LDX | BPF_MEM | BPF_W
const ALU64_MOV_K: u8 = 0xb7; // BPF_ALU64 | BPF_MOV | BPF_K

/// A field moving to a new offset in the target patches the instruction's `off`.
#[test]
fn moved_field_offset() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let event = local.struct_("event", 8, &[("ts", int_ty, 0), ("pid", int_ty, 32)]);
    let r = relo(&mut local, event, "0:1", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    // Host's "event" has an extra field between ts and pid, pushing pid from byte 4 to byte 8.
    target.struct_("event", 12, &[("ts", t_int, 0), ("extra", t_int, 32), ("pid", t_int, 64)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 4, 0)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert!(unresolved.is_empty());
    assert_eq!(off_of(insns[0]), 8);
}

/// A field nested inside a target-only anonymous union is still found by name, and its
/// offset includes the anonymous union's own offset.
#[test]
fn nested_anonymous_member() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let s = local.struct_("anonish", 4, &[("val", int_ty, 0)]);
    let r = relo(&mut local, s, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    // `val` lives inside an anonymous union starting at byte 4, alongside `padding`.
    let anon_union = target.union_("", 4, &[("padding", t_int, 0), ("val", t_int, 0)]);
    target.struct_("anonish", 8, &[("other", t_int, 0), ("", anon_union, 32)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(off_of(insns[0]), 4);
}

/// Array element access follows the target's own array offset and element size.
#[test]
fn array_element_offset() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let arr = local.array(int_ty, 4);
    let s = local.struct_("withArr", 20, &[("before", int_ty, 0), ("items", arr, 32)]);
    let r = relo(&mut local, s, "0:1:2", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    let t_arr = target.array(t_int, 4);
    // Host inserted a padding field before the array, moving it from byte 4 to byte 8.
    target.struct_("withArr", 24, &[("before", t_int, 0), ("pad", t_int, 32), ("items", t_arr, 64)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 12, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(off_of(insns[0]), 16); // 8 (array start) + 2 * 4 (element size)
}

/// Bitfield relocations extract the exact bits libbpf's formulas derive, not just the
/// right byte offset.
#[test]
fn bitfield_signed_and_shifts() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    // `v` occupies bits [3, 8) of a 4-byte int: byte_sz=4, byte_off=0.
    let s = local.bitfield_struct("flags", 4, &[("v", int_ty, 3, 5)]);
    let r_signed = relo(&mut local, s, "0:0", CoreReloKind::FieldSigned);
    let r_rshift = relo(&mut local, s, "0:0", CoreReloKind::FieldRShiftU64);
    let r_lshift = relo(&mut local, s, "0:0", CoreReloKind::FieldLShiftU64);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    // `v` occupies bits [20, 25) of a 4-byte int: byte_sz=4, byte_off=0.
    target.bitfield_struct("flags", 4, &[("v", t_int, 20, 5)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    // FieldSigned: both local and target `v` are signed ints -> 1, same on both sides.
    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_signed]).unwrap();
    assert_eq!(imm_of(insns[0]), 1);

    // FieldRShiftU64 = 64 - bit_size, independent of bit_offset -> 59 on both sides.
    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 59)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_rshift]).unwrap();
    assert_eq!(imm_of(insns[0]), 59);

    // FieldLShiftU64 = 64 - (bit_off + bit_size - byte_off*8): 56 locally, 39 on the target;
    // bitfields are never validated against the instruction's current value, so the
    // starting imm is irrelevant here.
    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_lshift]).unwrap();
    assert_eq!(imm_of(insns[0]), 39);
}

/// A field whose unsigned integer type widened gets its `LDX` memory access size adjusted;
/// the same change on a signed field poisons rather than risk sign-extending wrongly.
#[test]
fn size_change_adjusts_or_poisons_memory_access() {
    let mut local = TestBtf::new();
    let u32_ty = local.int("unsigned int", 4, false);
    let i32_ty = local.int("int", 4, true);
    let safe = local.struct_("safe", 4, &[("count", u32_ty, 0)]);
    let unsafe_ = local.struct_("unsafe", 4, &[("count", i32_ty, 0)]);
    let r_safe = relo(&mut local, safe, "0:0", CoreReloKind::FieldByteOffset);
    let r_unsafe = relo(&mut local, unsafe_, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let u64_ty = target.int("unsigned long", 8, false);
    let i64_ty = target.int("long", 8, true);
    target.struct_("safe", 8, &[("count", u64_ty, 0)]);
    target.struct_("unsafe", 8, &[("count", i64_ty, 0)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_safe]).unwrap();
    assert!(unresolved.is_empty());
    assert_eq!(off_of(insns[0]), 0);
    assert_eq!(insns[0] as u8 & 0x18, 0x18, "mem size should widen from W to DW");

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_unsafe]).unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(insns[0], 0x85 | u64::from(CORE_POISON_HELPER) << 32);
}

/// A target type with a `___flavor` suffix is still found by its essential name.
#[test]
fn flavor_suffix_matching() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let cfg = local.struct_("cfg", 4, &[("limit", int_ty, 0)]);
    let r = relo(&mut local, cfg, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    target.struct_("cfg___v2", 8, &[("pad", t_int, 0), ("limit", t_int, 32)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(off_of(insns[0]), 4);
}

/// Two target flavors that disagree on where a field landed make the relocation ambiguous.
#[test]
fn ambiguous_candidates_error() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let cfg = local.struct_("cfg", 4, &[("limit", int_ty, 0)]);
    let r = relo(&mut local, cfg, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    target.struct_("cfg", 4, &[("limit", t_int, 0)]);
    target.struct_("cfg___dup", 8, &[("pad", t_int, 0), ("limit", t_int, 32)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    let err = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap_err();
    assert!(matches!(err, CoreReloError::Ambiguous { .. }));
}

/// An enum value relocates to the target's value for the same (flavor-matched) variant.
#[test]
fn enum_value_relocation() {
    let mut local = TestBtf::new();
    let color = local.enum_("color", &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
    let r = relo(&mut local, color, "1", CoreReloKind::EnumvalValue); // GREEN
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    target.enum_("color___v2", &[("RED", 10), ("GREEN", 11), ("BLUE", 12)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(imm_of(insns[0]), 11);
}

/// `TYPE_ID_TARGET` resolves to the matched candidate's own type ID, not the local one.
#[test]
fn type_id_target_relocation() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let cfg = local.struct_("cfg", 4, &[("limit", int_ty, 0)]);
    let r = relo(&mut local, cfg, "0", CoreReloKind::TypeIdTarget);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = TestBtf::new();
    let t_int = target.int("int", 4, true);
    let _padding = target.int("padding filler", 1, false);
    let t_cfg = target.struct_("cfg", 4, &[("limit", t_int, 0)]);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    // TYPE_ID_TARGET is never validated against the instruction's current value.
    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 0xFFFF)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(imm_of(insns[0]) as u32, t_cfg);
}

/// `TYPE_MATCHES` structurally compares local and target: a superset of fields matches,
/// a missing field doesn't (and, since it's an "exists"-family kind, resolves to 0 rather
/// than poisoning).
#[test]
fn type_matches_true_and_false() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let a = local.struct_("a", 4, &[("x", int_ty, 0)]);
    let r_superset = relo(&mut local, a, "0", CoreReloKind::TypeMatches);
    let r_mismatched = relo(&mut local, a, "0", CoreReloKind::TypeMatches);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut superset = TestBtf::new();
    let s_int = superset.int("int", 4, true);
    superset.struct_("a", 8, &[("x", s_int, 0), ("y", s_int, 32)]);
    let superset_bytes = superset.encode();
    let superset_btf = Btf::parse(&superset_bytes).unwrap();

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    apply_core_relocations(&mut insns, &local_btf, &superset_btf, &[r_superset]).unwrap();
    assert_eq!(imm_of(insns[0]), 1);

    let mut mismatched = TestBtf::new();
    let m_int = mismatched.int("int", 4, true);
    mismatched.struct_("a", 4, &[("z", m_int, 0)]);
    let mismatched_bytes = mismatched.encode();
    let mismatched_btf = Btf::parse(&mismatched_bytes).unwrap();

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    apply_core_relocations(&mut insns, &local_btf, &mismatched_btf, &[r_mismatched]).unwrap();
    assert_eq!(imm_of(insns[0]), 0);
}

/// A type absent from the target poisons a field relocation's instruction (it's returned
/// as `Unresolved`), but a plain existence check patches to `0`, and so does every
/// type-based kind (not just `TYPE_EXISTS`/`TYPE_MATCHES`): libbpf never poisons those.
#[test]
fn missing_type_poisons_or_reads_as_absent() {
    let mut local = TestBtf::new();
    let int_ty = local.int("int", 4, true);
    let gone = local.struct_("gone", 4, &[("field", int_ty, 0)]);
    let r_offset = relo(&mut local, gone, "0:0", CoreReloKind::FieldByteOffset);
    let r_exists = relo(&mut local, gone, "0:0", CoreReloKind::FieldExists);
    let r_size = relo(&mut local, gone, "0", CoreReloKind::TypeSize);
    let r_id_target = relo(&mut local, gone, "0", CoreReloKind::TypeIdTarget);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let target = TestBtf::new();
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_offset]).unwrap();
    assert_eq!(
        unresolved,
        vec![Unresolved {
            insn_off: 0,
            error: CoreReloError::NoMatchingTarget { type_name: "gone".to_string(), access_str: "0:0".to_string() },
        }]
    );
    assert_eq!(insns[0], 0x85 | u64::from(CORE_POISON_HELPER) << 32);

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_exists]).unwrap();
    assert!(unresolved.is_empty());
    assert_eq!(imm_of(insns[0]), 0);

    // TYPE_SIZE's orig_val is the local type's own size (4), validated against the
    // instruction; a missing target still patches 0 rather than poisoning.
    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 4)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_size]).unwrap();
    assert!(unresolved.is_empty());
    assert_eq!(imm_of(insns[0]), 0);

    // TYPE_ID_TARGET is never validated, so the starting imm is irrelevant.
    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 0xFFFF)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_id_target]).unwrap();
    assert!(unresolved.is_empty());
    assert_eq!(imm_of(insns[0]), 0);
}
