//! End-to-end CO-RE relocation tests: a local (compile-time) BTF is relocated against a
//! target (host) BTF, exactly like a BPF program's debug info gets relocated against the
//! kernel's BTF. Both are encoded with [`BtfBuilder`] so each test controls, and can
//! hand-derive, the exact offsets/values the relocation must produce.

use crate::builder::BtfBuilder;
use crate::core_relo::{apply_core_relocations, CoreRelo, CoreReloError, CoreReloKind, Unresolved, CORE_POISON_HELPER};
use crate::parse::Btf;

/// Encode a single `CoreRelo` whose access string is appended to a scratch `BtfBuilder`'s
/// string table (CO-RE access strings live in the *local* BTF's strings).
fn relo(local: &mut BtfBuilder, type_id: u32, access_str: &str, kind: CoreReloKind) -> CoreRelo {
    let access_str_off = local.string(access_str);
    CoreRelo {
        insn_off: 0,
        type_id,
        access_str_off,
        kind,
    }
}

fn insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    u64::from(opcode)
        | u64::from(dst) << 8
        | u64::from(src) << 12
        | u64::from(off as u16) << 16
        | u64::from(imm as u32) << 32
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
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let event = local.add_struct("event", 8);
    local.member(event, "ts", 0, int_ty);
    local.member(event, "pid", 4, int_ty);
    let r = relo(&mut local, event, "0:1", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    // Host's "event" has an extra field between ts and pid, pushing pid from byte 4 to byte 8.
    let t_event = target.add_struct("event", 12);
    target.member(t_event, "ts", 0, t_int);
    target.member(t_event, "extra", 4, t_int);
    target.member(t_event, "pid", 8, t_int);
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
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let s = local.add_struct("anonish", 4);
    local.member(s, "val", 0, int_ty);
    let r = relo(&mut local, s, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    // `val` lives inside an anonymous union starting at byte 4, alongside `padding`.
    let anon_union = target.add_union("", 4);
    target.member(anon_union, "padding", 0, t_int);
    target.member(anon_union, "val", 0, t_int);
    let t_anonish = target.add_struct("anonish", 8);
    target.member(t_anonish, "other", 0, t_int);
    target.member(t_anonish, "", 4, anon_union);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(off_of(insns[0]), 4);
}

/// Array element access follows the target's own array offset and element size.
#[test]
fn array_element_offset() {
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let arr = local.array(int_ty, 4);
    let s = local.add_struct("withArr", 20);
    local.member(s, "before", 0, int_ty);
    local.member(s, "items", 4, arr);
    let r = relo(&mut local, s, "0:1:2", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    let t_arr = target.array(t_int, 4);
    // Host inserted a padding field before the array, moving it from byte 4 to byte 8.
    let t_with_arr = target.add_struct("withArr", 24);
    target.member(t_with_arr, "before", 0, t_int);
    target.member(t_with_arr, "pad", 4, t_int);
    target.member(t_with_arr, "items", 8, t_arr);
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
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    // `v` occupies bits [3, 8) of a 4-byte int: byte_sz=4, byte_off=0.
    let s = local.add_struct("flags", 4);
    local.bitfield_member(s, "v", 3, 5, int_ty);
    let r_signed = relo(&mut local, s, "0:0", CoreReloKind::FieldSigned);
    let r_rshift = relo(&mut local, s, "0:0", CoreReloKind::FieldRShiftU64);
    let r_lshift = relo(&mut local, s, "0:0", CoreReloKind::FieldLShiftU64);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    // `v` occupies bits [20, 25) of a 4-byte int: byte_sz=4, byte_off=0.
    let t_flags = target.add_struct("flags", 4);
    target.bitfield_member(t_flags, "v", 20, 5, t_int);
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
    let mut local = BtfBuilder::new();
    let u32_ty = local.int("unsigned int", 4, false);
    let i32_ty = local.int("int", 4, true);
    let safe = local.add_struct("safe", 4);
    local.member(safe, "count", 0, u32_ty);
    let unsafe_ = local.add_struct("unsafe", 4);
    local.member(unsafe_, "count", 0, i32_ty);
    let r_safe = relo(&mut local, safe, "0:0", CoreReloKind::FieldByteOffset);
    let r_unsafe = relo(&mut local, unsafe_, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let u64_ty = target.int("unsigned long", 8, false);
    let i64_ty = target.int("long", 8, true);
    let t_safe = target.add_struct("safe", 8);
    target.member(t_safe, "count", 0, u64_ty);
    let t_unsafe = target.add_struct("unsafe", 8);
    target.member(t_unsafe, "count", 0, i64_ty);
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
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let cfg = local.add_struct("cfg", 4);
    local.member(cfg, "limit", 0, int_ty);
    let r = relo(&mut local, cfg, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    let t_cfg = target.add_struct("cfg___v2", 8);
    target.member(t_cfg, "pad", 0, t_int);
    target.member(t_cfg, "limit", 4, t_int);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(off_of(insns[0]), 4);
}

/// Two target flavors that disagree on where a field landed make the relocation ambiguous.
#[test]
fn ambiguous_candidates_error() {
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let cfg = local.add_struct("cfg", 4);
    local.member(cfg, "limit", 0, int_ty);
    let r = relo(&mut local, cfg, "0:0", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    let t_cfg = target.add_struct("cfg", 4);
    target.member(t_cfg, "limit", 0, t_int);
    let t_cfg_dup = target.add_struct("cfg___dup", 8);
    target.member(t_cfg_dup, "pad", 0, t_int);
    target.member(t_cfg_dup, "limit", 4, t_int);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    let err = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap_err();
    assert!(matches!(err, CoreReloError::Ambiguous { .. }));
}

/// An enum value relocates to the target's value for the same (flavor-matched) variant.
#[test]
fn enum_value_relocation() {
    let mut local = BtfBuilder::new();
    let color = local.add_enum("color", 4, false);
    local.enumerator(color, "RED", 0);
    local.enumerator(color, "GREEN", 1);
    local.enumerator(color, "BLUE", 2);
    let r = relo(&mut local, color, "1", CoreReloKind::EnumvalValue); // GREEN
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_color = target.add_enum("color___v2", 4, false);
    target.enumerator(t_color, "RED", 10);
    target.enumerator(t_color, "GREEN", 11);
    target.enumerator(t_color, "BLUE", 12);
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert_eq!(imm_of(insns[0]), 11);
}

/// `TYPE_ID_TARGET` resolves to the matched candidate's own type ID, not the local one.
#[test]
fn type_id_target_relocation() {
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let cfg = local.add_struct("cfg", 4);
    local.member(cfg, "limit", 0, int_ty);
    let r = relo(&mut local, cfg, "0", CoreReloKind::TypeIdTarget);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut target = BtfBuilder::new();
    let t_int = target.int("int", 4, true);
    let _padding = target.int("padding filler", 1, false);
    let t_cfg = target.add_struct("cfg", 4);
    target.member(t_cfg, "limit", 0, t_int);
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
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let a = local.add_struct("a", 4);
    local.member(a, "x", 0, int_ty);
    let r_superset = relo(&mut local, a, "0", CoreReloKind::TypeMatches);
    let r_mismatched = relo(&mut local, a, "0", CoreReloKind::TypeMatches);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let mut superset = BtfBuilder::new();
    let s_int = superset.int("int", 4, true);
    let s_a = superset.add_struct("a", 8);
    superset.member(s_a, "x", 0, s_int);
    superset.member(s_a, "y", 4, s_int);
    let superset_bytes = superset.encode();
    let superset_btf = Btf::parse(&superset_bytes).unwrap();

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 1)];
    apply_core_relocations(&mut insns, &local_btf, &superset_btf, &[r_superset]).unwrap();
    assert_eq!(imm_of(insns[0]), 1);

    let mut mismatched = BtfBuilder::new();
    let m_int = mismatched.int("int", 4, true);
    let m_a = mismatched.add_struct("a", 4);
    mismatched.member(m_a, "z", 0, m_int);
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
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let gone = local.add_struct("gone", 4);
    local.member(gone, "field", 0, int_ty);
    let r_offset = relo(&mut local, gone, "0:0", CoreReloKind::FieldByteOffset);
    let r_exists = relo(&mut local, gone, "0:0", CoreReloKind::FieldExists);
    let r_size = relo(&mut local, gone, "0", CoreReloKind::TypeSize);
    let r_id_target = relo(&mut local, gone, "0", CoreReloKind::TypeIdTarget);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let target = BtfBuilder::new();
    let target_bytes = target.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 0, 0)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r_offset]).unwrap();
    assert_eq!(
        unresolved,
        vec![Unresolved {
            insn_off: 0,
            error: CoreReloError::NoMatchingTarget {
                type_name: "gone".to_string(),
                access_str: "0:0".to_string()
            },
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

/// `FieldByteSize` on an array member is the whole array's size (element size times
/// length), matching libbpf's `btf__resolve_size`, not just the element's size.
#[test]
fn array_field_byte_size_multiplies_by_length() {
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let arr = local.array(int_ty, 4);
    let s = local.add_struct("withArr", 16);
    local.member(s, "arr", 0, arr);
    let r = relo(&mut local, s, "0:0", CoreReloKind::FieldByteSize);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let target_bytes = local.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(ALU64_MOV_K, 0, 0, 0, 16)];
    let unresolved = apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    assert!(unresolved.is_empty());
    assert_eq!(imm_of(insns[0]), 16);
}

/// A two-dimensional array's second-level index is scaled by the inner array's whole
/// size, not just its element's: `a[i][j]`'s offset is `i * (inner_len * elem_sz) + j *
/// elem_sz`.
#[test]
fn two_dimensional_array_offset() {
    let mut local = BtfBuilder::new();
    let int_ty = local.int("int", 4, true);
    let inner = local.array(int_ty, 4);
    let outer = local.array(inner, 3);
    let s = local.add_struct("with2d", 52);
    local.member(s, "before", 0, int_ty);
    local.member(s, "grid", 4, outer);
    // idx1 selects "grid" (the struct's second member), idx2 selects the outer
    // dimension's element 1, idx3 selects the inner dimension's element 2.
    let r = relo(&mut local, s, "0:1:1:2", CoreReloKind::FieldByteOffset);
    let local_bytes = local.encode();
    let local_btf = Btf::parse(&local_bytes).unwrap();

    let target_bytes = local.encode();
    let target_btf = Btf::parse(&target_bytes).unwrap();

    let mut insns = [insn(LDX_W, 0, 1, 28, 0)];
    apply_core_relocations(&mut insns, &local_btf, &target_btf, &[r]).unwrap();
    // 4 (before) + 1 * 16 (one full inner array) + 2 * 4 (one int)
    assert_eq!(off_of(insns[0]), 28);
}
