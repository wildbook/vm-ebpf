//! Integration tests demonstrating the full BTF/CO-RE workflow.
//!
//! These tests show how a host application can:
//! 1. Register its struct layouts in a TypeRegistry
//! 2. Parse BTF from an eBPF program
//! 3. Apply CO-RE relocations to adjust field offsets

use crate::core_relo::{apply_core_relocations, CoreRelo, CoreReloError, CoreReloKind};
use crate::parse::Btf;
use crate::raw::{BTF_MAGIC, BTF_VERSION};
use crate::registry::TypeRegistry;

/// Build a minimal BTF blob for testing.
///
/// This creates BTF with:
/// - A string table
/// - A struct type with fields
fn build_test_btf(struct_name: &str, fields: &[(&str, u32)]) -> Vec<u8> {
    // Build string table: "\0<struct_name>\0<field1>\0<field2>\0..."
    let mut strings = vec![0u8]; // null string at offset 0
    let struct_name_off = strings.len() as u32;
    strings.extend_from_slice(struct_name.as_bytes());
    strings.push(0);

    let mut field_name_offs = Vec::new();
    for (name, _) in fields {
        field_name_offs.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }

    // Build type section
    let mut types = Vec::new();

    // Type 1: struct
    // btf_type: name_off (4) + info (4) + size (4) = 12 bytes
    let vlen = fields.len() as u32;
    let info = (4 << 24) | vlen; // kind=4 (struct), vlen=field count
    let struct_size = fields.iter().map(|(_, sz)| sz).sum::<u32>();

    types.extend_from_slice(&struct_name_off.to_le_bytes());
    types.extend_from_slice(&info.to_le_bytes());
    types.extend_from_slice(&struct_size.to_le_bytes());

    // btf_member for each field: name_off (4) + type_id (4) + offset (4) = 12 bytes each
    let mut bit_offset = 0u32;
    for (i, (_, size)) in fields.iter().enumerate() {
        types.extend_from_slice(&field_name_offs[i].to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes()); // type_id (dummy)
        types.extend_from_slice(&bit_offset.to_le_bytes()); // bit offset
        bit_offset += size * 8;
    }

    // Build header
    let hdr_len = 24u32;
    let type_off = 0u32;
    let type_len = types.len() as u32;
    let str_off = type_len;
    let str_len = strings.len() as u32;

    let mut btf = Vec::new();
    btf.extend_from_slice(&BTF_MAGIC.to_le_bytes());
    btf.push(BTF_VERSION);
    btf.push(0); // flags
    btf.extend_from_slice(&hdr_len.to_le_bytes());
    btf.extend_from_slice(&type_off.to_le_bytes());
    btf.extend_from_slice(&type_len.to_le_bytes());
    btf.extend_from_slice(&str_off.to_le_bytes());
    btf.extend_from_slice(&str_len.to_le_bytes());

    // Append type and string sections
    btf.extend_from_slice(&types);
    btf.extend_from_slice(&strings);

    btf
}

#[test]
fn test_btf_parsing() {
    let btf_data = build_test_btf("my_event", &[("timestamp", 8), ("pid", 4), ("flags", 4)]);

    let btf = Btf::parse(&btf_data).expect("failed to parse BTF");

    // Should have 2 types: void (id 0) and our struct (id 1)
    assert_eq!(btf.type_count(), 2);

    // Find our struct
    let (type_id, ty) = btf.find_struct("my_event").expect("struct not found");
    assert_eq!(type_id, 1);

    if let crate::types::BtfTypeInfo::Struct { name, size, members } = ty {
        assert_eq!(*name, "my_event");
        assert_eq!(*size, 16); // 8 + 4 + 4
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].name, "timestamp");
        assert_eq!(members[0].byte_offset(), 0);
        assert_eq!(members[1].name, "pid");
        assert_eq!(members[1].byte_offset(), 8);
        assert_eq!(members[2].name, "flags");
        assert_eq!(members[2].byte_offset(), 12);
    } else {
        panic!("expected struct type");
    }
}

#[test]
fn test_core_relocation_field_offset() {
    let mut registry = TypeRegistry::new();

    // Host's struct layout has different offsets than the BPF program expects
    registry
        .register_struct("my_event")
        .field("timestamp", 0, 8)
        .field("pid", 16, 4) // Host has pid at offset 16
        .field("flags", 20, 4)
        .size(24);

    // Build BTF where the BPF program expected pid right after timestamp
    let btf_data = build_test_btf(
        "my_event",
        &[
            ("timestamp", 8),
            ("pid", 4), // BPF expected at offset 8
            ("flags", 4),
        ],
    );
    let btf = Btf::parse(&btf_data).unwrap();

    // String table: "\0my_event\0timestamp\0pid\0flags\0"
    // Offsets:       0  1        10         20   24
    let relos = vec![
        CoreRelo {
            insn_off: 0,
            type_id: 1,         // my_event struct
            access_str_off: 20, // "pid"
            kind: CoreReloKind::FieldByteOffset,
        },
        CoreRelo {
            insn_off: 8,
            type_id: 1,
            access_str_off: 24, // "flags"
            kind: CoreReloKind::FieldByteOffset,
        },
    ];

    let mut instructions = vec![0x00000000_00000000u64; 2];

    let applied = apply_core_relocations(&mut instructions, &btf, &registry, &relos).unwrap();
    assert_eq!(applied, 2);

    // Both immediates (upper 32 bits) should now hold the host's actual offsets.
    assert_eq!((instructions[0] >> 32) as u32, 16); // pid moved from 8 to 16
    assert_eq!((instructions[1] >> 32) as u32, 20); // flags moved from 12 to 20
}

#[test]
fn test_core_relocation_field_exists() {
    let mut registry = TypeRegistry::new();

    // Host's struct doesn't have "old_field"
    registry
        .register_struct("my_event")
        .field("timestamp", 0, 8)
        .field("new_field", 8, 4) // Different field name
        .size(12);

    let btf_data = build_test_btf(
        "my_event",
        &[
            ("timestamp", 8),
            ("old_field", 4), // BPF program uses old field name
        ],
    );
    let btf = Btf::parse(&btf_data).unwrap();

    // Check if "old_field" exists (it doesn't in host)
    // String table: "\0my_event\0timestamp\0old_field\0"
    // Offsets:       0  1        10         20
    let relo = CoreRelo {
        insn_off: 0,
        type_id: 1,
        access_str_off: 20, // "old_field"
        kind: CoreReloKind::FieldExists,
    };

    let mut instructions = vec![0xFFFFFFFF_00000000u64; 1]; // Start with imm=0xFFFFFFFF

    let applied = apply_core_relocations(&mut instructions, &btf, &registry, &[relo]).unwrap();
    assert_eq!(applied, 1);

    // Should be patched to 0 (field doesn't exist)
    let patched_imm = (instructions[0] >> 32) as u32;
    assert_eq!(patched_imm, 0);
}

#[test]
fn test_core_relocation_type_size() {
    let mut registry = TypeRegistry::new();

    // Host's struct is larger than BPF expected
    registry
        .register_struct("my_event")
        .field("timestamp", 0, 8)
        .field("pid", 8, 4)
        .field("extra_data", 12, 64) // Extra field
        .size(80);

    let btf_data = build_test_btf("my_event", &[("timestamp", 8), ("pid", 4)]);
    let btf = Btf::parse(&btf_data).unwrap();

    // Get type size
    let relo = CoreRelo {
        insn_off: 0,
        type_id: 1,
        access_str_off: 0, // Not used for type size
        kind: CoreReloKind::TypeSize,
    };

    let mut instructions = vec![0u64; 1];

    let applied = apply_core_relocations(&mut instructions, &btf, &registry, &[relo]).unwrap();
    assert_eq!(applied, 1);

    // Should return host's actual size: 80
    let patched_imm = (instructions[0] >> 32) as u32;
    assert_eq!(patched_imm, 80);
}

#[test]
fn test_core_suffix_matching() {
    let mut registry = TypeRegistry::new();

    // Register base type
    registry
        .register_struct("task_struct")
        .field("pid", 0, 4)
        .field("tgid", 4, 4)
        .field("state", 8, 8)
        .size(16);

    // CO-RE suffix variants should all match
    assert!(registry.has_struct("task_struct"));
    assert!(registry.has_struct("task_struct___old"));
    assert!(registry.has_struct("task_struct___v2"));
    assert!(registry.has_struct("task_struct___custom_suffix"));

    // Field access with suffix should work
    assert_eq!(registry.field_offset("task_struct___old", "pid"), Some(0));
    assert_eq!(registry.field_offset("task_struct___v2", "state"), Some(8));
}

#[test]
fn test_missing_type_error() {
    let registry = TypeRegistry::new();
    // Don't register any types

    let btf_data = build_test_btf("unknown_struct", &[("field", 4)]);
    let btf = Btf::parse(&btf_data).unwrap();

    let relo = CoreRelo {
        insn_off: 0,
        type_id: 1,
        access_str_off: 1, // "unknown_struct"
        kind: CoreReloKind::FieldByteOffset,
    };

    let mut instructions = vec![0u64; 1];

    let result = apply_core_relocations(&mut instructions, &btf, &registry, &[relo]);
    assert!(matches!(result, Err(CoreReloError::FieldNotFound { .. })));
}

// ==================== clang-style access strings ====================

/// Raw BTF builder: `types` are pre-encoded `btf_type` records; `strings` starts with "\0".
fn build_raw_btf(types: &[u32], strings: &[u8]) -> Vec<u8> {
    let types: Vec<u8> = types.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut btf = Vec::new();
    btf.extend_from_slice(&BTF_MAGIC.to_le_bytes());
    btf.extend_from_slice(&[BTF_VERSION, 0]);
    for w in [24, 0, types.len() as u32, types.len() as u32, strings.len() as u32] {
        btf.extend_from_slice(&w.to_le_bytes());
    }
    btf.extend_from_slice(&types);
    btf.extend_from_slice(strings);
    btf
}

/// Local (compile-time) types:
/// 1 int; 2 struct inner { int x; int y; }; 3 struct outer { int a; struct inner in; };
/// 4 enum color { RED, GREEN, BLUE }; 5 typedef struct outer ev_t.
/// Access strings live at: "0:1:1"=1, "2:1"=7, "0:1:0"=11, "2"=17.
fn clang_style_btf() -> Vec<u8> {
    let strings = b"\x000:1:1\x002:1\x000:1:0\x002\0int\0inner\0x\0y\0outer\0a\0in\0color\0RED\0GREEN\0BLUE\0ev_t\0";
    let s = |name: &str| {
        let needle = [name.as_bytes(), b"\0"].concat();
        (1..strings.len())
            .find(|&i| strings[i - 1] == 0 && strings[i..].starts_with(&needle))
            .unwrap() as u32
    };
    #[rustfmt::skip]
    let types = [
        s("int"), 1 << 24, 4, 32,                                     // 1: int
        s("inner"), 4 << 24 | 2, 8, s("x"), 1, 0, s("y"), 1, 32,      // 2: struct inner
        s("outer"), 4 << 24 | 2, 12, s("a"), 1, 0, s("in"), 2, 32,    // 3: struct outer
        s("color"), 6 << 24 | 3, 4, s("RED"), 0, s("GREEN"), 1, s("BLUE"), 2, // 4: enum color
        s("ev_t"), 8 << 24, 3,                                        // 5: typedef
    ];
    build_raw_btf(&types, strings)
}

/// Host layout differs from the local one at every level.
fn clang_style_registry() -> TypeRegistry {
    let mut registry = TypeRegistry::new();
    registry
        .register_struct("inner")
        .field("x", 0, 4)
        .field("y", 8, 4)
        .size(16);
    registry
        .register_struct("outer")
        .field("a", 0, 4)
        .field("in", 8, 16)
        .size(24);
    registry
        .register_enum("color", 4, false)
        .variant("RED", 0)
        .variant("GREEN", 1)
        .variant("BLUE", 7);
    registry
}

fn relo(type_id: u32, access_str_off: u32, kind: CoreReloKind) -> CoreRelo {
    CoreRelo {
        insn_off: 0,
        type_id,
        access_str_off,
        kind,
    }
}

/// LDX_W r0, [r1 + off]
const LDXW: u64 = 0x61 | 1 << 12;

fn patched_off(insn: u64) -> i16 {
    (insn >> 16) as i16
}

#[test]
fn test_core_nested_and_array_access() {
    let btf_data = clang_style_btf();
    let btf = Btf::parse(&btf_data).unwrap();
    let registry = clang_style_registry();

    for (type_id, access, want) in [
        (3, 1, 16), // outer.in.y = 8 + 8
        (3, 7, 56), // p[2].in = 2 * 24 + 8
        (5, 11, 8), // typedef root: ev_t.in.x = 8 + 0
    ] {
        let mut insns = [LDXW];
        apply_core_relocations(&mut insns, &btf, &registry, &[relo(type_id, access, CoreReloKind::FieldByteOffset)])
            .unwrap();
        assert_eq!(patched_off(insns[0]), want, "type {type_id} access@{access}");
    }

    let mut insns = [0u64];
    apply_core_relocations(&mut insns, &btf, &registry, &[relo(3, 1, CoreReloKind::FieldByteSize)]).unwrap();
    assert_eq!(insns[0] >> 32, 4);
}

#[test]
fn test_core_enum_value_by_index() {
    let btf_data = clang_style_btf();
    let btf = Btf::parse(&btf_data).unwrap();
    let mut registry = clang_style_registry();

    let mut insns = [0u64];
    apply_core_relocations(&mut insns, &btf, &registry, &[relo(4, 17, CoreReloKind::EnumvalValue)]).unwrap();
    assert_eq!(insns[0] >> 32, 7);

    // LD_IMM64 receives the full 64-bit value across both slots.
    registry.register_enum("color", 8, false).variant("BLUE", 0x1_0000_0007);
    let mut insns = [0x18u64, 0];
    apply_core_relocations(&mut insns, &btf, &registry, &[relo(4, 17, CoreReloKind::EnumvalValue)]).unwrap();
    assert_eq!((insns[0] >> 32) | (insns[1] >> 32) << 32, 0x1_0000_0007);
}

#[test]
fn test_core_patches_off_for_all_memory_classes() {
    let btf_data = clang_style_btf();
    let btf = Btf::parse(&btf_data).unwrap();
    let registry = clang_style_registry();

    // ST_W [r1 + off], 5 / LDXSW (MEMSX) / atomic ADD_W: `off` is patched, imm keeps its meaning.
    for insn in [0x62 | 1 << 8 | 5 << 32, 0x81 | 1 << 12, 0xc3 | 1 << 8 | 2 << 12] {
        let mut insns = [insn];
        apply_core_relocations(&mut insns, &btf, &registry, &[relo(3, 1, CoreReloKind::FieldByteOffset)]).unwrap();
        assert_eq!(patched_off(insns[0]), 16, "opcode {:#x}", insn as u8);
        assert_eq!(insns[0] >> 32, insn >> 32, "imm changed for opcode {:#x}", insn as u8);
    }
}
