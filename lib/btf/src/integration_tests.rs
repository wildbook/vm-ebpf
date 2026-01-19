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
fn test_type_registry_field_lookup() {
    let mut registry = TypeRegistry::new();

    // Host application's actual struct layout (might differ from BPF program's expectation)
    registry
        .register_struct("my_event")
        .field("timestamp", 0, 8)
        .field("pid", 8, 4)
        .field("flags", 16, 4) // Note: different offset than BPF expects!
        .size(24);

    assert_eq!(registry.field_offset("my_event", "timestamp"), Some(0));
    assert_eq!(registry.field_offset("my_event", "pid"), Some(8));
    assert_eq!(registry.field_offset("my_event", "flags"), Some(16));
    assert_eq!(registry.struct_size("my_event"), Some(24));

    // Non-existent field
    assert_eq!(registry.field_offset("my_event", "nonexistent"), None);
    assert!(!registry.field_exists("my_event", "nonexistent"));
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

    // Build BTF where BPF program expected pid at offset 8
    let btf_data = build_test_btf(
        "my_event",
        &[
            ("timestamp", 8),
            ("pid", 4), // BPF expected at offset 8
            ("flags", 4),
        ],
    );
    let btf = Btf::parse(&btf_data).unwrap();

    // Create a CO-RE relocation for reading the "pid" field
    // String table: "\0my_event\0timestamp\0pid\0flags\0"
    // Offsets:       0  1        10         20   24
    let relo = CoreRelo {
        insn_off: 0,        // Patch instruction at offset 0
        type_id: 1,         // Type ID 1 (my_event struct)
        access_str_off: 20, // "pid" in string table
        kind: CoreReloKind::FieldByteOffset,
    };

    // Instructions: one dummy instruction where we'll patch the immediate
    let mut instructions = vec![0x00000000_00000000u64; 1];

    // Apply the relocation
    let applied = apply_core_relocations(&mut instructions, &btf, &registry, &[relo]).unwrap();
    assert_eq!(applied, 1);

    // The immediate (upper 32 bits) should now be 16 (host's actual offset)
    let patched_imm = (instructions[0] >> 32) as u32;
    assert_eq!(patched_imm, 16);
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
fn test_core_relocation_enum_value() {
    let mut registry = TypeRegistry::new();

    // Host's enum values
    registry
        .register_enum("event_type", 4, false)
        .variant("EVENT_NONE", 0)
        .variant("EVENT_READ", 1)
        .variant("EVENT_WRITE", 2)
        .variant("EVENT_CLOSE", 5); // Note: value 5, not 3

    // For enum relocations, we need a BTF with an enum type
    // For simplicity, we'll test the registry directly
    assert_eq!(registry.enum_value("event_type", "EVENT_CLOSE"), Some(5));
    assert!(registry.enum_variant_exists("event_type", "EVENT_READ"));
    assert!(!registry.enum_variant_exists("event_type", "EVENT_OPEN"));
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

#[test]
fn test_multiple_relocations() {
    let mut registry = TypeRegistry::new();

    registry
        .register_struct("packet")
        .field("src_ip", 0, 4)
        .field("dst_ip", 4, 4)
        .field("src_port", 8, 2)
        .field("dst_port", 10, 2)
        .field("protocol", 12, 1)
        .size(16);

    let btf_data = build_test_btf(
        "packet",
        &[
            ("src_ip", 4),
            ("dst_ip", 4),
            ("src_port", 2),
            ("dst_port", 2),
            ("protocol", 1),
        ],
    );
    let btf = Btf::parse(&btf_data).unwrap();

    // String table: "\0packet\0src_ip\0dst_ip\0src_port\0dst_port\0protocol\0"
    // Offsets:       0  1      8       15       22        31         40

    let relos = vec![
        CoreRelo {
            insn_off: 0,
            type_id: 1,
            access_str_off: 8, // src_ip
            kind: CoreReloKind::FieldByteOffset,
        },
        CoreRelo {
            insn_off: 8,
            type_id: 1,
            access_str_off: 15, // dst_ip
            kind: CoreReloKind::FieldByteOffset,
        },
        CoreRelo {
            insn_off: 16,
            type_id: 1,
            access_str_off: 22, // src_port
            kind: CoreReloKind::FieldByteOffset,
        },
    ];

    let mut instructions = vec![0u64; 3];

    let applied = apply_core_relocations(&mut instructions, &btf, &registry, &relos).unwrap();
    assert_eq!(applied, 3);

    assert_eq!((instructions[0] >> 32) as u32, 0); // src_ip at 0
    assert_eq!((instructions[1] >> 32) as u32, 4); // dst_ip at 4
    assert_eq!((instructions[2] >> 32) as u32, 8); // src_port at 8
}
