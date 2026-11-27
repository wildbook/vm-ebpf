//! Prepared images: round-trip serialization, token dispatch, and rejection of malformed or oversized images.

use rvm::{
    Borrow, Image, Import, LinkError, MapDef, MapKind, Module, Plugin, Vm, VmConfig, VmError, DEFAULT_MEMORY_LIMIT,
    MAX_REGION_LEN,
};
use rvm_core::opcode::CALL;

use crate::common::{host_vm, object};

/// Preparing, serializing, and loading an image matches ELF linking across maps, function pointers, and cross-module
/// links.
#[test]
fn image_round_trips_and_runs() {
    let vm = host_vm();
    let cases: &[(&[&str], &str, &[u64])] = &[
        (&["tests/maps.o"], "count", &[1]),
        (&["tests/func_ptr.o"], "dense_switch", &[3, 10]),
        (&["tests/link_main.o", "tests/link_lib.o"], "run", &[7]),
    ];

    for &(objects, func, args) in cases {
        let elfs: Vec<_> = objects.iter().map(|name| object(name)).collect();
        let modules: Vec<Module> = elfs.iter().map(|elf| Module::from_elf(elf).unwrap()).collect();
        let refs: Vec<&Module> = modules.iter().collect();

        let mut linked = vm.load_modules(&refs).unwrap();
        let image = vm.prepare_modules(&refs).unwrap();
        let bytes = image.to_bytes();
        assert_eq!(Image::from_bytes(&bytes).unwrap(), image);
        let mut loaded = vm.load_image_bytes(&bytes).unwrap();

        assert_eq!(loaded.call(func, args).unwrap(), linked.call(func, args).unwrap(), "{objects:?} {func}");
    }
}

#[test]
fn malformed_images_fail_to_load() {
    let vm = Vm::new();
    let good = vm.prepare_elf(&object("tests/maps.o")).unwrap();
    let bytes = good.to_bytes();
    let load = |image: &Image| vm.load_image_bytes(&image.to_bytes());
    let is_invalid = |r: rvm::Result<rvm::Program>| matches!(r, Err(VmError::InvalidImage(_)));

    for len in 0..bytes.len() {
        assert!(is_invalid(vm.load_image_bytes(&bytes[..len])), "truncated to {len} bytes");
    }

    let mut other_magic = bytes.clone();
    other_magic[0] = b'X';
    assert!(is_invalid(vm.load_image_bytes(&other_magic)));

    // the version string follows the magic, the format version and its length
    let ours = env!("CARGO_PKG_VERSION");
    let mut other_version = bytes.clone();
    other_version[12] ^= 1;
    let theirs = std::str::from_utf8(&other_version[12..][..ours.len()]).unwrap();
    let err = vm.load_image_bytes(&other_version).unwrap_err().to_string();
    assert!(err.contains(&format!("rvm {theirs} ")) && err.contains(&format!("rvm {ours} ")), "{err}");

    let insns = (good.code.len() / 8) as u32;
    let not_a_call = good.code.chunks(8).position(|insn| insn[0] != CALL).unwrap() as u32;
    for at in [insns, not_a_call] {
        let mut image = good.clone();
        image.add_call(at, Import::Helper(1));
        assert!(is_invalid(load(&image)), "extern at {at}");
    }

    let mut image = good.clone();
    image.imports[0] = Import::Helper(999);
    assert!(matches!(load(&image), Err(VmError::Link(LinkError::UnknownHelper(999)))));

    let mut image = good.clone();
    image.functions[0].1.pc = insns.into();
    assert!(is_invalid(load(&image)));

    // a borrow's length can't be another borrow's pointer, which the call rewrites first
    let mut image = good.clone();
    let borrow = |arg, len_arg| Borrow {
        arg,
        len_arg,
        writable: true,
    };
    image.functions[0].1.borrows = vec![borrow(0, 1), borrow(1, 0)];
    assert!(is_invalid(load(&image)));

    let mut image = good.clone();
    image.maps[0].max_entries = u32::MAX;
    let err = load(&image).unwrap_err();
    assert!(matches!(&err, VmError::Link(LinkError::InvalidMap(msg)) if msg.contains("too large")), "{err}");

    let mut image = good.clone();
    image.data_len = MAX_REGION_LEN + 1;
    assert!(matches!(load(&image), Err(VmError::ProgramTooLarge("data"))));
}

/// Images that ask for more memory than the limit fail before allocating it, whether one region or map asks or
/// several add up.
#[test]
fn oversized_images_fail_to_load() {
    let vm = Vm::new();
    let good = vm.prepare_elf(&object("tests/maps.o")).unwrap();
    let over_limit = |vm: &Vm, image: &Image| match vm.load_image_bytes(&image.to_bytes()) {
        Err(VmError::MemoryLimit(limit)) => limit,
        other => panic!("{other:?}"),
    };

    let mut image = good.clone();
    image.rodata_len = MAX_REGION_LEN;
    assert_eq!(over_limit(&vm, &image), DEFAULT_MEMORY_LIMIT);

    // one 4 GiB key in 64 bytes of values
    let mut image = good.clone();
    let map = |name: &str, key_size, max_entries| MapDef {
        name: name.into(),
        kind: MapKind::Hash,
        key_size,
        value_size: 8,
        max_entries,
    };
    image.maps = vec![map("big_key", u32::MAX, 1)];
    assert_eq!(over_limit(&vm, &image), DEFAULT_MEMORY_LIMIT);

    // each map fits the limit, together they don't
    let small = Vm::with_config(VmConfig {
        memory_limit: 1 << 20,
        ..VmConfig::default()
    })
    .unwrap();
    image.maps = (0..3).map(|i| map(&format!("m{i}"), 1024, 400)).collect();
    assert_eq!(over_limit(&small, &image), 1 << 20);
    image.maps.pop();
    small.load_image_bytes(&image.to_bytes()).unwrap();
}

/// `&extern` tokens in code, `.rodata` tables, and `.data` tables call host closures and plugin exports (including
/// stack arguments and metered fuel) with `RawCalls::OFF` and `Passthrough::OFF`, and round-trip in prepared images.
#[test]
fn tokens_call_host_closures_and_exports_without_raw_calls() {
    let config = VmConfig {
        #[cfg(feature = "fuel")]
        instruction_limit: 100_000,
        ..VmConfig::default()
    };
    let vm = Vm::with_config(config).unwrap();
    vm.register_extern("tok_host", |(a, b): (u64, u64)| a.wrapping_add(b));
    vm.register_extern_with_memory("tok_checked", |mem, (buf, len): (u64, u64)| {
        let bytes = mem.read_vec(buf, len as usize)?;
        Ok::<_, rvm::MemoryError>(bytes.iter().map(|&b| u64::from(b)).sum::<u64>())
    });
    type Six = (u64, u64, u64, u64, u64, u64);
    vm.register_extern("tok_stack", |(a, b, c, d, e, f): Six| a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6);

    // Export a guest function as `tok_nat` to exercise metered plugin-export token calls too.
    let mut asm = ebpf_asm::Assembler::new();
    asm.mov64(ebpf_asm::R0, ebpf_asm::R1)
        .mul64(ebpf_asm::R0, ebpf_asm::R2)
        .exit();
    let mut exp_img = Image::from_code(asm.assemble().unwrap());
    exp_img.functions[0].0 = "tok_nat".into();
    let provider = Plugin::new("provider", vm.load_image(exp_img).unwrap());
    vm.export(&provider, "tok_nat").unwrap();

    let image = Vm::new().prepare_elf(&object("tests/tokens.o")).unwrap();
    assert!(!image.tokens.is_empty());
    let bytes = image.to_bytes();
    assert_eq!(Image::from_bytes(&bytes).unwrap(), image);

    let mut prog = vm.load_image_bytes(&bytes).unwrap();
    for (func, idx, want) in [
        ("call_code_token", 0, 13),
        ("call_code_token", 1, 42),
        ("call_ro_token", 0, 13),
        ("call_rw_token", 0, 42),
    ] {
        assert_eq!(prog.call(func, &[idx, 6, 7]).unwrap(), want, "{func}({idx})");
    }
    assert_eq!(prog.call("call_checked_token", &[0]).unwrap(), 10);
    assert_eq!(prog.call("call_stack_token", &[1]).unwrap(), 1 + 2 * 2 + 3 * 3 + 4 * 4 + 5 * 5 + 6 * 6);
}
