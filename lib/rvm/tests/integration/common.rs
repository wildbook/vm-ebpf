//! Fixture loading and the host setup shared by the integration tests.

use rvm::{HostTypes, Module, Plugin, Vm, VmConfig};

/// Read a compiled fixture by its path under `bpf/prebuilt/`.
pub fn object(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../bpf/prebuilt/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The host's `struct bits`: a signed 12-bit `b` at bit 20, where `bpf/tests/core_bitfield.c` has it elsewhere.
pub fn describe_bits(types: &mut HostTypes) {
    let u32_t = types.add_int("unsigned int", 4, false);
    let i32_t = types.add_int("int", 4, true);
    let bits = types.add_struct("bits", 4);
    types.bitfield_member(bits, "reserved", 0, 20, u32_t);
    types.bitfield_member(bits, "b", 20, 12, i32_t);
}

/// A VM with every extern, helper and host type the fixtures use, so most of them link and their CO-RE relocations have
/// candidates to match.
pub fn host_vm() -> Vm {
    host_vm_with(VmConfig::default())
}

/// [`host_vm`] with `config`.
pub fn host_vm_with(config: VmConfig) -> Vm {
    let vm = Vm::with_config(config).unwrap();
    let host = Module::from_elf(&object("tests/host_event.o")).unwrap();
    vm.with_types(|types| {
        types.append_btf(host.btf().unwrap()).unwrap();
        describe_bits(types);
    });

    vm.register_helper(100, |x: u64| x * 2);
    vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);
    vm.register_extern("host_reenter", |x: u64| x);
    vm.enable_time();
    vm.enable_random();
    vm.enable_print(|_| {});
    let a = Plugin::new("a", vm.load_elf(&object("tests/plugin_a_v1.o")).unwrap());
    vm.export(&a, "a_scale").unwrap();
    let callee = Plugin::new("callee", vm.load_elf(&object("tests/borrow_callee.o")).unwrap());
    for func in ["sum", "fill", "poke"] {
        vm.export(&callee, func).unwrap();
    }
    vm
}
