//! Guest memory regions of linked programs: layout, permissions, host mapping.

use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{ExecError, Image, Perms, Plugin, Program, Region, Vm, VmError, DATA_REGION, RODATA_REGION};

use crate::common::object;

/// A program whose `main` runs `*(u64 *)r1 = r2; r0 = *(u64 *)r1`, with 8 bytes of rodata, all 1s, and 8 of data.
fn store_load(vm: &Vm) -> Program {
    let mut asm = Assembler::new();
    asm.stxdw(R1, 0, R2).ldxdw(R0, R1, 0).exit();
    let image = Image {
        rodata: vec![1; 8],
        rodata_len: 8,
        data_len: 8,
        ..Image::from_code(asm.assemble().unwrap())
    };
    vm.load_image(image).unwrap()
}

fn is_mem_fault(r: rvm::Result<u64>) -> bool {
    matches!(r, Err(VmError::Exec(ExecError::MemoryFault { .. })))
}

#[test]
fn rodata_is_read_only_data_is_writable() {
    let mut program = store_load(&Vm::new());
    let rodata = program.memory().region_base(RODATA_REGION);
    assert!(is_mem_fault(program.call("main", &[rodata, 0])));
    assert_eq!(program.memory().read::<u64>(rodata).unwrap(), 0x0101_0101_0101_0101);
    let data = program.memory().region_base(DATA_REGION);
    assert_eq!(program.call("main", &[data, 77]).unwrap(), 77);
}

#[test]
fn map_host_aliases_and_survives_fault() {
    let mut word = 0u64;
    let mut program = store_load(&Vm::new());
    // SAFETY: `word` outlives the mapping (unmapped below) and isn't touched meanwhile.
    let region = unsafe {
        program
            .memory_mut()
            .map_host(NonNull::from(&mut word).cast(), size_of::<u64>(), Perms::RW)
            .unwrap()
    };
    assert!(is_mem_fault(program.call("main", &[0xFFFF_FFFF_0000, 1])));
    assert_eq!(program.call("main", &[region.base(), 35]).unwrap(), 35);
    program.memory_mut().unmap(region).unwrap();
    assert_eq!(word, 35);
}

/// Helpers read guest pointers with the guest's permissions, so they can't leak a region the guest may only write.
#[test]
fn helpers_cannot_read_write_only_memory() {
    const EINVAL: u64 = -22i64 as u64;
    let vm = Vm::new();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    vm.enable_print(move |line| sink.lock().unwrap().push(line.to_string()));
    // SAFETY: the program runs on this thread only.
    let mut write_only = unsafe { vm.share_region(64, Perms::W) }.unwrap();
    let mut readable = unsafe { vm.share_region(64, Perms::RW) }.unwrap();
    write_only.write_bytes(0, b"secret!\0").unwrap();
    readable.write_bytes(0, b"secret!\0").unwrap();
    let (write_only, readable) = (write_only.base(), readable.base());

    let mut program = vm.load_elf(&object("tests/guest_ptrs.o")).unwrap();
    let key = u64::from_le_bytes(*b"secret!\0");
    program.map("seen").unwrap().update_as(key, 7u64, 0).unwrap();

    // each readable call shows what a leak would return
    assert_eq!(program.call("lookup", &[readable]).unwrap(), 7);
    assert_eq!(program.call("lookup", &[write_only]).unwrap(), u64::MAX);
    assert_eq!(program.call("store", &[write_only]).unwrap(), EINVAL);
    assert_eq!(program.map("seen").unwrap().get_as::<u64, u64>(0), Ok(None));
    assert_eq!(program.call("store", &[readable]).unwrap(), 0);
    assert_eq!(program.map("seen").unwrap().get_as::<u64, u64>(0), Ok(Some(key)));

    assert_eq!(program.call("print_fmt", &[readable]).unwrap(), 7);
    assert_eq!(program.call("print_fmt", &[write_only]).unwrap(), EINVAL);
    program.call("print_str", &[readable]).unwrap();
    program.call("print_str", &[write_only]).unwrap();
    assert_eq!(*lines.lock().unwrap(), ["secret!", "secret!", ""]);
}

/// A program maps host regions from the ones its VM doesn't share, unmapping one frees it for the next mapping, and
/// both run out with an error.
#[test]
fn host_regions_are_allocated() {
    let vm = Vm::new();
    // SAFETY: the programs run on this thread only.
    let shared = unsafe { vm.share_region(8, Perms::RW) }.unwrap();
    let mut program = store_load(&vm);
    let mut regions = Vec::new();
    let err = loop {
        match program.memory_mut().map(8, Perms::RW) {
            Ok(region) => regions.push(region),
            Err(err) => break err,
        }
    };
    assert!(matches!(err, VmError::NoFreeRegion), "{err}");
    let mut bases: Vec<u64> = regions.iter().map(Region::base).chain([shared.base()]).collect();
    bases.sort_unstable();
    bases.dedup();
    assert_eq!(bases.len(), regions.len() + 1);
    assert_eq!(program.call("main", &[shared.base(), 9]).unwrap(), 9);
    assert_eq!(shared.read::<u64>(0), Ok(9));

    let last = regions.pop().unwrap();
    let base = last.base();
    program.memory_mut().unmap(last).unwrap();
    assert!(is_mem_fault(program.call("main", &[base, 1])));
    regions.push(program.memory_mut().map(8, Perms::RW).unwrap());
    assert!(matches!(program.memory_mut().map(8, Perms::RW), Err(VmError::NoFreeRegion)));

    // a VM that shares every host region leaves none to the programs it links afterwards
    // SAFETY: as above.
    let err = loop {
        if let Err(err) = unsafe { vm.share_region(8, Perms::RW) } {
            break err;
        }
    };
    assert!(matches!(err, VmError::NoFreeRegion), "{err}");
    let mut later = store_load(&vm);
    assert!(matches!(later.memory_mut().map(8, Perms::RW), Err(VmError::NoFreeRegion)));
}

/// A region handle that outlives its program, here through `Plugin::replace`, unmaps nothing in the program that
/// replaced it, whichever region the handle names.
#[test]
fn stale_region_handle_fails() {
    let vm = Vm::new();
    let plugin = Plugin::new("p", store_load(&vm));
    let old = plugin.lock().unwrap().memory_mut().map(8, Perms::RW).unwrap();
    plugin.replace(store_load(&vm)).unwrap();

    let mut program = plugin.lock().unwrap();
    let regions: Vec<Region> = std::iter::from_fn(|| program.memory_mut().map(8, Perms::RW).ok()).collect();
    assert!(matches!(program.memory_mut().unmap(old), Err(VmError::ForeignRegion)));
    for region in &regions {
        assert_eq!(program.call("main", &[region.base(), 5]).unwrap(), 5);
    }
}
