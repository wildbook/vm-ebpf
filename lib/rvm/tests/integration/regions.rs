//! Guest memory regions of linked programs: layout, permissions, host mapping.

use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{region_base, ExecError, Image, Perms, Program, Vm, VmError, DATA_REGION, FIRST_FREE_REGION, RODATA_REGION};

use crate::common::object;

fn example() -> Program {
    Vm::new().load_elf(&object("examples/example.o")).unwrap()
}

/// A program whose `main` runs `*(u64 *)r1 = r2; r0 = *(u64 *)r1`, with 8 bytes of rodata, all 1s, and 8 of data.
fn store_load() -> Program {
    let mut asm = Assembler::new();
    asm.stxdw(R1, 0, R2).ldxdw(R0, R1, 0).exit();
    let image = Image {
        rodata: vec![1; 8],
        rodata_len: 8,
        data_len: 8,
        ..Image::from_code(asm.assemble().unwrap())
    };
    Vm::new().load_image(image).unwrap()
}

fn is_mem_fault(r: rvm::Result<u64>) -> bool {
    matches!(r, Err(VmError::Exec(ExecError::MemoryFault { .. })))
}

#[test]
fn rodata_is_read_only_data_is_writable() {
    let mut program = Vm::new().load_elf(&object("examples/example.o")).unwrap();
    assert_eq!(program.call("return_magic", &[]).unwrap(), 0xDEAD_BEEF_CAFE_BABE);

    let mut program = store_load();
    let rodata = region_base(RODATA_REGION);
    assert!(is_mem_fault(program.call("main", &[rodata, 0])));
    assert_eq!(program.memory().read::<u64>(rodata).unwrap(), 0x0101_0101_0101_0101);
    assert_eq!(program.call("main", &[region_base(DATA_REGION), 77]).unwrap(), 77);
}

/// `bpf_main` writes through host-mapped structs; the writes must not land on other code.
#[test]
fn bpf_main_globals_do_not_clobber_code() {
    #[repr(C)]
    struct Input {
        a: u64,
        b: u64,
        op: u32,
        flags: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Output {
        result: u64,
        status: u32,
        reserved: u32,
    }

    let input = Input {
        a: 5,
        b: 7,
        op: 2, // mul
        flags: 0,
    };
    let mut output = Output::default();
    let mut program = example();
    let mut mem = program.memory_mut();
    // SAFETY: both structs outlive the mappings (unmapped below) and aren't touched meanwhile.
    let (ctx, out) = unsafe {
        (
            mem.map_host(FIRST_FREE_REGION, NonNull::from(&input).cast(), size_of::<Input>(), Perms::R)
                .unwrap(),
            mem.map_host(FIRST_FREE_REGION + 1, NonNull::from(&mut output).cast(), size_of::<Output>(), Perms::RW)
                .unwrap(),
        )
    };

    assert_eq!(program.call("bpf_main", &[ctx, out]).unwrap(), 0);
    program.memory_mut().unmap(FIRST_FREE_REGION).unwrap();
    program.memory_mut().unmap(FIRST_FREE_REGION + 1).unwrap();
    assert_eq!((output.result, output.status), (35, 0));
    assert_eq!(program.call("simple_add", &[2, 3]).unwrap(), 5);
}

#[test]
fn memory_survives_fault() {
    let mut program = example();
    assert!(program.call("bpf_main", &[0xFFFF_FFFF_0000, 0xFFFF_FFFF_0000]).is_err());
    assert_eq!(program.call("simple_add", &[2, 3]).unwrap(), 5);
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
    let mut write_only = unsafe { vm.share_region(FIRST_FREE_REGION, 64, Perms::W) }.unwrap();
    let mut readable = unsafe { vm.share_region(FIRST_FREE_REGION + 1, 64, Perms::RW) }.unwrap();
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
