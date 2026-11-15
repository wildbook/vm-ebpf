//! Guest memory regions of linked programs: layout, permissions, host mapping.

use std::ptr::NonNull;

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{
    instructions_from_bytes, region_base, ExecError, Executor, HelperRegistry, Perms, Program, Vm, VmError,
    DATA_REGION, FIRST_FREE_REGION, RODATA_REGION,
};

fn example() -> Program {
    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/example.o")).unwrap();
    Vm::new().load_elf(&elf).unwrap()
}

/// Run `*(u64 *)r1 = r2; r0 = *(u64 *)r1` against the program's memory.
fn store_load(program: &mut Program, addr: u64, value: u64) -> rvm::Result<u64> {
    let mut asm = Assembler::new();
    asm.stxdw(R1, 0, R2).ldxdw(R0, R1, 0).exit();
    let code = instructions_from_bytes(&asm.assemble().unwrap());
    let stack_top = program.stack_top();
    Executor::new(&code, program.memory_mut(), &HelperRegistry::new(), stack_top).call(0, &[addr, value])
}

fn is_mem_fault(r: rvm::Result<u64>) -> bool {
    matches!(r, Err(VmError::Exec(ExecError::MemoryFault(_))))
}

#[test]
fn null_and_unmapped_regions_fault() {
    let mut program = example();
    assert!(is_mem_fault(store_load(&mut program, 0, 1)));
    assert!(is_mem_fault(store_load(&mut program, 8, 1)));
    assert!(is_mem_fault(store_load(&mut program, region_base(FIRST_FREE_REGION), 1)));
}

#[test]
fn rodata_is_read_only_data_is_writable() {
    let mut program = example();
    let magic = region_base(RODATA_REGION) + 8; // MAX_FIB_N (u32) then MAGIC_VALUE (u64)
    assert_eq!(program.memory().read::<u64>(magic).unwrap(), 0xDEAD_BEEF_CAFE_BABE);
    assert!(is_mem_fault(store_load(&mut program, magic, 0)));
    assert_eq!(program.call("return_magic", &[]).unwrap(), 0xDEAD_BEEF_CAFE_BABE);

    assert_eq!(store_load(&mut program, region_base(DATA_REGION), 77).unwrap(), 77);
}

/// The guest reads and writes host structs in place: no copies in or out.
#[test]
fn linked_program_uses_host_mapped_structs() {
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

    let input = Input { a: 6, b: 7, op: 2, flags: 0 }; // mul
    let mut output = Output::default();
    let mut program = example();
    let mem = program.memory_mut();
    // SAFETY: both structs outlive the mappings (unmapped below) and aren't touched meanwhile.
    let (ctx, out) = unsafe {
        (
            mem.map_host(FIRST_FREE_REGION, NonNull::from(&input).cast(), size_of::<Input>(), Perms::R),
            mem.map_host(FIRST_FREE_REGION + 1, NonNull::from(&mut output).cast(), size_of::<Output>(), Perms::RW),
        )
    };

    assert_eq!(program.call("bpf_main", &[ctx, out]).unwrap(), 0);
    program.memory_mut().unmap(FIRST_FREE_REGION);
    program.memory_mut().unmap(FIRST_FREE_REGION + 1);
    assert_eq!((output.result, output.status), (42, 0));
}
