//! Memory access example: Read and write memory from eBPF.
//!
//! This example demonstrates load/store operations with different sizes.
//!
//! Run with: cargo run --example memory

use ebpf_asm::{Assembler, R0, R1, R2, R3};
use rvm::{Perms, VmMemory};

fn main() {
    println!("=== Memory Access ===\n");

    test_store_load_byte();
    test_store_load_half();
    test_store_load_word();
    test_store_load_dword();
    test_memory_with_offset();

    println!("All tests passed!");
}

fn test_store_load_byte() {
    // Store byte and load it back
    // r1 = data_ptr, store 0x42 at [r1], load it to r0
    let mut asm = Assembler::new();
    asm.mov64_imm(R2, 0x42); // r2 = 0x42
    asm.stxb(R1, 0, R2); // *(u8*)(r1+0) = r2
    asm.ldxb(R0, R1, 0); // r0 = *(u8*)(r1+0)
    asm.exit();

    let result = run_with_data(&mut asm);
    println!("BYTE: store 0x42, load = 0x{:02X} (expected: 0x42)", result);
    assert_eq!(result, 0x42);
}

fn test_store_load_half() {
    // Store halfword (16-bit)
    let mut asm = Assembler::new();
    asm.mov64_imm(R2, 0x1234);
    asm.stxh(R1, 0, R2); // *(u16*)(r1+0) = r2
    asm.ldxh(R0, R1, 0); // r0 = *(u16*)(r1+0)
    asm.exit();

    let result = run_with_data(&mut asm);
    println!("HALF: store 0x1234, load = 0x{:04X} (expected: 0x1234)", result);
    assert_eq!(result, 0x1234);
}

fn test_store_load_word() {
    // Store word (32-bit)
    let mut asm = Assembler::new();
    asm.mov64_imm(R2, 0x12345678u32 as i32);
    asm.stxw(R1, 0, R2); // *(u32*)(r1+0) = r2
    asm.ldxw(R0, R1, 0); // r0 = *(u32*)(r1+0)
    asm.exit();

    let result = run_with_data(&mut asm);
    println!("WORD: store 0x12345678, load = 0x{:08X} (expected: 0x12345678)", result);
    assert_eq!(result, 0x12345678);
}

fn test_store_load_dword() {
    // Store doubleword (64-bit) using LD_IMM64
    let mut asm = Assembler::new();
    asm.lddw(R2, 0xDEADBEEFCAFEBABEu64 as i64); // r2 = 0xDEADBEEFCAFEBABE
    asm.stxdw(R1, 0, R2); // *(u64*)(r1+0) = r2
    asm.ldxdw(R0, R1, 0); // r0 = *(u64*)(r1+0)
    asm.exit();

    let result = run_with_data(&mut asm);
    println!("DWORD: store 0xDEADBEEFCAFEBABE, load = 0x{:016X}", result);
    assert_eq!(result, 0xDEADBEEFCAFEBABE);
}

fn test_memory_with_offset() {
    // Store at offset and load back
    let mut asm = Assembler::new();
    asm.mov64_imm(R2, 0xAA);
    asm.stxb(R1, 5, R2); // *(u8*)(r1+5) = r2
    asm.mov64_imm(R2, 0xBB);
    asm.stxb(R1, 10, R2); // *(u8*)(r1+10) = r2
    asm.ldxb(R0, R1, 5); // r0 = *(u8*)(r1+5)
    asm.ldxb(R3, R1, 10); // r3 = *(u8*)(r1+10)
    asm.add64(R0, R3); // r0 += r3
    asm.exit();

    let result = run_with_data(&mut asm);
    println!("OFFSET: [5]=0xAA, [10]=0xBB, sum = 0x{:02X} (expected: 0x165)", result);
    assert_eq!(result, 0xAA + 0xBB);
}

// ============================================================================
// Runner with data area
// ============================================================================

fn run_with_data(asm: &mut Assembler) -> u64 {
    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);

    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;
    let data_base = memory.map(rvm::FIRST_FREE_REGION, 128, Perms::RW);

    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);

    // Pass data area pointer in r1
    executor.call(0, &[data_base]).unwrap()
}
