//! Basic example: Execute a simple eBPF program.
//!
//! This example demonstrates the minimal setup needed to run eBPF bytecode.
//! We manually construct the bytecode here to avoid needing an external .o file.
//!
//! Run with: cargo run --example hello

use rvm::VmMemory;

fn main() {
    println!("=== Hello rvm ===\n");

    // Create a simple program that computes: r0 = r1 + 10
    //
    // Instructions:
    //   mov r0, r1      ; r0 = arg1
    //   add r0, 10      ; r0 += 10
    //   exit            ; return r0
    let program = build_program(&[
        insn_mov_reg(0, 1),  // r0 = r1
        insn_add_imm(0, 10), // r0 += 10
        insn_exit(),         // exit
    ]);

    // Create memory and load the program
    let mut memory = VmMemory::new(program.len() + 512); // code + stack
    memory.write_bytes(0, &program).unwrap();

    // Create executor and run
    let helpers = rvm::HelperRegistry::new();
    let stack_top = (program.len() + 512) as u64;
    let mut executor = rvm::Executor::new(&mut memory, &helpers, stack_top);

    // Call with argument r1 = 32
    let result = executor.call(0, &[32]).unwrap();

    println!("Input:  32");
    println!("Output: {} (expected: 42)", result);
    assert_eq!(result, 42);

    println!("\nSuccess!");
}

// ============================================================================
// Instruction builders (little-endian eBPF format)
// ============================================================================

/// MOV dst, src (64-bit register move)
fn insn_mov_reg(dst: u8, src: u8) -> u64 {
    // opcode 0xbf = ALU64 | MOV | SRC_REG
    let opc = 0xbfu64;
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    opc | dst | src
}

/// ADD dst, imm (64-bit immediate add)
fn insn_add_imm(dst: u8, imm: i32) -> u64 {
    // opcode 0x07 = ALU64 | ADD | SRC_IMM
    let opc = 0x07u64;
    let dst = (dst as u64) << 8;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | imm
}

/// EXIT (return r0)
fn insn_exit() -> u64 {
    0x95 // JMP | EXIT
}

/// Build program bytes from instructions
fn build_program(insns: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
        bytes.extend_from_slice(&insn.to_le_bytes());
    }
    bytes
}
