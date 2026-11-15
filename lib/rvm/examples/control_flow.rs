//! Control flow example: Jumps and conditionals.
//!
//! This example demonstrates various jump instructions including
//! unconditional jumps, conditional jumps, and comparisons.
//!
//! Run with: cargo run --example control_flow

use ebpf_asm::{Assembler, R0, R1};
use rvm::{Perms, VmMemory};

fn main() {
    println!("=== Control Flow ===\n");

    test_unconditional_jump();
    test_jeq();
    test_jne();
    test_jgt();
    test_jge();
    test_jlt();
    test_jle();
    test_jset();
    test_loop();

    println!("All tests passed!");
}

fn test_unconditional_jump() {
    // JA +1 (skip next instruction)
    // MOV r0, 99 (skipped)
    // MOV r0, 42
    // EXIT
    let mut asm = Assembler::new();
    let mut skip_target = asm.create_label();
    asm.ja(&skip_target); // jump over next instruction
    asm.mov64_imm(R0, 99); // skipped
    asm.set_label(&mut skip_target).unwrap();
    asm.mov64_imm(R0, 42);
    asm.exit();

    let result = run(&mut asm);
    println!("JA: skip instruction, r0 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_jeq() {
    // JEQ r1, 10, +1 (if r1 == 10, jump +1)
    // MOV r0, 0
    // MOV r0, 1
    // EXIT
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jeq_imm(R1, 10, &skip); // if r1 == 10, skip next
    asm.mov64_imm(R0, 0); // not taken
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[10]);
    println!("JEQ (true): r1=10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);

    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jeq_imm(R1, 10, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[5]);
    println!("JEQ (false): r1=5, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jne() {
    // JNE r1, 10, +1
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jne_imm(R1, 10, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[5]);
    println!("JNE (true): r1=5 != 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jgt() {
    // JGT r1, 5, +1 (unsigned greater than)
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jgt_imm(R1, 5, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[10]);
    println!("JGT (true): 10 > 5, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jge() {
    // JGE r1, 10, +1 (unsigned greater or equal)
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jge_imm(R1, 10, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[10]);
    println!("JGE (equal): 10 >= 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jlt() {
    // JLT r1, 10, +1 (unsigned less than)
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jlt_imm(R1, 10, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[5]);
    println!("JLT (true): 5 < 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jle() {
    // JLE r1, 10, +1 (unsigned less or equal)
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jle_imm(R1, 10, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[10]);
    println!("JLE (equal): 10 <= 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jset() {
    // JSET r1, 0x10, +1 (if r1 & 0x10 != 0)
    let mut asm = Assembler::new();
    let mut skip = asm.create_label();
    asm.jset_imm(R1, 0x10, &skip);
    asm.mov64_imm(R0, 0);
    asm.set_label(&mut skip).unwrap();
    asm.mov64_imm(R0, 1);
    asm.exit();

    let result = run_with_args(&mut asm, &[0x1F]);
    println!("JSET (true): 0x1F & 0x10 != 0, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_loop() {
    // Compute sum of 1..10 using a loop
    // r1 = counter (starts at 10)
    // r0 = accumulator (starts at 0)
    //
    // loop:
    //   r0 += r1
    //   r1 -= 1
    //   if r1 != 0: goto loop
    // exit
    let mut asm = Assembler::new();
    let mut loop_start = asm.create_label();

    asm.mov64_imm(R0, 0); // r0 = 0 (accumulator)
    asm.set_label(&mut loop_start).unwrap(); // loop:
    asm.add64(R0, R1); // r0 += r1
    asm.add64_imm(R1, -1); // r1 -= 1
    asm.jne_imm(R1, 0, &loop_start); // if r1 != 0, goto loop
    asm.exit();

    let result = run_with_args(&mut asm, &[10]);
    println!("LOOP: sum(1..10) = {} (expected: 55)", result);
    assert_eq!(result, 55);
}

// ============================================================================
// Runner
// ============================================================================

fn run(asm: &mut Assembler) -> u64 {
    run_with_args(asm, &[])
}

fn run_with_args(asm: &mut Assembler, args: &[u64]) -> u64 {
    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);

    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;

    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);

    executor.call(0, args).unwrap()
}
