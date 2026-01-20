//! Control flow example: Jumps and conditionals.
//!
//! This example demonstrates various jump instructions including
//! unconditional jumps, conditional jumps, and comparisons.
//!
//! Run with: cargo run --example control_flow

use rvm::VmMemory;

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
    let result = run(&[
        insn_ja(1),          // jump over next instruction
        insn_mov_imm(0, 99), // skipped
        insn_mov_imm(0, 42),
        insn_exit(),
    ]);
    println!("JA: skip instruction, r0 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_jeq() {
    // JEQ r1, 10, +1 (if r1 == 10, jump +1)
    // MOV r0, 0
    // MOV r0, 1
    // EXIT
    let result = run_with_args(
        &[
            insn_jeq_imm(1, 10, 1), // if r1 == 10, skip next
            insn_mov_imm(0, 0),     // not taken
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[10],
    );
    println!("JEQ (true): r1=10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);

    let result = run_with_args(
        &[
            insn_jeq_imm(1, 10, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[5],
    );
    println!("JEQ (false): r1=5, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jne() {
    // JNE r1, 10, +1
    let result = run_with_args(
        &[
            insn_jne_imm(1, 10, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[5],
    );
    println!("JNE (true): r1=5 != 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jgt() {
    // JGT r1, 5, +1 (unsigned greater than)
    let result = run_with_args(
        &[
            insn_jgt_imm(1, 5, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[10],
    );
    println!("JGT (true): 10 > 5, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jge() {
    // JGE r1, 10, +1 (unsigned greater or equal)
    let result = run_with_args(
        &[
            insn_jge_imm(1, 10, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[10],
    );
    println!("JGE (equal): 10 >= 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jlt() {
    // JLT r1, 10, +1 (unsigned less than)
    let result = run_with_args(
        &[
            insn_jlt_imm(1, 10, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[5],
    );
    println!("JLT (true): 5 < 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jle() {
    // JLE r1, 10, +1 (unsigned less or equal)
    let result = run_with_args(
        &[
            insn_jle_imm(1, 10, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[10],
    );
    println!("JLE (equal): 10 <= 10, r0 = {} (expected: 1)", result);
    assert_eq!(result, 1);
}

fn test_jset() {
    // JSET r1, 0x10, +1 (if r1 & 0x10 != 0)
    let result = run_with_args(
        &[
            insn_jset_imm(1, 0x10, 1),
            insn_mov_imm(0, 0),
            insn_mov_imm(0, 1),
            insn_exit(),
        ],
        &[0x1F],
    );
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
    let result = run_with_args(
        &[
            insn_mov_imm(0, 0), // r0 = 0 (accumulator)
            // loop: (PC = 1)
            insn_add_reg(0, 1),     // r0 += r1
            insn_add_imm(1, -1),    // r1 -= 1
            insn_jne_imm(1, 0, -3), // if r1 != 0, jump back to loop (offset -3 from next insn)
            insn_exit(),
        ],
        &[10],
    );
    println!("LOOP: sum(1..10) = {} (expected: 55)", result);
    assert_eq!(result, 55);
}

// ============================================================================
// Runner
// ============================================================================

fn run(insns: &[u64]) -> u64 {
    run_with_args(insns, &[])
}

fn run_with_args(insns: &[u64], args: &[u64]) -> u64 {
    let program: Vec<u8> = insns.iter().flat_map(|i| i.to_le_bytes()).collect();

    let code_size = program.len();
    let stack_size = 512;
    let total_size = ((code_size + 7) / 8) * 8 + stack_size;

    let mut memory = VmMemory::new(total_size);
    memory.write_bytes(0, &program).unwrap();

    let helpers = rvm::HelperRegistry::new();
    let stack_top = total_size as u64;
    let mut executor = rvm::Executor::new(&mut memory, &helpers, stack_top);

    executor.call(0, args).unwrap()
}

// ============================================================================
// Instruction builders
// ============================================================================

fn insn_mov_imm(dst: u8, imm: i32) -> u64 {
    let opc = 0xb7u64; // ALU64 | MOV | IMM
    let dst = (dst as u64) << 8;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | imm
}

fn insn_add_reg(dst: u8, src: u8) -> u64 {
    let opc = 0x0fu64; // ALU64 | ADD | REG
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    opc | dst | src
}

fn insn_add_imm(dst: u8, imm: i32) -> u64 {
    let opc = 0x07u64; // ALU64 | ADD | IMM
    let dst = (dst as u64) << 8;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | imm
}

fn insn_exit() -> u64 {
    0x95
}

// Unconditional jump
fn insn_ja(off: i16) -> u64 {
    let opc = 0x05u64; // JMP | JA
    let off = ((off as u16) as u64) << 16;
    opc | off
}

// Conditional jumps with immediate
fn jmp_imm(opc: u8, dst: u8, imm: i32, off: i16) -> u64 {
    let opc = opc as u64;
    let dst = (dst as u64) << 8;
    let off = ((off as u16) as u64) << 16;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | off | imm
}

fn insn_jeq_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0x15, dst, imm, off) // JMP | JEQ | IMM
}

fn insn_jne_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0x55, dst, imm, off) // JMP | JNE | IMM
}

fn insn_jgt_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0x25, dst, imm, off) // JMP | JGT | IMM
}

fn insn_jge_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0x35, dst, imm, off) // JMP | JGE | IMM
}

fn insn_jlt_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0xa5, dst, imm, off) // JMP | JLT | IMM
}

fn insn_jle_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0xb5, dst, imm, off) // JMP | JLE | IMM
}

fn insn_jset_imm(dst: u8, imm: i32, off: i16) -> u64 {
    jmp_imm(0x45, dst, imm, off) // JMP | JSET | IMM
}
