//! Loops and Branches Example
//!
//! Demonstrates label-based control flow in eBPF assembly.
//! Shows forward jumps, backward jumps (loops), and conditional branching.
//!
//! Run with: cargo run --example loops_and_branches

use ebpf_asm::{decode_all, Assembler, DefaultFormatter, Formatter, R0, R1, R2};

fn main() {
    println!("=== Loops and Branches Example ===\n");

    // Example 1: Simple countdown loop
    countdown_loop();

    // Example 2: Conditional branching (if-else)
    conditional_branch();

    // Example 3: Nested conditions
    nested_conditions();

    // Example 4: Sum numbers 1 to N
    sum_to_n();
}

/// Countdown from 10 to 0
fn countdown_loop() {
    println!("--- Example 1: Countdown Loop ---");
    println!("Counts down from 10 to 0\n");

    let mut asm = Assembler::new();

    // Create a label for the loop start
    let mut loop_start = asm.create_label();

    // r0 = 10 (our counter)
    asm.mov64_imm(R0, 10);

    // loop_start:
    asm.set_label(&mut loop_start).unwrap();

    // r0 = r0 - 1
    asm.sub64_imm(R0, 1);

    // if r0 != 0, jump back to loop_start
    asm.jne_imm(R0, 0, &loop_start);

    // return r0 (will be 0)
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Countdown loop", &bytecode);
}

/// If-else: return different values based on condition
fn conditional_branch() {
    println!("--- Example 2: Conditional Branch ---");
    println!("If r1 > 10, return 1; else return 0\n");

    let mut asm = Assembler::new();

    // Create labels
    let mut else_branch = asm.create_label();
    let mut end = asm.create_label();

    // Check if r1 > 10
    // jle r1, 10, else_branch (if r1 <= 10, go to else)
    asm.jle_imm(R1, 10, &else_branch);

    // Then branch: r0 = 1
    asm.mov64_imm(R0, 1);
    asm.ja(&end); // skip else

    // else_branch: r0 = 0
    asm.set_label(&mut else_branch).unwrap();
    asm.mov64_imm(R0, 0);

    // end:
    asm.set_label(&mut end).unwrap();
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Conditional branch", &bytecode);
}

/// Nested conditions: classify a value
fn nested_conditions() {
    println!("--- Example 3: Nested Conditions ---");
    println!("Classify r1: <0 -> -1, 0 -> 0, >0 -> 1\n");

    let mut asm = Assembler::new();

    // Labels for different branches
    let mut check_positive = asm.create_label();
    let mut is_zero = asm.create_label();
    let mut is_positive = asm.create_label();
    let mut done = asm.create_label();

    // First check: is r1 < 0? (signed comparison)
    // jsge r1, 0, check_positive (if r1 >= 0, check if positive)
    asm.jsge_imm(R1, 0, &check_positive);

    // r1 < 0: return -1
    asm.mov64_imm(R0, -1);
    asm.ja(&done);

    // check_positive:
    asm.set_label(&mut check_positive).unwrap();

    // Is r1 == 0?
    asm.jeq_imm(R1, 0, &is_zero);

    // r1 > 0: return 1
    asm.ja(&is_positive);

    // is_zero:
    asm.set_label(&mut is_zero).unwrap();
    asm.mov64_imm(R0, 0);
    asm.ja(&done);

    // is_positive:
    asm.set_label(&mut is_positive).unwrap();
    asm.mov64_imm(R0, 1);

    // done:
    asm.set_label(&mut done).unwrap();
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Nested conditions", &bytecode);
}

/// Calculate sum of 1 + 2 + ... + N (where N is in r1)
fn sum_to_n() {
    println!("--- Example 4: Sum 1 to N ---");
    println!("Computes 1 + 2 + ... + r1\n");

    let mut asm = Assembler::new();

    let mut loop_start = asm.create_label();
    let mut done = asm.create_label();

    // r0 = 0 (accumulator)
    asm.mov64_imm(R0, 0);

    // r2 = r1 (copy N to r2 as our counter)
    asm.mov64(R2, R1);

    // If N <= 0, skip to done
    asm.jle_imm(R2, 0, &done);

    // loop_start:
    asm.set_label(&mut loop_start).unwrap();

    // r0 = r0 + r2 (add current counter to sum)
    asm.add64(R0, R2);

    // r2 = r2 - 1 (decrement counter)
    asm.sub64_imm(R2, 1);

    // if r2 > 0, continue loop
    asm.jgt_imm(R2, 0, &loop_start);

    // done:
    asm.set_label(&mut done).unwrap();
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Sum 1 to N", &bytecode);

    // Show how it looks with instruction indices
    println!("With instruction indices:");
    let instructions = decode_all(&bytecode);
    let formatter = DefaultFormatter::new();
    for (idx, insn) in instructions.iter().enumerate() {
        let offset = insn.offset();
        println!("  [{idx:2}] {offset:04x}: {}", formatter.format_to_string(insn));
    }
    println!();
}

/// Helper to print disassembly
fn print_disassembly(name: &str, bytecode: &[u8]) {
    let formatter = DefaultFormatter::new();
    println!("{name}:");
    for insn in ebpf_asm::Decoder::new(bytecode) {
        let offset = insn.offset();
        println!("  {offset:04x}: {}", formatter.format_to_string(&insn));
    }
    println!();
}
