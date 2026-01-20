//! BPF-to-BPF function calls example.
//!
//! This example demonstrates internal function calls within eBPF programs.
//! BPF-to-BPF calls use the CALL instruction with a relative offset.
//!
//! Run with: cargo run --example bpf_to_bpf

use rvm::VmMemory;

fn main() {
    println!("=== BPF-to-BPF Function Calls ===\n");

    test_simple_call();
    test_nested_calls();
    test_recursive_factorial();
    test_callee_saved_registers();

    println!("All tests passed!");
}

fn test_simple_call() {
    // Main function calls a helper that doubles the input
    //
    // main:          ; PC=0
    //   call double  ; call function at PC=3
    //   exit
    //
    // double:        ; PC=3
    //   r0 = r1 + r1
    //   exit
    let result = run_with_args(
        &[
            // main: PC=0
            insn_call(2), // call PC+1+2 = PC=3 (double)
            insn_exit(),  // PC=1
            // padding
            insn_mov_imm(0, 0), // PC=2 (unused)
            // double: PC=3
            insn_mov_reg(0, 1), // r0 = r1
            insn_add_reg(0, 1), // r0 += r1 (double)
            insn_exit(),
        ],
        &[21],
    );
    println!("Simple call: double(21) = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_nested_calls() {
    // main calls add, which calls inc
    //
    // main:      ; PC=0
    //   call add ; PC=3
    //   exit
    //
    // add:       ; PC=3
    //   call inc ; PC=7
    //   r0 = r1 + r0
    //   exit
    //
    // inc:       ; PC=7
    //   r0 = r1 + 1
    //   exit
    let result = run_with_args(
        &[
            // main: PC=0
            insn_call(2),       // call PC=3 (add)
            insn_exit(),        // PC=1
            insn_mov_imm(0, 0), // PC=2 (padding)
            // add: PC=3
            insn_call(3),       // call PC=7 (inc)
            insn_add_reg(0, 1), // r0 = r0 + r1 (add result of inc to r1)
            insn_exit(),        // PC=5
            insn_mov_imm(0, 0), // PC=6 (padding)
            // inc: PC=7
            insn_mov_reg(0, 1), // r0 = r1
            insn_add_imm(0, 1), // r0 += 1
            insn_exit(),
        ],
        &[10],
    );
    // inc(10) = 11, add returns inc(10) + 10 = 21
    println!("Nested calls: add(10) where add calls inc = {} (expected: 21)", result);
    assert_eq!(result, 21);
}

fn test_recursive_factorial() {
    // Compute factorial recursively (limited to small values to avoid stack overflow)
    //
    // factorial(n):
    //   if n <= 1: return 1
    //   else: return n * factorial(n-1)
    //
    // Layout:
    //   PC=0: entry - jump to factorial
    //   PC=1: factorial function
    let result = run_with_args(
        &[
            // entry: PC=0
            insn_call(1), // call factorial at PC=2
            insn_exit(),  // PC=1
            // factorial: PC=2
            // Check if r1 <= 1
            insn_jle_imm(1, 1, 5), // if r1 <= 1, jump to base case (PC+1+5 = PC=8)
            // Recursive case: n * factorial(n-1)
            insn_mov_reg(6, 1),  // save r1 to r6 (callee-saved)
            insn_add_imm(1, -1), // r1 = n - 1
            insn_call(-4),       // call factorial (PC+1-4 = PC=2)
            insn_mul_reg(0, 6),  // r0 = r0 * r6 (result * n)
            insn_exit(),         // PC=7
            // Base case: return 1
            insn_mov_imm(0, 1), // r0 = 1
            insn_exit(),
        ],
        &[5], // factorial(5)
    );
    println!("Recursive: factorial(5) = {} (expected: 120)", result);
    assert_eq!(result, 120);
}

fn test_callee_saved_registers() {
    // Test that callee-saved registers (r6-r9) are preserved across calls
    //
    // main:
    //   r6 = 100
    //   r7 = 200
    //   call modify_r6_r7
    //   r0 = r6 + r7  ; should still be 100 + 200 = 300
    //   exit
    //
    // modify_r6_r7:
    //   r6 = 0
    //   r7 = 0
    //   exit
    let result = run_with_args(
        &[
            // main: PC=0
            insn_mov_imm(6, 100), // r6 = 100
            insn_mov_imm(7, 200), // r7 = 200
            insn_call(3),         // call modify at PC=6
            insn_mov_reg(0, 6),   // r0 = r6
            insn_add_reg(0, 7),   // r0 += r7
            insn_exit(),          // PC=5
            // modify_r6_r7: PC=6
            insn_mov_imm(6, 0), // r6 = 0 (modified in callee)
            insn_mov_imm(7, 0), // r7 = 0
            insn_exit(),
        ],
        &[],
    );
    println!("Callee-saved: r6=100, r7=200 after call = {} (expected: 300)", result);
    assert_eq!(result, 300);
}

// ============================================================================
// Runner
// ============================================================================

fn run_with_args(insns: &[u64], args: &[u64]) -> u64 {
    let program: Vec<u8> = insns.iter().flat_map(|i| i.to_le_bytes()).collect();

    let code_size = program.len();
    let stack_size = 4096; // Larger stack for recursive calls
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

fn insn_mov_reg(dst: u8, src: u8) -> u64 {
    let opc = 0xbfu64; // ALU64 | MOV | REG
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    opc | dst | src
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

fn insn_mul_reg(dst: u8, src: u8) -> u64 {
    let opc = 0x2fu64; // ALU64 | MUL | REG
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    opc | dst | src
}

fn insn_exit() -> u64 {
    0x95 // EXIT
}

// BPF-to-BPF call (pseudo-call with relative offset)
fn insn_call(off: i32) -> u64 {
    // CALL instruction with src=BPF_PSEUDO_CALL (1)
    // Offset is in imm field for BPF_PSEUDO_CALL
    let opc = 0x85u64; // JMP | CALL
    let src = 1u64 << 12; // BPF_PSEUDO_CALL = 1
    let imm = ((off as u32) as u64) << 32;
    opc | src | imm
}

fn insn_jle_imm(dst: u8, imm: i32, off: i16) -> u64 {
    let opc = 0xb5u64; // JMP | JLE | IMM
    let dst = (dst as u64) << 8;
    let off = ((off as u16) as u64) << 16;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | off | imm
}
