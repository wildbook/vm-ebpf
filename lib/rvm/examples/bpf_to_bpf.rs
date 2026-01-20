//! BPF-to-BPF function calls example.
//!
//! This example demonstrates internal function calls within eBPF programs.
//! BPF-to-BPF calls use the CALL instruction with a relative offset.
//!
//! Run with: cargo run --example bpf_to_bpf

use ebpf_asm::{Assembler, R0, R1, R6, R7};
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
    let mut asm = Assembler::new();
    let mut double_fn = asm.create_label();

    // main:
    asm.call_local(&double_fn); // call double
    asm.exit();

    // double:
    asm.set_label(&mut double_fn).unwrap();
    asm.mov64(R0, R1); // r0 = r1
    asm.add64(R0, R1); // r0 += r1 (double)
    asm.exit();

    let result = run_with_args(&mut asm, &[21]);
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
    let mut asm = Assembler::new();
    let mut add_fn = asm.create_label();
    let mut inc_fn = asm.create_label();

    // main:
    asm.call_local(&add_fn); // call add
    asm.exit();

    // add:
    asm.set_label(&mut add_fn).unwrap();
    asm.call_local(&inc_fn); // call inc
    asm.add64(R0, R1); // r0 = r0 + r1
    asm.exit();

    // inc:
    asm.set_label(&mut inc_fn).unwrap();
    asm.mov64(R0, R1); // r0 = r1
    asm.add64_imm(R0, 1); // r0 += 1
    asm.exit();

    let result = run_with_args(&mut asm, &[10]);
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
    let mut asm = Assembler::new();
    let mut factorial_fn = asm.create_label();
    let mut base_case = asm.create_label();

    // entry:
    asm.call_local(&factorial_fn); // call factorial
    asm.exit();

    // factorial:
    asm.set_label(&mut factorial_fn).unwrap();
    asm.jle_imm(R1, 1, &base_case); // if r1 <= 1, jump to base case

    // Recursive case: n * factorial(n-1)
    asm.mov64(R6, R1); // save r1 to r6 (callee-saved)
    asm.add64_imm(R1, -1); // r1 = n - 1
    asm.call_local(&factorial_fn); // call factorial
    asm.mul64(R0, R6); // r0 = r0 * r6 (result * n)
    asm.exit();

    // Base case: return 1
    asm.set_label(&mut base_case).unwrap();
    asm.mov64_imm(R0, 1); // r0 = 1
    asm.exit();

    let result = run_with_args(&mut asm, &[5]); // factorial(5)
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
    let mut asm = Assembler::new();
    let mut modify_fn = asm.create_label();

    // main:
    asm.mov64_imm(R6, 100); // r6 = 100
    asm.mov64_imm(R7, 200); // r7 = 200
    asm.call_local(&modify_fn); // call modify
    asm.mov64(R0, R6); // r0 = r6
    asm.add64(R0, R7); // r0 += r7
    asm.exit();

    // modify_r6_r7:
    asm.set_label(&mut modify_fn).unwrap();
    asm.mov64_imm(R6, 0); // r6 = 0 (modified in callee)
    asm.mov64_imm(R7, 0); // r7 = 0
    asm.exit();

    let result = run_with_args(&mut asm, &[]);
    println!("Callee-saved: r6=100, r7=200 after call = {} (expected: 300)", result);
    assert_eq!(result, 300);
}

// ============================================================================
// Runner
// ============================================================================

fn run_with_args(asm: &mut Assembler, args: &[u64]) -> u64 {
    let program = asm.assemble().unwrap();

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
