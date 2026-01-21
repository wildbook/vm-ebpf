//! Function Calls Example
//!
//! Demonstrates eBPF helper calls and BPF-to-BPF local function calls.
//! Shows how to set up arguments and handle return values.
//!
//! Run with: cargo run --example function_calls

use ebpf_asm::{Assembler, Decoder, DefaultFormatter, Formatter, R0, R1, R10, R2, R3, R4};

fn main() {
    println!("=== Function Calls Example ===\n");

    // Example 1: Calling a helper function
    helper_call();

    // Example 2: BPF-to-BPF local function call
    local_function_call();

    // Example 3: Multiple function calls
    multiple_calls();

    // Example 4: Function with stack frame
    function_with_stack();
}

/// Calling an external helper function
fn helper_call() {
    println!("--- Example 1: Helper Function Call ---");
    println!("Calls helper #1 (like bpf_map_lookup_elem)\n");

    let mut asm = Assembler::new();

    // In eBPF, function arguments are passed in r1-r5
    // r0 receives the return value

    // Set up arguments for helper call
    // r1 = first argument (e.g., map pointer)
    asm.mov64_imm(R1, 0x1000);

    // r2 = second argument (e.g., key pointer)
    asm.mov64(R2, R10); // Use stack pointer
    asm.add64_imm(R2, -8); // Point to stack location

    // Call helper function #1
    // In real eBPF, helper IDs are defined by the kernel
    asm.call(1);

    // r0 now contains the return value
    // Exit with the result
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Helper call", &bytecode);
}

/// BPF-to-BPF local function call
fn local_function_call() {
    println!("--- Example 2: Local Function Call ---");
    println!("Calls a local BPF function and returns its result\n");

    let mut asm = Assembler::new();

    // Labels for our functions
    let mut main_end = asm.create_label();
    let mut double_func = asm.create_label();

    // === Main function ===
    // r1 = 21 (argument to pass)
    asm.mov64_imm(R1, 21);

    // Call our local 'double' function
    asm.call_local(&double_func);

    // r0 contains result (42)
    asm.ja(&main_end);

    // === double function ===
    // Input: r1 = value to double
    // Output: r0 = r1 * 2
    asm.set_label(&mut double_func).unwrap();

    // r0 = r1
    asm.mov64(R0, R1);

    // r0 = r0 * 2
    asm.mul64_imm(R0, 2);

    // Return to caller
    asm.exit();

    // === End of main ===
    asm.set_label(&mut main_end).unwrap();
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Local function call", &bytecode);
}

/// Multiple function calls demonstrating call convention
fn multiple_calls() {
    println!("--- Example 3: Multiple Calls ---");
    println!("Chain multiple helper calls\n");

    let mut asm = Assembler::new();

    // Call helper #1: bpf_get_current_pid_tgid (example)
    asm.call(14); // Helper ID 14

    // Save result to r6 (callee-saved register)
    // Note: In eBPF, r6-r9 are callee-saved
    asm.mov64(ebpf_asm::R6, R0);

    // Call helper #2: bpf_ktime_get_ns (example)
    asm.call(5); // Helper ID 5

    // Combine results: r0 = saved_pid ^ ktime
    asm.xor64(R0, ebpf_asm::R6);

    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Multiple calls", &bytecode);
}

/// Function with proper stack frame setup
fn function_with_stack() {
    println!("--- Example 4: Function with Stack Frame ---");
    println!("Shows stack frame usage for local variables\n");

    let mut asm = Assembler::new();

    let mut compute_func = asm.create_label();
    let mut main_end = asm.create_label();

    // === Main ===
    // Prepare arguments
    asm.mov64_imm(R1, 10);
    asm.mov64_imm(R2, 20);
    asm.mov64_imm(R3, 30);

    // Call compute function
    asm.call_local(&compute_func);

    // Exit with result
    asm.ja(&main_end);

    // === compute(a, b, c) -> a + b * c ===
    // Uses stack to save intermediate values
    asm.set_label(&mut compute_func).unwrap();

    // Save r1 (a) to stack
    asm.stxdw(R10, -8, R1);

    // r0 = r2 * r3 (b * c)
    asm.mov64(R0, R2);
    asm.mul64(R0, R3);

    // Load a from stack
    asm.ldxdw(R4, R10, -8);

    // r0 = r0 + r4 (b*c + a)
    asm.add64(R0, R4);

    // Note: In a real BPF-to-BPF call, we'd use 'exit' to return
    // The calling convention uses r0 for return value
    asm.exit();

    asm.set_label(&mut main_end).unwrap();
    asm.exit();

    let bytecode = asm.assemble().unwrap();
    print_disassembly("Function with stack", &bytecode);

    // Also show argument register usage
    println!("eBPF Calling Convention:");
    println!("  r0       - Return value");
    println!("  r1-r5    - Function arguments");
    println!("  r6-r9    - Callee-saved registers");
    println!("  r10 (fp) - Frame pointer (read-only)");
    println!();
}

/// Helper to print disassembly
fn print_disassembly(name: &str, bytecode: &[u8]) {
    let formatter = DefaultFormatter::new();
    println!("{name}:");
    for insn in Decoder::new(bytecode) {
        let offset = insn.offset();
        println!("  {offset:04x}: {}", formatter.format_to_string(&insn));
    }
    println!();
}
