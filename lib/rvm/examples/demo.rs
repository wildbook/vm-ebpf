#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::ops::ControlFlow;

use hex_literal::hex;
use rvm::{Context, Flow, Instruction, Memory};

const fn parse_instructions<const N: usize>(data: [u8; N * 8]) -> [Instruction; N] {
    let mut instructions = [Instruction(0); N];

    let mut i = 0;
    while i < N {
        let value = u64::from_ne_bytes([
            data[i * 8 + 0],
            data[i * 8 + 1],
            data[i * 8 + 2],
            data[i * 8 + 3],
            data[i * 8 + 4],
            data[i * 8 + 5],
            data[i * 8 + 6],
            data[i * 8 + 7],
        ]);

        instructions[i] = Instruction(value);
        i += 1;
    }

    instructions
}

pub enum CallResult {
    Return,
    Failure,
}

#[inline(always)]
pub fn call<C: Memory>(ctx: &mut Context<C>, mut pc: usize, code: &[Instruction]) -> ControlFlow<()> {
    loop {
        let instr = code[pc];
        pc += 1;

        match rvm::step(ctx, instr) {
            Flow::Next => continue,
            Flow::Exit => break ControlFlow::Continue(()),
            Flow::FailCpu => break ControlFlow::Break(()),
            Flow::FailMem(_) => break ControlFlow::Break(()),
            Flow::Call(offset) => call(ctx, pc.wrapping_add_signed(offset as isize), code)?,
            Flow::Jump(offset) => pc = pc.wrapping_add_signed(offset as isize),

            Flow::CallExt(x) => todo!("syscall: {x}"), // todo: syscall(ctx)?,
            Flow::Missing => todo!(),
        }
    }
}

#[rustfmt::skip]
const CODE: [u8; 24] = hex!("
b7 01 00 00 0a 00 00 00
85 20 00 00 05 00 00 00
95 00 00 00 00 00 00 00
");

const INSN: [Instruction; 3] = parse_instructions(CODE);

#[inline(never)]
pub fn run_math(a1: u64, a2: u64) -> u64 {
    let mut ctx = Context::<()> {
        regs: [0; 16],
        data: (),
    };

    ctx.regs[1] = a1;
    ctx.regs[2] = a2;

    call(&mut ctx, 0, &INSN);

    ctx.regs[0]
}

pub fn main() {
    println!("{:?}", run_math(3, 5));
}
