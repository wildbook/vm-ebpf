use std::fmt::{Debug, Formatter, Result};

use crate::opcode::{AluOpc, Class, OpCode};
use crate::Instruction;

impl Debug for Instruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Instruction")
            .field("opcode", &self.opcode())
            .field("dst_reg", &self.dst_reg())
            .field("src_reg", &self.src_reg())
            .field("offset", &self.offset())
            .field("imm", &self.imm())
            .finish()
    }
}

#[rustfmt::skip]
impl Debug for OpCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut dstr = f.debug_struct("OpCode");
        dstr.field("class", &self.class());

        match self.class() {
            | Class::LdImm
            | Class::LdReg
            | Class::StImm
            | Class::StReg => {
                dstr.field("size", &self.mem_size())
                    .field("mode", &self.mem_mode());
            },

            | Class::Jmp64
            | Class::Jmp32 => {
                dstr.field("opc", &self.jmp_opc())
                    .field("src", &self.jmp_src());
            },

            | Class::Alu32
            | Class::Alu64 => {
                dstr.field("opc", &self.alu_opc());
                match self.alu_opc() == AluOpc::End {
                    true => dstr.field("end", &self.alu_end()),
                    false => dstr.field("src", &self.alu_src()),
                };

            },
        };

        dstr.finish()
    }
}
