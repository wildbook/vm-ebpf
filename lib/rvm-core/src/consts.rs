pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

#[rustfmt::skip]
pub mod class {
    pub const BPF_LD:     u8 = 0x00;
    pub const BPF_LDX:    u8 = 0x01;
    pub const BPF_ST:     u8 = 0x02;
    pub const BPF_STX:    u8 = 0x03;
    pub const BPF_ALU_32: u8 = 0x04;
    pub const BPF_JMP_64: u8 = 0x05;
    pub const BPF_JMP_32: u8 = 0x06;
    pub const BPF_ALU_64: u8 = 0x07;
}

#[rustfmt::skip]
pub mod alu {
    pub const BPF_TO_LE: u8 = 0x00;
    pub const BPF_TO_BE: u8 = 0x08;

    pub const BPF_ADD:  u8 = 0x00;
    pub const BPF_SUB:  u8 = 0x10;
    pub const BPF_MUL:  u8 = 0x20;
    pub const BPF_DIV:  u8 = 0x30;
    pub const BPF_OR:   u8 = 0x40;
    pub const BPF_AND:  u8 = 0x50;
    pub const BPF_LSH:  u8 = 0x60;
    pub const BPF_RSH:  u8 = 0x70;
    pub const BPF_NEG:  u8 = 0x80;
    pub const BPF_MOD:  u8 = 0x90;
    pub const BPF_XOR:  u8 = 0xA0;
    pub const BPF_MOV:  u8 = 0xB0;
    pub const BPF_ARSH: u8 = 0xC0;
    pub const BPF_END:  u8 = 0xD0;
}

#[rustfmt::skip]
pub mod jmp {
    pub const BPF_JA:    u8 = 0x00;
    pub const BPF_JEQ:   u8 = 0x10;
    pub const BPF_JGT:   u8 = 0x20;
    pub const BPF_JGE:   u8 = 0x30;
    pub const BPF_JSET:  u8 = 0x40;
    pub const BPF_JNE:   u8 = 0x50;
    pub const BPF_JSGT:  u8 = 0x60;
    pub const BPF_JSGE:  u8 = 0x70;
    pub const BPF_CALL:  u8 = 0x80;
    pub const BPF_EXIT:  u8 = 0x90;
    pub const BPF_JLT:   u8 = 0xA0;
    pub const BPF_JLE:   u8 = 0xB0;
    pub const BPF_JSLT:  u8 = 0xC0;
    pub const BPF_JSLE:  u8 = 0xD0;

    pub const BPF_PSEUDO_CALL:       usize = 1;
    pub const BPF_PSEUDO_KFUNC_CALL: usize = 2;
}

#[rustfmt::skip]
pub mod mem {
    pub mod size {
        pub const BPF_W:  u8 = 0x00;
        pub const BPF_H:  u8 = 0x08;
        pub const BPF_B:  u8 = 0x10;
        pub const BPF_DW: u8 = 0x18;
    }

    pub mod mode {
        pub const BPF_IMM:    u8 = 0x00;
        pub const BPF_ABS:    u8 = 0x20;
        pub const BPF_IND:    u8 = 0x40;
        pub const BPF_MEM:    u8 = 0x60;
        pub const BPF_MEM_SX: u8 = 0x80;
        pub const BPF_ATOMIC: u8 = 0xC0;
    }
}
