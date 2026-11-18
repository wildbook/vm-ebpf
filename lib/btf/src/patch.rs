//! Writing resolved CO-RE values into eBPF instructions.

use crate::core_relo::{CoreReloError, ResolvedRelo};
use crate::ext::CoreRelo;

/// Helper ID that unresolved relocations call, as in libbpf: running such an instruction must fail, while a program
/// that never reaches it still works.
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// `call CORE_POISON_HELPER`, written over every slot of a poisoned instruction.
const POISON: [u8; 8] = {
    let [a, b, c, d] = CORE_POISON_HELPER.to_le_bytes();
    [0x85, 0, 0, 0, a, b, c, d]
};

const CLASS_MASK: u8 = 0x07;
const LD: u8 = 0x00;
const LDX: u8 = 0x01;
const ST: u8 = 0x02;
const STX: u8 = 0x03;
const ALU: u8 = 0x04;
const ALU64: u8 = 0x07;
const BPF_SRC_X: u8 = 0x08;
const BPF_LD_IMM64: u8 = 0x18;

/// Patch the relocated value into an instruction, as libbpf's `bpf_core_patch_insn` does. Returns whether the
/// instruction was poisoned instead (for the caller's `Unresolved` list).
pub fn patch_instruction(insns: &mut [[u8; 8]], relo: &CoreRelo, res: &ResolvedRelo) -> Result<bool, CoreReloError> {
    if relo.insn_off % 8 != 0 {
        return Err(CoreReloError::InstructionOutOfBounds(relo.insn_off));
    }
    let idx = (relo.insn_off / 8) as usize;
    let insn = *insns
        .get(idx)
        .ok_or(CoreReloError::InstructionOutOfBounds(relo.insn_off))?;
    let opcode = insn[0];

    match opcode & CLASS_MASK {
        ALU | ALU64 => {
            if opcode & BPF_SRC_X != 0 {
                return Err(CoreReloError::UnpatchableInstruction(relo.insn_off));
            }
            if res.poison {
                return Ok(poison(&mut insns[idx]));
            }
            check_orig(relo, res, i64::from(imm(&insn) as i32) as u64)?;
            set_imm(&mut insns[idx], res.new_val as u32);
            Ok(false)
        }
        LDX | ST | STX => {
            if res.poison {
                return Ok(poison(&mut insns[idx]));
            }
            check_orig(relo, res, i64::from(i16::from_le_bytes([insn[2], insn[3]])) as u64)?;
            if res.new_val > i16::MAX as u64 {
                return Err(CoreReloError::OffsetTooLarge {
                    insn_off: relo.insn_off,
                    value: res.new_val,
                });
            }
            if res.fail_memsz_adjust {
                return Ok(poison(&mut insns[idx]));
            }
            let insn = &mut insns[idx];
            insn[2..4].copy_from_slice(&(res.new_val as u16).to_le_bytes());

            if res.new_sz != res.orig_sz {
                let (Some(orig_sz), Some(new_sz)) = (res.orig_sz, res.new_sz) else {
                    return Err(CoreReloError::UnpatchableInstruction(relo.insn_off));
                };
                let encoded_sz = mem_size_bytes(opcode).ok_or(CoreReloError::UnpatchableInstruction(relo.insn_off))?;
                if encoded_sz != orig_sz {
                    return Err(CoreReloError::UnexpectedValue {
                        insn_off: relo.insn_off,
                        expected: u64::from(orig_sz),
                        found: u64::from(encoded_sz),
                    });
                }
                let new_mode_size =
                    bytes_to_mem_size(new_sz).ok_or(CoreReloError::UnpatchableInstruction(relo.insn_off))?;
                insn[0] = (opcode & 0xE0) | new_mode_size | (opcode & CLASS_MASK);
            }
            Ok(false)
        }
        LD => {
            let hi = *insns
                .get(idx + 1)
                .ok_or(CoreReloError::InstructionOutOfBounds(relo.insn_off + 8))?;
            let well_formed = opcode == BPF_LD_IMM64 && insn[1] >> 4 == 0 && insn[2..4] == [0; 2] && hi[..4] == [0; 4];
            if !well_formed {
                return Err(CoreReloError::UnpatchableInstruction(relo.insn_off));
            }
            if res.poison {
                insns[idx..][..2].fill(POISON);
                return Ok(true);
            }
            check_orig(relo, res, u64::from(imm(&insn)) | u64::from(imm(&hi)) << 32)?;
            set_imm(&mut insns[idx], res.new_val as u32);
            set_imm(&mut insns[idx + 1], (res.new_val >> 32) as u32);
            Ok(false)
        }
        _ => Err(CoreReloError::UnpatchableInstruction(relo.insn_off)),
    }
}

/// Fail if the relocation validates its original value and the instruction encodes `found` instead.
fn check_orig(relo: &CoreRelo, res: &ResolvedRelo, found: u64) -> Result<(), CoreReloError> {
    if res.validate && found != res.orig_val {
        return Err(CoreReloError::UnexpectedValue {
            insn_off: relo.insn_off,
            expected: res.orig_val,
            found,
        });
    }
    Ok(())
}

/// Overwrite `insn` with [`POISON`]. Returns `true` for the caller's poisoned flag.
fn poison(insn: &mut [u8; 8]) -> bool {
    *insn = POISON;
    true
}

fn imm(insn: &[u8; 8]) -> u32 {
    let [.., a, b, c, d] = *insn;
    u32::from_le_bytes([a, b, c, d])
}

fn set_imm(insn: &mut [u8; 8], imm: u32) {
    insn[4..].copy_from_slice(&imm.to_le_bytes());
}

/// The load/store size field (`opcode & 0x18`) and the access width in bytes it encodes.
const MEM_SIZES: [(u8, u32); 4] = [(0x18, 8), (0x00, 4), (0x08, 2), (0x10, 1)];

fn mem_size_bytes(opcode: u8) -> Option<u32> {
    let field = opcode & 0x18;
    MEM_SIZES.iter().find(|&&(f, _)| f == field).map(|&(_, b)| b)
}

fn bytes_to_mem_size(bytes: u32) -> Option<u8> {
    MEM_SIZES.iter().find(|&&(_, b)| b == bytes).map(|&(f, _)| f)
}
