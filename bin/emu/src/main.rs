use constelf::file::ElfFile;
use constelf::raw::{reloc, shf};
use constelf::relocs::ElfRelocsChunk;
use constelf::sections::ElfSections;
use rvm::{Executor, HelperRegistry, Memory};

const fn num_allocs(elf: ElfSections<'_>) -> usize {
    let mut num = 0;

    let mut idx = 0;
    while idx < elf.headers().len() {
        let header = elf.header_by_index(idx).unwrap();
        if (header.sh_flags & shf::ALLOC as u64) != 0 {
            num += 1;
        }

        idx += 1;
    }

    num
}

/// Index into `MAP` (not the section index) of the first executable (`SHF_EXECINSTR`) section.
const fn find_code_map_idx<const N: usize>(elf: ElfSections<'_>, map: &[AddrMapEnt; N]) -> usize {
    let mut i = 0;
    while i < map.len() {
        let header = match elf.header_by_index(map[i].sect) {
            Some(h) => h,
            None => panic!(),
        };
        if (header.sh_flags & shf::EXECINSTR as u64) != 0 && map[i].size > 0 {
            return i;
        }
        i += 1;
    }
    panic!("no executable section found")
}

#[derive(Clone, Copy, Debug)]
struct AddrMapEnt {
    sect: usize,
    addr: u64,
    size: u64,
}

const fn gen_addrmap<const N: usize>(elf: ElfSections<'_>, base: u64) -> [AddrMapEnt; N] {
    let mut addrmap = [AddrMapEnt {
        sect: 0,
        addr: 0,
        size: 0,
    }; N];

    let mut address = base;
    let mut map_idx = 0;

    let mut idx = 0;
    while idx < elf.headers().len() {
        let header = elf.header_by_index(idx).unwrap();
        if (header.sh_flags & shf::ALLOC as u64) != 0 {
            assert!(header.sh_addr == 0);
            addrmap[map_idx] = AddrMapEnt {
                sect: idx,
                addr: address,
                size: header.sh_size,
            };

            address += header.sh_size;
            map_idx += 1;
        }

        idx += 1;
    }

    addrmap
}

#[inline(never)]
fn elfin() -> anyhow::Result<()> {
    const fn ct_unwrap_opt<T: Copy /* !Drop */>(x: Option<T>) -> T {
        match x {
            Some(x) => x,
            None => panic!(),
        }
    }

    const fn ct_unwrap_res<T: Copy /* !Drop */, E: Copy>(x: Result<T, E>) -> T {
        match x {
            Ok(x) => x,
            Err(_) => panic!(),
        }
    }

    const fn copy(src: &[u8], dst: &mut [u8], offset: usize) {
        let mut i = 0;
        while i < src.len() {
            dst[offset + i] = src[i];
            i += 1;
        }
    }

    const PAGE_SIZE: usize = 8;
    const PAGE_BASE: usize = 8;
    const STACK_SIZE: usize = 512 * (rvm::MAX_CALL_DEPTH + 1); // one 512-byte eBPF frame per call level

    const RAW: &[u8; include_bytes!("../../../bpf.o").len()] = include_bytes!("../../../bpf.o");

    const ELF: ElfFile<'_> /* ----------- */ = ct_unwrap_res(ElfFile::new(RAW));
    const SCT: ElfSections<'_> /* ------- */ = ct_unwrap_res(ELF.sections());
    const MAP: [AddrMapEnt; num_allocs(SCT)] = gen_addrmap(SCT, PAGE_BASE as u64);
    const CODE_ENT: AddrMapEnt = MAP[find_code_map_idx(SCT, &MAP)];

    const LEN: usize = {
        let mut s = PAGE_BASE;
        let mut i = 0_usize;

        while i < MAP.len() {
            s = s.next_multiple_of(PAGE_SIZE);

            s += MAP[i].size as usize;
            i += 1;
        }

        // Add stack space at the end
        s = s.next_multiple_of(PAGE_SIZE);
        s += STACK_SIZE;

        s
    };

    // Stack starts after all sections, r10 points to end of stack
    const STACK_END: usize = LEN;

    const OUT: [u8; LEN] = {
        let mut flat = [0; LEN];
        let mut smap = [None; SCT.len()];

        let mut i = 0;
        while i < MAP.len() {
            smap[MAP[i].sect] = Some(i);
            i += 1;
        }

        let mut i = 0;
        while i < MAP.len() {
            let ent = MAP[i];

            let sect = ct_unwrap_opt(SCT.by_index(ent.sect));
            let data = ct_unwrap_res(sect.bytes());
            let addr = ent.addr as usize;

            let mut j = 0;
            while j < ent.size as usize {
                flat[addr + j] = data[j];
                j += 1;
            }

            i += 1;
        }

        let Ok(symtab) = SCT.symtab() else {
            panic!();
        };

        let mut reloc = ct_unwrap_res(ELF.relocs().iter());
        loop {
            let (next, chunk) = reloc.into_next();
            reloc = next;

            let Some(chunk) = chunk else {
                break;
            };

            let Some(target) = smap[chunk.target_idx()] else {
                // Relocations for unmapped sections (e.g., debug info) - skip them
                continue;
            };

            let target_ent = MAP[target];

            let rel = ct_unwrap_res(chunk.relocs());

            // Handle both REL and RELA relocation types
            // For simplicity, we process them the same way since BPF typically uses REL
            // and the addend is usually embedded in the instruction
            let (relocs, _has_addend): (&[_], bool) = match rel {
                ElfRelocsChunk::Rel(r) => (r, false),
                ElfRelocsChunk::Rela(r) => {
                    // RELA relocations have explicit addends
                    // Warning: RELA support is incomplete - addends are ignored
                    // This may cause incorrect symbol resolution for some ELF files
                    #[cfg(debug_assertions)]
                    {
                        // In debug builds, we can't easily print at const time
                        // but this documents the limitation
                    }
                    // Skip RELA sections for now - they need different handling
                    let _ = r; // suppress unused warning
                    continue;
                }
                ElfRelocsChunk::None => continue,
            };

            let mut i: usize = 0;
            while i < relocs.len() {
                let r = relocs[i];

                let r_off = r.r_offset;
                let r_sym = r.sym();
                let r_typ = r.typ();

                let symbol = ct_unwrap_opt(symtab.get(r_sym as usize));

                let seg = target_ent.addr;
                let stv = symbol.st_value;

                let beg = seg + r_off;

                match r_typ {
                    reloc::bpf::BPF_64_64 => {
                        // Get the section where the symbol is defined
                        let sym_sect_idx = symbol.st_shndx as usize;

                        // Get the mapped address of that section
                        let sym_sect_addr = match smap[sym_sect_idx] {
                            Some(map_idx) => MAP[map_idx].addr,
                            None => panic!("Symbol references unmapped section"),
                        };

                        // Final address = section base + symbol offset + REL addend (the existing imm)
                        let at = (beg + 4) as usize;
                        let imm = u32::from_le_bytes([flat[at], flat[at + 1], flat[at + 2], flat[at + 3]]);
                        let sym_addr = sym_sect_addr + stv + imm as u64;

                        // R_BPF_64_64 patches the imm32 fields of a LD_IMM64 instruction
                        // Write lower 32 bits to imm of first instruction (offset +4)
                        let lo = (sym_addr as u32).to_le_bytes();
                        copy(&lo, &mut flat, (beg + 4) as usize);

                        // Write upper 32 bits to imm of second instruction (offset +12)
                        let hi = ((sym_addr >> 32) as u32).to_le_bytes();
                        copy(&hi, &mut flat, (beg + 12) as usize);
                    }
                    _ => unimplemented!(),
                }

                i += 1;
            }
        }

        flat
    };

    struct Mem {
        data: [u8; LEN],
    }

    impl Memory for Mem {
        type Err = ();

        fn load_u8(&self, addr: u64) -> Result<u8, Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(1).ok_or(())?;
            match self.data.get(beg..end) {
                Some(s) => Ok(s[0]),
                None => Err(()),
            }
        }

        fn load_u16(&self, addr: u64) -> Result<u16, Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(2).ok_or(())?;
            match self.data.get(beg..end) {
                Some(s) => Ok(u16::from_le_bytes([s[0], s[1]])),
                None => Err(()),
            }
        }

        fn load_u32(&self, addr: u64) -> Result<u32, Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(4).ok_or(())?;
            match self.data.get(beg..end) {
                Some(s) => Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]])),
                None => Err(()),
            }
        }

        fn load_u64(&self, addr: u64) -> Result<u64, Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(8).ok_or(())?;
            match self.data.get(beg..end) {
                Some(s) => Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])),
                None => Err(()),
            }
        }

        fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(1).ok_or(())?;
            match self.data.get_mut(beg..end) {
                Some(slice) => {
                    slice.copy_from_slice(&value.to_le_bytes());
                    Ok(())
                }
                None => Err(()),
            }
        }

        fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(2).ok_or(())?;
            match self.data.get_mut(beg..end) {
                Some(slice) => {
                    slice.copy_from_slice(&value.to_le_bytes());
                    Ok(())
                }
                None => Err(()),
            }
        }

        fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(4).ok_or(())?;
            match self.data.get_mut(beg..end) {
                Some(slice) => {
                    slice.copy_from_slice(&value.to_le_bytes());
                    Ok(())
                }
                None => Err(()),
            }
        }

        fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
            let beg = addr as usize;
            let end = beg.checked_add(8).ok_or(())?;
            match self.data.get_mut(beg..end) {
                Some(slice) => {
                    slice.copy_from_slice(&value.to_le_bytes());
                    Ok(())
                }
                None => Err(()),
            }
        }
    }

    let code_beg = CODE_ENT.addr as usize;
    let code_end = code_beg + CODE_ENT.size as usize;
    let code = rvm::instructions_from_bytes(&OUT[code_beg..code_end]);
    let mut mem = Mem { data: OUT };
    let helpers = HelperRegistry::<Mem>::default();

    // r10 (frame pointer) starts at the end of the stack.
    let res = Executor::new(&code, &mut mem, &helpers, STACK_END as u64).call(0, &[]);
    println!("res: {res:?}");

    Ok(())
}

pub fn main() {
    println!("{:?}", elfin().unwrap());
}
