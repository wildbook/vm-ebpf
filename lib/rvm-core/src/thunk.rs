//! Static pool of 64 native-to-guest callback thunks in `.text`.
//!
//! Each thunk loads its slot index into `eax` and jumps to `rvm_thunk_common`, which saves the host C ABI arguments
//! and invokes the registered Rust dispatch callback. No executable memory is allocated or modified at run time.

use std::arch::global_asm;
use std::sync::atomic::{AtomicPtr, Ordering};

/// Number of static callback thunks in `.text`.
pub const THUNK_COUNT: usize = 64;

/// Rust entry point invoked by `rvm_thunk_common`: slot index (`0..THUNK_COUNT`), integer/stack argument array, and
/// saved floating-point argument registers (`xmm0..xmm3` on Windows x64, `xmm0..xmm4` on SysV x64).
pub type ThunkHandler = extern "C" fn(index: u32, ints: *const u64, floats: *const u64) -> u64;

extern "C" fn default_handler(_index: u32, _ints: *const u64, _floats: *const u64) -> u64 {
    0
}

static HANDLER: AtomicPtr<()> = AtomicPtr::new(default_handler as *mut ());

/// Register the Rust dispatch function called by every callback thunk.
pub fn set_thunk_handler(handler: ThunkHandler) {
    HANDLER.store(handler as *mut (), Ordering::Release);
}

extern "C" fn rvm_thunk_dispatch(index: u32, ints: *const u64, floats: *const u64) -> u64 {
    let ptr = HANDLER.load(Ordering::Acquire);
    // SAFETY: `HANDLER` is initialized to `default_handler` and only updated with valid `ThunkHandler` pointers.
    let handler: ThunkHandler = unsafe { std::mem::transmute(ptr) };
    handler(index, ints, floats)
}

/// Host code address of thunk slot `index` (`0..THUNK_COUNT`).
pub fn thunk_addr(index: u8) -> u64 {
    THUNKS[usize::from(index) & (THUNK_COUNT - 1)] as usize as u64
}

/// Slot index of `addr` if it equals one of the static thunks, or `None`.
pub fn thunk_index(addr: u64) -> Option<u8> {
    THUNKS.iter().position(|&f| f as usize as u64 == addr).map(|i| i as u8)
}

macro_rules! define_thunks {
    ($(($idx:literal, $sym:ident)),* $(,)?) => {
        unsafe extern "C" {
            $(fn $sym();)*
        }

        static THUNKS: [unsafe extern "C" fn(); THUNK_COUNT] = [$($sym),*];

        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        global_asm!(
            ".section .text,\"xr\"",
            $(
                concat!(
                    ".balign 16\n",
                    ".globl ", stringify!($sym), "\n",
                    ".def ", stringify!($sym), "; .scl 2; .type 32; .endef\n",
                    stringify!($sym), ":\n",
                    "    mov eax, ", stringify!($idx), "\n",
                    "    jmp rvm_thunk_common\n",
                ),
            )*
            ".balign 16",
            ".globl rvm_thunk_common",
            ".def rvm_thunk_common; .scl 2; .type 32; .endef",
            ".seh_proc rvm_thunk_common",
            "rvm_thunk_common:",
            // spill rcx..r9 into the caller's 32-byte home area so ints[0..] is contiguous with stack args
            "    mov [rsp + 8], rcx",
            "    mov [rsp + 16], rdx",
            "    mov [rsp + 24], r8",
            "    mov [rsp + 32], r9",
            // 32-byte home area for callee + 32 bytes for xmm0..xmm3 + 8 bytes alignment (entry rsp % 16 == 8)
            "    sub rsp, 72",
            "    .seh_stackalloc 72",
            "    .seh_endprologue",
            "    movq [rsp + 32], xmm0",
            "    movq [rsp + 40], xmm1",
            "    movq [rsp + 48], xmm2",
            "    movq [rsp + 56], xmm3",
            "    mov ecx, eax",
            "    lea rdx, [rsp + 80]",
            "    lea r8, [rsp + 32]",
            "    call {dispatch}",
            // place return bits in both rax and xmm0 so integer, pointer, float and double returns work
            "    movq xmm0, rax",
            "    add rsp, 72",
            "    ret",
            "    .seh_endproc",
            dispatch = sym rvm_thunk_dispatch,
        );

        #[cfg(all(target_arch = "x86_64", unix))]
        macro_rules! sysv_thunks_asm {
            ($prefix:literal, $elf:tt) => {
                global_asm!(
                    $(
                        concat!(
                            ".balign 16\n",
                            ".globl ", $prefix, stringify!($sym), "\n",
                            sysv_thunks_asm!(@type $elf, stringify!($sym)),
                            $prefix, stringify!($sym), ":\n",
                            "    mov eax, ", stringify!($idx), "\n",
                            "    jmp ", $prefix, "rvm_thunk_common\n",
                            sysv_thunks_asm!(@size $elf, stringify!($sym)),
                        ),
                    )*
                    ".balign 16",
                    concat!(".globl ", $prefix, "rvm_thunk_common"),
                    sysv_thunks_asm!(@type $elf, "rvm_thunk_common"),
                    concat!($prefix, "rvm_thunk_common:"),
                    "    .cfi_startproc",
                    // 48 bytes for rdi..r9 + 40 bytes for xmm0..xmm4 = 88 bytes (entry rsp % 16 == 8 -> aligned)
                    "    sub rsp, 88",
                    "    .cfi_def_cfa_offset 96",
                    "    mov [rsp], rdi",
                    "    mov [rsp + 8], rsi",
                    "    mov [rsp + 16], rdx",
                    "    mov [rsp + 24], rcx",
                    "    mov [rsp + 32], r8",
                    "    mov [rsp + 40], r9",
                    "    movq [rsp + 48], xmm0",
                    "    movq [rsp + 56], xmm1",
                    "    movq [rsp + 64], xmm2",
                    "    movq [rsp + 72], xmm3",
                    "    movq [rsp + 80], xmm4",
                    "    mov edi, eax",
                    "    lea rsi, [rsp]",
                    "    lea rdx, [rsp + 48]",
                    "    call {dispatch}",
                    "    movq xmm0, rax",
                    "    add rsp, 88",
                    "    .cfi_def_cfa_offset 8",
                    "    ret",
                    "    .cfi_endproc",
                    sysv_thunks_asm!(@size $elf, "rvm_thunk_common"),
                    dispatch = sym rvm_thunk_dispatch,
                );
            };
            (@type true, $name:expr) => { concat!(".type ", $name, ", @function\n") };
            (@type false, $name:expr) => { "" };
            (@size true, $name:expr) => { concat!(".size ", $name, ", .-", $name, "\n") };
            (@size false, $name:expr) => { "" };
        }

        #[cfg(all(target_arch = "x86_64", unix, not(target_vendor = "apple")))]
        sysv_thunks_asm!("", true);

        #[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
        sysv_thunks_asm!("_", false);
    };
}

define_thunks!(
    (0, rvm_thunk_0),
    (1, rvm_thunk_1),
    (2, rvm_thunk_2),
    (3, rvm_thunk_3),
    (4, rvm_thunk_4),
    (5, rvm_thunk_5),
    (6, rvm_thunk_6),
    (7, rvm_thunk_7),
    (8, rvm_thunk_8),
    (9, rvm_thunk_9),
    (10, rvm_thunk_10),
    (11, rvm_thunk_11),
    (12, rvm_thunk_12),
    (13, rvm_thunk_13),
    (14, rvm_thunk_14),
    (15, rvm_thunk_15),
    (16, rvm_thunk_16),
    (17, rvm_thunk_17),
    (18, rvm_thunk_18),
    (19, rvm_thunk_19),
    (20, rvm_thunk_20),
    (21, rvm_thunk_21),
    (22, rvm_thunk_22),
    (23, rvm_thunk_23),
    (24, rvm_thunk_24),
    (25, rvm_thunk_25),
    (26, rvm_thunk_26),
    (27, rvm_thunk_27),
    (28, rvm_thunk_28),
    (29, rvm_thunk_29),
    (30, rvm_thunk_30),
    (31, rvm_thunk_31),
    (32, rvm_thunk_32),
    (33, rvm_thunk_33),
    (34, rvm_thunk_34),
    (35, rvm_thunk_35),
    (36, rvm_thunk_36),
    (37, rvm_thunk_37),
    (38, rvm_thunk_38),
    (39, rvm_thunk_39),
    (40, rvm_thunk_40),
    (41, rvm_thunk_41),
    (42, rvm_thunk_42),
    (43, rvm_thunk_43),
    (44, rvm_thunk_44),
    (45, rvm_thunk_45),
    (46, rvm_thunk_46),
    (47, rvm_thunk_47),
    (48, rvm_thunk_48),
    (49, rvm_thunk_49),
    (50, rvm_thunk_50),
    (51, rvm_thunk_51),
    (52, rvm_thunk_52),
    (53, rvm_thunk_53),
    (54, rvm_thunk_54),
    (55, rvm_thunk_55),
    (56, rvm_thunk_56),
    (57, rvm_thunk_57),
    (58, rvm_thunk_58),
    (59, rvm_thunk_59),
    (60, rvm_thunk_60),
    (61, rvm_thunk_61),
    (62, rvm_thunk_62),
    (63, rvm_thunk_63),
);
