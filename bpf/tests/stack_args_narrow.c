/*
 * Narrow integer parameters past the fifth argument, compiled with clang 23.1:
 *
 * - `s32` and `u32` work between a plugin's own functions: the callee reads only the low 32 bits of the stack slot
 *   and extends them itself.
 * - `u8` and `u16` work between a plugin's own functions when the caller masks or zero-extends them.
 * - `s8` and `s16` miscompile between a plugin's own functions (llvm/llvm-project#238315): the callee reads all 64
 *   bits of the stack slot without extending, while a caller passing a negative constant or forwarding a narrow
 *   parameter stores only its low 32 bits extended (upper 32 bits zero).
 * - Host functions and native functions read narrow arguments from the low bits, on the stack as in a register.
 */
#include "rvm_bpf.h"

/* Guest callees with a narrow sixth argument. */

noinline s64 g_s8(u64 a, u64 b, u64 c, u64 d, u64 e, s8 f) { return (s64)f; }
noinline u64 g_u8(u64 a, u64 b, u64 c, u64 d, u64 e, u8 f) { return (u64)f; }
noinline s64 g_s16(u64 a, u64 b, u64 c, u64 d, u64 e, s16 f) { return (s64)f; }
noinline u64 g_u16(u64 a, u64 b, u64 c, u64 d, u64 e, u16 f) { return (u64)f; }
noinline s64 g_s32(u64 a, u64 b, u64 c, u64 d, u64 e, s32 f) { return (s64)f; }
noinline u64 g_u32(u64 a, u64 b, u64 c, u64 d, u64 e, u32 f) { return (u64)f; }

u64 call_g_s32_imm(void) { return (u64)g_s32(1, 2, 3, 4, 5, -50000); }
u64 call_g_s32_reg(s32 x) { return (u64)g_s32(1, 2, 3, 4, 5, x); }
u64 call_g_u32_imm(void) { return g_u32(1, 2, 3, 4, 5, 0x80000001u); }
u64 call_g_u32_reg(u32 x) { return g_u32(1, 2, 3, 4, 5, x); }

u64 call_g_u8_imm(void) { return g_u8(1, 2, 3, 4, 5, 250); }
u64 call_g_u8_reg(u64 x) { return g_u8(1, 2, 3, 4, 5, (u8)x); }
u64 call_g_u16_imm(void) { return g_u16(1, 2, 3, 4, 5, 65000); }
u64 call_g_u16_reg(u64 x) { return g_u16(1, 2, 3, 4, 5, (u16)x); }

/* Reproduces the clang 23.1 miscompile on negative s8 / s16 constants and forwarded narrow register parameters. */
u64 call_g_s8_imm(void) { return (u64)g_s8(1, 2, 3, 4, 5, -5); }
u64 call_g_s16_imm(void) { return (u64)g_s16(1, 2, 3, 4, 5, -500); }
noinline u64 forward_s8(s8 x) { return (u64)g_s8(1, 2, 3, 4, 5, x); }
u64 call_forward_s8(void) { return forward_s8(-5); }

/* Host and native callees taking narrow types from the sixth argument on. */

extern s64 h_narrow(u64 a, u64 b, u64 c, u64 d, u64 e, s8 f, u8 g, s16 h, u16 i, s32 j, u32 k);
extern s64 n_narrow(u64 a, u64 b, u64 c, u64 d, u64 e, s8 f, u8 g, s16 h, u16 i, s32 j, u32 k);

u64 call_h_narrow_imm(void) { return (u64)h_narrow(1, 2, 3, 4, 5, -5, 250, -500, 65000, -50000, 0x80000001u); }
u64 call_h_narrow_reg(u64 x) {
    return (u64)h_narrow(1, 2, 3, 4, 5, (s8)x, (u8)x, (s16)x, (u16)x, (s32)x, (u32)x);
}

u64 call_n_narrow_imm(void) { return (u64)n_narrow(1, 2, 3, 4, 5, -5, 250, -500, 65000, -50000, 0x80000001u); }
u64 call_n_narrow_reg(u64 x) {
    return (u64)n_narrow(1, 2, 3, 4, 5, (s8)x, (u8)x, (s16)x, (u16)x, (s32)x, (u32)x);
}
