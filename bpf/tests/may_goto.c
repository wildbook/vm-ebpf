/*
 * A loop bounded with may_goto, as libbpf's can_loop in bpf_experimental.h writes it.
 */
#include "rvm_bpf.h"

#define can_loop                                                    \
    ({                                                              \
        __label__ l_break, l_continue;                              \
        int ret = 1;                                                \
        asm volatile goto("may_goto %l[l_break]" :::: l_break);     \
        goto l_continue;                                            \
    l_break:                                                        \
        ret = 0;                                                    \
    l_continue:;                                                    \
        ret;                                                        \
    })

u64 sum(u64 n) {
    u64 s = 0;
    for (u64 i = 0; i < n && can_loop; i++)
        s += i;
    return s;
}
