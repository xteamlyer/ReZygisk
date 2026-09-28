/* INFO: Some libc functions (memcpy and friends) have SIMD/NEON paths whose
           registers are caller-saved, and libc does not restore them. The string
           data left behind can be used to detect VexZygisk, so clear_regs()
           scrubs those registers. */

#ifndef REGISTERS_H
#define REGISTERS_H

#include <stddef.h>

/* INFO: In ARM64, we clear the following registers:
           NEON: q0, q1, ..., q7
           GPR : x6, x7, x11, x12, x13, x14, x15, x16, x17
*/
__attribute__((always_inline))
static inline void registers_clear(void) {
  __asm__ volatile(
    "mov x6, xzr\n"
    "mov x7, xzr\n"
    "mov x11, xzr\n"
    "mov x12, xzr\n"
    "mov x13, xzr\n"
    "mov x14, xzr\n"
    "mov x15, xzr\n"
    "mov x16, xzr\n"
    "mov x17, xzr\n"
    "movi v0.16b, #0\n"
    "movi v1.16b, #0\n"
    "movi v2.16b, #0\n"
    "movi v3.16b, #0\n"
    "movi v4.16b, #0\n"
    "movi v5.16b, #0\n"
    "movi v6.16b, #0\n"
    "movi v7.16b, #0\n"
    : : : "x6","x7","x11","x12","x13","x14","x15","x16","x17",
          "v0","v1","v2","v3","v4","v5","v6","v7"
  );
}

#endif /* REGISTERS_H */
