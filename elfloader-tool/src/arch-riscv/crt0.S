.extern main
.global _start
.extern __global_pointer$
.extern elfloader_stack_alloc
.extern boot_seconday_core

#define BIT(n) (1 << (n))

_start:

  /* mhartid value is in a0 */
  /* la sp, (elfo loader_stack_alloc + BIT(12)) */
  li      sp, BIT(12)
  mul     sp, sp, a0
  la      x1, elfloader_stack_alloc
  add     sp, sp, x1

  bne x0, a0, boot_seconday_core

  la gp, __global_pointer$
  la s0, main
  jr s0  

.align 8
.space 4096
_bootstack_top_core1:
