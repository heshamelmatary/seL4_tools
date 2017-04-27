.extern main
.global _start
.extern __global_pointer$

_start:
  la sp, _bootstack_top_core1
  la gp, __global_pointer$
  la s0, main
  jr s0  

.align 8
.space 4096
_bootstack_top_core1:
