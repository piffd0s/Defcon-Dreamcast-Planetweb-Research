! crt0.s -- bare-metal SH-4 entry for the staged DOOM binary.
! Sets stack, zeroes BSS, calls main. Linked at a fixed no-ASLR base.
    .section .text.start
    .global _start
    .align 2
_start:
    mov.l   stack_top, r15        ! set our own stack (free RAM)
    ! zero BSS
    mov.l   bss_start, r0
    mov.l   bss_end,   r1
    mov     #0, r2
1:  cmp/hs  r1, r0
    bt      2f
    mov.l   r2, @r0
    bra     1b
    add     #4, r0
2:  mov.l   main_addr, r0
    jsr     @r0                   ! main(0,0)
    mov     #0, r4
3:  bra     3b                    ! main returns -> hang
    nop
    .align 2
stack_top:  .long 0x8CFFFFF0      ! stack top (grows down, above heap)
bss_start:  .long __bss_start
bss_end:    .long _end
main_addr:  .long _main
