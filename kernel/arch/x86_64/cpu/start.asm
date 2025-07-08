[BITS 64]
global _start

_start:
    mov rsp, stack_top      ; Initialize Stackpointer
    xor rbp, rbp            ; Clear rbp

    extern kmain
    call kmain              ; Jump to kernel main

    cli                     ; Disable interrupts

.hang:
    hlt
    jmp .hang

section .bss
    resb 16384              ; 16 KB stack
stack_top:

