; Multiboot header and entry point for GRUB
; Based on OSDev Bare Bones tutorial
[BITS 32]

MULTIBOOT_MAGIC     equ 0x1BADB002
MULTIBOOT_ALIGN     equ 1 << 0
MULTIBOOT_MEMINFO   equ 1 << 1
MULTIBOOT_FLAGS     equ MULTIBOOT_ALIGN | MULTIBOOT_MEMINFO
MULTIBOOT_CHECKSUM  equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

section .multiboot.data
align 4
    dd MULTIBOOT_MAGIC
    dd MULTIBOOT_FLAGS
    dd MULTIBOOT_CHECKSUM

section .multiboot.text
global _start
extern kmain

_start:
    ; Now set up stack and call kmain
    mov esp, 0x90000
    push ebx
    push eax
    call kmain
    cli
.hang:
    hlt
    jmp .hang
