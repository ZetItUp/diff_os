[BITS 16]
ORG 0x8000

global pm_start
pm_start:
    lgdt [gdt_descriptor]

    mov eax, cr0
    or eax, 1
    mov cr0, eax            ;; Set PE-bit (Protected Mode)

    jmp CODE_SEG:protected_mode_entry

; Vi är nu i 32-bit protected mode
[BITS 32]
global protected_mode_entry
protected_mode_entry:
    mov ax, DATA_SEG
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov esi, 0x10000            ; src (där kernel laddades i real mode)
    mov edi, 0x100000           ; dest (dit vi vill flytta kernel)
    
    movzx eax, word [0x8000]    ; EAX = number of sectors
    shl eax, 9                  ; Sectors * 512 = bytes
    add eax, 3                  ; Round
    shr eax, 2                  ; Divide by 4 = words
    mov ecx, eax                ; ECX = dwords to copy                
    rep movsd                   ; kopiera kernel

    ; Nolla .bss – exempel: 0x100000 + 1545 till 0x100000 + 0x1000
    mov edi, 0x100000   ; börja efter din kernel (avrunda uppåt)
    movzx eax, word [0x8000]
    shl eax, 9
    add edi, eax
    add edi, 3
    and edi, 0xFFFFFFFC        ; align 4
    mov ecx, 0x1000 / 4        ; 4 KB reset
    xor eax, eax

    rep stosd
    
    mov ebp, 0x20000
    mov esp, ebp

    jmp CODE_SEG:0x100000    ; Jump to kernel main


.hang:
    hlt
    jmp .hang

align 8
global gdt_start
gdt_start:
    dq 0x0                                ; Null descriptor (mandatory)

global gdt_code
gdt_code:
    ; Kernel Code Segment (base=0, limit=0xFFFFF, type=0x9A, flags=0xCF)
    dw 0xFFFF                             ; Limit (low)
    dw 0x0000                             ; Base (low)
    db 0x00                               ; Base (middle)
    db 0x9A                               ; Access byte: present, ring 0, executable, readable
    db 0xCF                               ; Flags: granularity=4K, 32-bit
    db 0x00                               ; Base (high)

global gdt_data
gdt_data:
    ; Kernel Data Segment (same as above, but type=0x92)
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 0x92                               ; Access byte: present, ring 0, data, writable
    db 0xCF
    db 0x00

global gdt_end
gdt_end:

global gdt_descriptor
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start  ; Offset to absolute address in RAM

global CODE_SEG
CODE_SEG equ gdt_code - gdt_start
global DATA_SEG
DATA_SEG equ gdt_data - gdt_start

