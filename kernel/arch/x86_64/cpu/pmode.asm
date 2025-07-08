[BITS 16]
section .text
global start

start:
    cli
    call load_gdt
    jmp 0x08:protected_mode_entry

section .rodata
align 8                 ; Align to 8 byte segment descriptors
gdt_start:
    ; 1. Null descriptor (8 bytes) - always first
    dq 0x0000000000000000

    ; 2. Code segment descriptor (8 bytes)
    ; Base = 0x0, Limit = 0xFFFFF (4 GB), Code segment, Executable, Readable, Accessed
    ; Granularity = 4KB, 32-bit segment
    dw 0xFFFF           ; Segment limit (low 16 bits)
    dw 0x0000           ; Base (low 16 bits)
    db 0x00             ; Base (middle 8 bits)
    db 10011010b        ; Access byte: Present = 1, Ring = 00, Code = 1, Executable = 1, Readable = 1
    db 11001111b        ; Granularity: 4KB, 32-bit, limit high 4 bits = 0xF
    db 0x00             ; Base (high 8 bits)
    
    ; 3. Data segment descriptor (8 bytes)
    ; Base=0x0, Limit=0xFFFFF (4 GB), Data segment, Read/Write
    dw 0xFFFF           ; Segment limit (low 16 bits)
    dw 0x0000           ; Base (low 16 bits)
    db 0x00             ; Base (middle 8 bits)
    db 10010010b        ; Access byte: Present=1, Ring=00, Data=1, Writable=1
    db 11001111b        ; Granularity: 4KB gran, 32-bit, limit high 4 bits = 0xF
    db 0x00             ; Base (high 8 bits)

gdt_end:
    ; GDTR Structure
    ; 6 bytes: 2 bytes limit, 4 bytes base address

align 8
gdt_descriptor:
    dw gdt_end - gdt_start - 1      ; Limit = size of GDT - 1
    dd gdt_start                    ; Base address to GDT-table


section .text
; Load GDT and switch to protected mode
load_gdt:
    lgdt [gdt_descriptor]           ; Load GDTR with the address to GDT

    mov eax, cr0        ; Read CR0 to EAX
    or eax, 1           ; Set PE-bit (bit 0) in EAX
    mov cr0, eax        ; Write EAX back to CR0

    ; We should be in protected mode, but still in 16-bit, lets fix that
    ; Do a "far jump" to flush the pipeline and switch CS-segment
    ; Assume that code segment selector is 0x08 (The first real segment descriptor)
    ret

[BITS 32]
protected_mode_entry:
    ; We should be in 32-bit protected mode now
    ; Initialize data segment registers (DS, ES, SS, etc)
    mov ax, 0x10        ; Data segment selector (second segment in GDT, index 2x8=0x10)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov dword [0xB8000], 0x2F4B4B4B  ; "KKK" i grön text

.hang:
    hlt
    jmp .hang

    call enable_long_mode   ; Setup paging and long mode

    ;jmp 0x08:_start         ; Far jump to 64-bit code

; Enable Long Mode
enable_long_mode:
    mov eax, cr4            ; CR4: Set PAE
    or eax, 1 << 5
    mov cr4, eax

    mov ecx, 0xC0000080     ; EFER -> Set LME (Bit 8)
    rdmsr
    or eax, 1 << 8
    wrmsr

    mov eax, 0x9000         ; Hard coded page tables for now
    mov cr3, eax

    mov eax, cr0            ; CR0: Enable paging (Bit 31)
    or eax, 1 << 31
    mov cr0, eax

    ret
