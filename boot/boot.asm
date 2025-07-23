[BITS 16]
[ORG 0x7C00]

entry:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov sp, 0x8000
    mov bp, sp
    
    ; Save boot drive and disable SMM
    mov [boot_drive], dl
    ;call disable_smm
    ; Enable A20
    call enable_a20
    mov ax, 0
    mov ds, ax
    mov es, ax
    jnc .a20ok
    mov si, msg_a20_fail
    jmp error
.a20ok:

    mov cx, 3
.load_kernel:
    mov byte [bp], 0x10           ; Size of DAP
    mov byte [bp+1], 0x00

%include "build/kernel_sizes.inc"
    mov word [bp+2], KERNEL_SECTORS            ; kernel sectors
    mov word [bp+4], 0x0000       ; Offset
    mov word [bp+6], 0x1000        ; Segment (0x7E0:0 = 0x7E00)
    mov dword [bp+8], 2048        ; LBA
    mov dword [bp+12], 0x00
    mov si, bp
    mov dl, [boot_drive] 
    mov ah, 0x42
    int 0x13
    jnc .kernel_ok
    loop .load_kernel
    mov si, msg_load_fail
    jmp error

.kernel_ok:
    mov ax, 0
    mov ds, ax

    lgdt [gdt_descriptor]

    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp CODE_SEG:init_pm


enable_a20:
    ; Fast method
    in al, 0x92
    test al, 2
    jnz .done
    or al, 2
    out 0x92, al
.done:
    ; Verify
    xor ax, ax
    mov es, ax
    mov di, 0x0500
    mov ax, 0xFFFF
    mov ds, ax
    mov si, 0x0510
    mov al, [es:di]
    push ax
    mov al, [ds:si]
    push ax
    mov byte [es:di], 0x00
    mov byte [ds:si], 0xFF
    cmp byte [es:di], 0xFF
    pop ax
    mov [ds:si], al
    pop ax
    mov [es:di], al
    je .fail
    clc
    ret
.fail:
    stc
    ret

print_string:
    pusha
    mov ah, 0x0E
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .loop
.done:
    popa
    ret

error:
    call print_string
    mov si, msg_halt
    call print_string
    cli
    hlt

[BITS 32]
init_pm:
%include "build/kernel_sizes.inc"
    mov ax, DATA_SEG
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x400000
    mov ebp, esp
    
    mov esi, 0x10000
    mov edi, 0x100000
    mov ecx, KERNEL_MOVSDS 
    rep movsd

    jmp 0x100000

[BITS 16]
print_hex16:
    ; Input: AX = value to print
    pusha
    mov cx, 4           ; 4 hex digits (16 bits)
    mov dx, ax          ; Backup AX since we modify it
.next_digit:
    rol dx, 4           ; Rotate left 4 bits (bring next nibble to low 4 bits)
    mov bx, dx
    and bx, 0x000F      ; Isolate lowest 4 bits
    mov al, [hex_chars + bx] ; Get ASCII character
    mov ah, 0x0E        ; BIOS teletype function
    int 0x10            ; Print character
    loop .next_digit
    popa
    ret

; GDT
gdt_start:
    dd 0x0
    dd 0x0

gdt_code:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 10011010b
    db 11001111b
    db 0x0

gdt_data:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 10010010b
    db 11001111b
    db 0x0

gdt_end:


gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start

hex_chars db '0123456789ABCDEF'
; Data
msg_a20_fail    db 'A20 fail',0
msg_load_fail   db 'Load fail',0
msg_kernel_invalid db 'Bad kernel',0
msg_halt        db 'Halted',0

boot_drive      db 0

times 510-($-$$) db 0
dw 0xAA55
