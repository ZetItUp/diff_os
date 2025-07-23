[BITS 16]
[ORG 0x7C00]

entry:
    cli                                 ; Stop interrupts on the CPU
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax                          ; Clear all segments

    mov sp, 0x8000
    mov bp, sp                          ; Set stack pointer and base pointer
    
    mov [boot_drive], dl                ; Store the boot drive that BIOS gave us
    
    call enable_a20                     ; Enable the A20 line
    mov ax, 0
    mov ds, ax
    mov es, ax
    jnc .a20ok                          ; If we succeed, continue with loading the kernel
    mov si, msg_a20_fail                ; If we fail, crash and halt CPU
    jmp error
.a20ok:

    mov cx, 3                           ; Attempt to read the kernel 3 times
.load_kernel:   
    mov byte [bp], 0x10                 ; Size of DAP
    mov byte [bp+1], 0x00

%include "build/kernel_sizes.inc"       ; Include kernel_sizes.inc to get calculated sizes from buildtime
    mov word [bp+2], KERNEL_SECTORS     ; Kernel sectors
    mov word [bp+4], 0x0000             ; Offset
    mov word [bp+6], 0x1000             ; Segment 
    mov dword [bp+8], 2048              ; LBA (Kernel is at 2048)
    mov dword [bp+12], 0x00
    mov si, bp
    mov dl, [boot_drive]                ; Get the boot drive, put it in dl
    mov ah, 0x42
    int 0x13                            ; Read from disk
    jnc .kernel_ok                      ; If read succeeded, jump to kernel_ok
    loop .load_kernel                   ; Else loop back to .load_kernel
    mov si, msg_load_fail               ; Couldn't load the kernel, show error and halt CPU
    jmp error   

.kernel_ok:
    xor ax, ax                          
    mov ds, ax                          ; Make sure Data Segment is zero

    lgdt [gdt_descriptor]               ; Load GDT Descriptor

    mov eax, cr0
    or eax, 1                           ; Set PM bit to 1
    mov cr0, eax

    jmp CODE_SEG:init_pm                ; Do far jump into init_pm

; Function to enable to A20 line
enable_a20:
    in al, 0x92
    test al, 2
    jnz .done
    or al, 2
    out 0x92, al
.done:
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

; Prints message to the screen in Real Mode
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

; Error function, something went bad, print a message and halt the CPU
error:
    call print_string
    mov si, msg_halt
    call print_string
    cli
    hlt

; 32-bit Protected Mode Initialization
[BITS 32]
init_pm:
%include "build/kernel_sizes.inc"       ; This needs to be included here so 32-bit
                                        ; protected mode knows about KERNEL_MOVSDS
    mov ax, DATA_SEG
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x400000
    mov ebp, esp                        ; Set the stack in Protected Mode
    
    mov esi, 0x10000
    mov edi, 0x100000       
    mov ecx, KERNEL_MOVSDS  
    rep movsd                           ; Move the kernel from 0x10000 to 0x100000 (1MB) 

    jmp 0x100000

; Helper function to print 16-bit Hex values
[BITS 16]
print_hex16:
    ; Input: AX = value to print
    pusha
    mov cx, 4                           ; 4 hex digits (16 bits)
    mov dx, ax                          ; Backup AX since we modify it
.next_digit:
    rol dx, 4                           ; Rotate left 4 bits (bring next nibble to low 4 bits)
    mov bx, dx
    and bx, 0x000F                      ; Isolate lowest 4 bits
    mov al, [hex_chars + bx]            ; Get ASCII character
    mov ah, 0x0E                        ; BIOS teletype function
    int 0x10                            ; Print character
    loop .next_digit
    popa
    ret

; GDT Table
gdt_start:
    dd 0x0
    dd 0x0                              ; First needs to be 0

gdt_code:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 10011010b
    db 11001111b
    db 0x0                              ; Second is for Code Segment

gdt_data:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 10010010b
    db 11001111b   
    db 0x0                              ; Third for Data Segment

gdt_end:


gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start                        ; Calculated the correct GDT values

CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start

hex_chars db '0123456789ABCDEF'         ; Hex characters

; Data
msg_a20_fail    db 'A20 fail',0
msg_load_fail   db 'Load fail',0
msg_halt        db 'Halted',0

boot_drive      db 0

; Fill in the rest of the file with zeros and add the mandatory boot magic number at the end
times 510-($-$$) db 0
dw 0xAA55
