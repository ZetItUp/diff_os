[BITS 16]
[ORG 0x8000]

mov ax, [0x8000]                        ; Get the boot drive we got from bios in Stage 1
mov [boot_drive], ax

entry_stage2:
    xor ebx, ebx                      ; continuation = 0
    mov edx, 0x534D4150               ; 'SMAP'
    mov edi, e820_buffer
    mov ax, 0                         ; clear ES
    mov es, ax
    mov si, 0                         ; SI = entry counter

.get_e820:
    mov eax, 0xE820
    mov ecx, 24                       ; size of buffer
    int 0x15
    jc .done_e820                     ; CF=1 -> done
    cmp eax, 0x534D4150
    jne .done_e820

    inc si
    add di, 24
    cmp si, 32
    jae .done_e820
    test ebx, ebx
    jnz .get_e820

.done_e820:
    mov [mem_entry_count], si

    mov cx, 3                           ; Attempt to read the kernel 3 times
.load_kernel:   
    mov byte [bp], 0x10                ; Size of DAP
    mov byte [bp+1], 0x00

%include "build/kernel_sizes.inc"       ; Include kernel_sizes.inc to get calculated sizes from buildtime
    mov word [bp+2], KERNEL_SECTORS    ; Kernel sectors
    mov word [bp+4], 0x0000            ; Offset
    mov word [bp+6], 0x1000            ; Segment 
    mov dword [bp+8], 2048             ; LBA (Kernel is at 2048)
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

    mov edi, 0x8F000                    ; Beginning of stack (just below 0x7FFFF)
    mov ecx, 0x400                      ; 4KB = 1024 dword (4 * 1024 = 4096 bytes)
    xor eax, eax
    rep stosd

    mov esp, 0x7C00                     ; Set the stack in Protected Mode to 0x7FFFF
    mov ebp, esp
    push esp

    mov esi, 0x10000
    mov edi, 0x100000       
    mov ecx, KERNEL_MOVSDS  
    rep movsd                           ; Move the kernel from 0x10000 to 0x100000 (1MB) 

    ; Send E820 info to the kernel by pushing pointer + count
    push dword [mem_entry_count]
    push dword e820_buffer

    jmp CODE_SEG:0x100000               ; Jump to 1MB in RAM, Kernel should be here now.

[BITS 16]
; Prints message to the screen in Real Mode
print_string:
    pusha
    mov ah, 0x0E                        ; BIOS Teletype output function
.loop:
    lodsb                               ; Load byte as DS:SI into AL, increment SI
    test al, al                         ; Is it null terminator? (End of string)
    jz .done                            ; If it is, jump out, we are done
    int 0x10                            ; BIOS interrupt to print AL at cursor
    jmp .loop                           ; Attempt to print next character
.done:
    popa
    ret

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

; Error function, something went bad, print a message and halt the CPU
error:
    call print_string                   ; Prints what's currently in SI
    mov si, msg_halt                    
    call print_string                   ; Prints the msg_halt string
    cli
    hlt

; GDT Table
global gdt_start
gdt_start:
    dd 0x0                              
    dd 0x0                              ; First needs to be 0, Null descriptor

gdt_code:
    dw 0xFFFF                           ; Segment Limit (4GB limit, with granularity)
    dw 0x0                              ; Base Address 0-15     = 0
    db 0x0                              ; Base Address 16-23    = 0

    db 10011010b                        ; Access Byte: 
                                        ; Present, Ring 0, Code, Readable, Accessed
                                        ; 1, 00 , 1, 1, 0 , 1 , 0
                                        ; P, DPL, S, E, DC, RW, A

    db 11001111b                        ; Flags + Limit 16-19:
                                        ; 4KB Granularity, 32-bit, high limit nibble
                                        ; G, D/B, L, AVL + limit (16-19)

    db 0x0                              ; Base Address 24-31    = 0

gdt_data:
    dw 0xFFFF                           ; Segment Limit (4GB limit, with granularity)
    dw 0x0                              ; Base Address 0-15     = 0
    db 0x0                              ; Base Address 16-23    = 0

    db 10010010b                        ; Access Byte:
                                        ; Present, Ring 0, Data, Writeable
                                        ; 1, 00 , 1, 0, 0 , 1 , 0
                                        ; P, DPL, S, E, DC, RW, A
    
    db 11001111b                        ; Flags + Limit 16-19, same as gdt_code
    db 0x0                              ; Base Address 24-31    = 0

global gdt_end
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start                        ; Calculated the correct GDT values

CODE_SEG equ gdt_code - gdt_start       ; Calculate Code Segment
DATA_SEG equ gdt_data - gdt_start       ; Calculate Data Segment

hex_chars db '0123456789ABCDEF'         ; Hex characters
boot_drive db 0

e820_buffer:
    times 32 * 24 db 0                  ; Buffer for 32 entries (24 bytes each)
    mem_entry_count dd 0                ; Number of entries found

; Messages
msg_load_fail   db 'ERROR: Kernel missing',0
msg_halt        db 'System Halted',0

