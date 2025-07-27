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

; Get memorymap through BIOS using E820
    mov di, e820_buffer                 ; ES:DI point to buffer
    xor bx, bx                          ; Set EBX to 0
    mov cx, 24                          ; 24 bytes per entry
    xor si, si                          ; SI = entry counter

.get_e820:
    mov ax, 0xE820
    mov dx, 0x534D                      ; 'SM'
    push dx
    mov dx, 0x4159                      ; 'AP'
    int 0x15
    jc .done_e820
    cmp ax, 0x534D
    jne .done_e820

    add di, 24                          ; Next entry in buffer
    inc si                              ; SI = still entry counter
    cmp si, 32
    jae .done_e820
    test bx, bx
    jnz .get_e820

.done_e820:
    mov [mem_entry_count], si

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
    in al, 0x92                         ; Read port 0x92 (Control Port A)
    test al, 2                          ; Check if A20 is already enabled
    jnz .done                           ; If it is, skip
    or al, 2                            ; Set bit 1 (A20 Gate)
    out 0x92, al                        ; Write to port 0x92 to enable A20
.done:
    xor ax, ax
    mov es, ax                          ; ES = 0x0000
    mov di, 0x0500                      ; ES:DI point to 0x0000:0500
    mov ax, 0xFFFF
    mov ds, ax                          ; DS = 0xFFFF
    mov si, 0x0510                      ; DS:SI point to 0xFFFF:0510 (Wraps to 0x10)
    
    ; Store original data at test addresses
    mov al, [es:di]                     ; Load value at 0x0000:0500
    push ax
    mov al, [ds:si]                     ; Load value at 0xFFFF:0510
    push ax

    ; Test A20 by writing different values to wrap addresses
    mov byte [es:di], 0x00              ; Write 0x00 to 0x0000:0500
    mov byte [ds:si], 0xFF              ; Write 0xFF to 0xFFFF:0510
    cmp byte [es:di], 0xFF              ; If A20 is enabled, values won't mirror
    pop ax                              ; Restore old value at DS:SI
    mov [ds:si], al
    pop ax                              ; Restor old value as ES:DI
    mov [es:di], al
    je .fail                            ; If readback is 0xFF, A20 failed to enable
    
    clc                                 ; Clear carry flag to indicate success
    ret
.fail:
    stc                                 ; Set carry flag to indicate fail
    ret

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

; Error function, something went bad, print a message and halt the CPU
error:
    call print_string                   ; Prints what's currently in SI
    mov si, msg_halt                    
    call print_string                   ; Prints the msg_halt string
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

; Messages
msg_a20_fail    db 'ERROR: Setting A20 Gate Failed',0
msg_load_fail   db 'ERROR: Kernel missing',0
msg_halt        db 'System Halted',0

boot_drive      db 0                    ; Holds the boot drive number

e820_buffer:
    times 32 * 24 db 0                  ; Buffer for 32 entries (24 bytes each)
    mem_entry_count dw 0                ; Number of entries found

; Fill in the rest of the file with zeros and add the mandatory boot magic number at the end
times 510-($-$$) db 0
dw 0xAA55
