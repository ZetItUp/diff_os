[BITS 16]
[ORG 0x8000]

mov ax, [0x8000]                        ; Get the boot drive we got from bios in Stage 1
mov [boot_drive], ax

MAX_SECTORS     equ 127
SECTOR_SIZE     equ 512

%define TSS_SIZE   104
%define TSS_LIMIT  (TSS_SIZE-1)

SUPERBLOCK_LBA  equ 2048
SUPERBLOCK_SEG  equ 0x1000
FILETABLE_SEG   equ 0x3000

file_lba_low:       dw 0                ; LBA low word
file_lba_high:      dw 0                ; LBA high word
file_remain:        dw 0                ; Remaining Sectors
buffer_segment:     dw 0

dap:
    db 0x10                             ; Size
    db 0                                ; Reserved
    dw 0                                ; Sector count
    dw 0                                ; Buffer offset
    dw 0                                ; Buffer segment
    dd 0                                ; LBA low
    dd 0                                ; LBA high

entry_stage2:
    xor ebx, ebx                        ; continuation = 0
    mov edx, 0x534D4150                 ; 'SMAP'
    mov edi, e820_buffer
    mov ax, 0                           ; clear ES
    mov es, ax
    mov ds, ax
    mov si, 0                           ; SI = entry counter

.get_e820:
    mov eax, 0xE820
    mov ecx, 24                         ; size of buffer
    int 0x15
    jc .done_e820                       ; CF=1 -> done
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

start_loader:
    ; Read superblock, 1 sector
    mov word [file_lba_low], SUPERBLOCK_LBA
    mov word [file_lba_high], 0
    mov word [buffer_segment], SUPERBLOCK_SEG
    mov dx, 1
    call read_chunk

    ; Get filetable from the superblock
    mov ax, SUPERBLOCK_SEG
    mov es, ax

    mov ax, [es:0x0C]                   ; Filetable LBA low
    mov [file_lba_low], ax
    mov ax, [es:0x0E]                   ; Filetable LBA high
    mov [file_lba_high], ax
    mov ax, [es:0x10]                   ; Total sectors
    mov [file_remain], ax

    ; Read the file table in chunks
    mov word [buffer_segment], FILETABLE_SEG
    call read_large_file
    
    ; Get the kernel from the file table
    mov ax, FILETABLE_SEG
    mov es, ax

    ; Kernel entry = Entry 2 (offset 2 * sizeof(FileEntry))
    ; sizeof(FileEntry) = 128 bytes (0x80)
    mov bx, 0x100                       ; (2 * 0x80) = 0x100

    ; Start sector (4 bytes) at offset 0x40 
    mov ax, [es:bx+0x4C]
    mov [file_lba_low], ax
    mov ax, [es:bx+0x4E]
    mov [file_lba_high], ax

    ; Sector count at offset 0x44
    mov ax, [es:bx+0x50]
    mov [file_remain], ax
    mov [kernel_sectors], ax            ; Store for Protected Mode
    mov ah, 0x0E
    mov al, 'Q'
    int 0x10
    ; Read kernel
    mov word [buffer_segment], 0x1000   ; 0x1000:0000 = 1MB
    call read_large_file
    

    call switch_pm
.halt:
    cli
    hlt
    jmp .halt

; -------------------------------------------------
; BIOS LBA READ via INT 13h (DL=boot drive)
; (sector count in DX, segment in [buffer_segment], LBA in [file_lba_low])
; -------------------------------------------------
read_chunk:
    ; DAP
    mov byte [dap], 0x10
    mov byte [dap+1], 0
    mov [dap+2], dx
    mov word [dap+4], 0
    mov ax, [buffer_segment]
    mov [dap+6], ax
    mov ax, [file_lba_low]
    mov [dap+8], ax
    mov ax, [file_lba_high]
    mov [dap+10], ax
    mov word [dap+12], 0
    mov word [dap+14], 0

    ; Read
    mov si, dap
    mov dl, [boot_drive]
    mov ah, 0x42
    int 0x13
    jc fail_load
    ret

; -------------------------------------------------
; read_large_file - load [file_remain] sectors from [file_lba_low] into RAM
; -------------------------------------------------
read_large_file:
.next_chunk:
    xor dx, dx
    mov ax, [file_remain]
    or ax, ax
    jz .done

    cmp ax, MAX_SECTORS
    jbe .use_ax
    mov dx, MAX_SECTORS
    jmp .have_dx

.use_ax:
    mov dx, ax

.have_dx:
    mov ax, [buffer_segment]
    mov cx, dx
    call read_chunk
    mov dx, cx
    mov ax, dx
    
    ; Update buffer segment
    mov ax, dx
    shl ax, 5
    add [buffer_segment], ax

    ; Update LBA
    mov ax, [file_lba_low]
    add ax, dx
    mov [file_lba_low], ax
    jc .carry
    jmp .skip

.carry:
    inc word [file_lba_high]

.skip:

    ; Update remain
    mov ax, [file_remain]
    sub ax, dx
    mov [file_remain], ax

    jmp .next_chunk

.done:
    ret

print_hex8:
    push ax
    mov ah, 0x0E
    push bx
    mov bh, al
    shr al, 4
    and al, 0x0F
    mov bl, al
    mov al, [hex_chars + bx]
    int 0x10
    mov al, bh
    and al, 0x0F
    mov bl, al
    mov al, [hex_chars + bx]
    int 0x10
    mov al, ' '
    int 0x10
    pop bx
    pop ax
    ret    

switch_pm:
    ; Switch to Protected Mode
    xor ax, ax
    mov ds, ax                          ; Make sure DS is 0 (zero)
    lgdt [gdt_descriptor]

    mov eax, cr0
    or eax, 1                           ; Set PM bit to 1
    mov cr0, eax
    jmp CODE_SEG:init_pm                ; Far jump into init_pm

; 32-bit Protected Mode Initialization
[BITS 32]
init_pm:
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

    mov esp, 0x7FFFF                    ; Set the stack in Protected Mode to 0x7FFFF
    mov ebp, esp
    push esp

    ; Patch GDT TSS Descriptor with the address to TSS
    mov eax, tss
    mov word [gdt_tss + 2], ax
    shr eax, 16
    mov byte [gdt_tss + 4], al
    mov byte [gdt_tss + 7], ah

    ; Init TSS: SS0 = Kernel Data, ESP0 = kernel_stack_top
    mov eax, kernel_stack_top
    mov [tss + 4], eax                  ; ESP0
    mov ax, DATA_SEG
    mov [tss + 8], ax                   ; SS0
    mov word [tss + 102], 104           ; I/O Map Base = TSS size

    mov ax, TSS_SEG
    ltr ax

    mov esi, 0x10000
    mov edi, 0x100000       
    mov ecx, [kernel_sectors]
    shl ecx, 7                          ; Sectors * 512 / 4
    rep movsd                           ; Move the kernel from 0x10000 to 0x100000 (1MB) 

    ; Send E820 info to the kernel by pushing pointer + count
    push dword [mem_entry_count]
    push dword e820_buffer

    jmp CODE_SEG:0x100000               ; Jump to 1MB in RAM, Kernel should be here now.

[BITS 16]
; Error Handling
fail_load:
    call print_hex16
    mov si, msg_load_fail
    jmp error

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


gdt_user_code:
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 11111010b
    db 11001111b
    db 0x00

gdt_user_data:
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 11110010b
    db 11001111b
    db 0x00

; 32-bit TSS Descriptor
gdt_tss:
    dw TSS_LIMIT 
    dw 0
    db 0
    db 10001001b                        ; Type=0x9, S = 0, DPL = 0, P = 1
    db ((TSS_LIMIT >> 16) & 0x0F)
    db 0

global gdt_end
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start                        ; Calculated the correct GDT values

CODE_SEG equ gdt_code - gdt_start       ; Calculate Code Segment
DATA_SEG equ gdt_data - gdt_start       ; Calculate Data Segment
USER_CODE_SEG equ (gdt_user_code - gdt_start) | 3
USER_DATA_SEG equ (gdt_user_data - gdt_start) | 3

TSS_SEG equ gdt_tss - gdt_start

; TSS (32-bit)
align 4
tss:
    times 104 db 0                      ; 32-bit TSS (104 bytes)
tss_end:

section .bss
; Kernel stack (Ring 0)
align 16
kernel_stack:
    resb 16384                          ; 16 KB

kernel_stack_top:


e820_buffer:
    resb 32 * 24                       ; Buffer for 32 entries (24 bytes each)
mem_entry_count:
    resd 1                             ; Number of entries found

section .text

hex_chars db '0123456789ABCDEF'         ; Hex characters
boot_drive db 0

kernel_sectors dd 0

; Messages
msg_load_fail   db 'ERROR: Kernel missing',0
msg_halt        db 'System Halted',0
