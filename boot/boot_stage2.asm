[BITS 16]
[ORG 0x8000]

mov ax, [0x8000]                        ; Get the boot drive we got from bios in Stage 1
mov [boot_drive], ax

DAP_ADDR        equ 0x3000
MAX_SECTORS     equ 127
SECTOR_SIZE     equ 512

SUPERBLOCK_LBA  equ 2048
SUPERBLOCK_SEG  equ 0x1000
FILETABLE_SEG   equ 0x2000

file_lba_low:       dw 0                ; LBA low word
file_lba_high:      dw 0                ; LBA high word
file_remain:        dw 0                ; Remaining Sectors
buffer_segment:     dw 0

dap:
    db 0x10          ; Size
    db 0             ; Reserved
    dw 0             ; Sector count
    dw 0             ; Buffer offset
    dw 0             ; Buffer segment
    dd 0             ; LBA low
    dd 0             ; LBA high

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

    ; Mount Diff FS and find /system/kernel.bin

start_loader:
    ; Spara boot drive (DL från stage1)
    mov [boot_drive], dl

    ; === Steg 1: Läs superblock (1 sektor) ===
    mov word [file_lba_low], SUPERBLOCK_LBA
    mov word [file_lba_high], 0
    mov word [buffer_segment], SUPERBLOCK_SEG
    mov dx, 1
    call read_chunk

    ; DEBUG: printa första ordet i superblock
    mov ax, SUPERBLOCK_SEG
    mov es, ax
    mov ax, [es:0]
    call print_hex16
    
    ; === Steg 2: Hämta filtabellens info från superblock ===
    mov ax, SUPERBLOCK_SEG
    mov es, ax
    mov ax, [es:0]       ; filetable LBA low
    mov [file_lba_low], ax
    mov ax, [es:2]       ; filetable LBA high
    mov [file_lba_high], ax
    mov ax, [es:4]       ; antal sektorer
    mov [file_remain], ax

    ; === Steg 3: Läs filtabellen i chunkar ===
    mov word [buffer_segment], FILETABLE_SEG
    call read_large_file

    ; DEBUG: printa första ordet i filtabellen
    mov ax, FILETABLE_SEG
    mov es, ax
    mov ax, [es:0]
    call print_hex16

    ; DONE → hoppa till nästa steg (t.ex. laddning av kernel)
    jmp $


; -------------------------------------------------
; BIOS LBA READ via INT 13h (DL=boot drive)
; (sector count in DX, segment in [buffer_segment], LBA in [file_lba_low])
; -------------------------------------------------
read_chunk:
    ; Fyll DAP
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



    ; Läs
    mov si, dap
    mov dl, [boot_drive]
    mov ah, 0x42

    push ax

    call debug_dap

    pop ax

    int 0x13
    jc fail_load
    ret

; -------------------------------------------------
; read_large_file - laddar [file_remain] sektorer från [file_lba_low] till minne
; -------------------------------------------------
read_large_file:
.next_chunk:
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

    call read_chunk

    ; Uppdatera buffer segment
    mov ax, dx
    shl ax, 5
    add [buffer_segment], ax

    ; Uppdatera LBA
    mov ax, [file_lba_low]
    add ax, dx
    mov [file_lba_low], ax
    jc .carry
    jmp .skip
.carry:
    inc word [file_lba_high]
.skip:

    ; Uppdatera remain
    mov ax, [file_remain]
    sub ax, dx
    mov [file_remain], ax

    jmp .next_chunk
.done:
    ret


debug_dap:
    mov si, dap
    mov cx, 16       ; Visa hela 16-byte DAP
    mov ah, 0x0E     ; BIOS teletype
.dap_loop:
    lodsb            ; Läs byte från [si] till al, öka si
    push ax
    shr al, 4
    call .nibble
    pop ax
    and al, 0x0F
    call .nibble
    mov al, ' '
    int 0x10
    loop .dap_loop
    ;jmp $            ; Frysa här för att läsa utskriften


.nibble:
    add al, '0'
    cmp al, '9'
    jbe .print
    add al, 7
.print:
    int 0x10
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

    mov esp, 0x7C00                     ; Set the stack in Protected Mode to 0x7FFFF
    mov ebp, esp
    push esp

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

global gdt_end
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start                        ; Calculated the correct GDT values

CODE_SEG equ gdt_code - gdt_start       ; Calculate Code Segment
DATA_SEG equ gdt_data - gdt_start       ; Calculate Data Segment

hex_chars db '0123456789ABCDEF'         ; Hex characters
boot_drive db 0

kernel_name db 'kernel.bin',0
system_name db 'system', 0

system_id dw 0
filetable_lba dd 0
filetable_size dd 0
kernel_start_lba dd 0
kernel_sectors dd 0

msg_sys db 'SYS=',0
msg_ker db 'KER=',0
msg_sec db 'SEC=',0

e820_buffer:
    times 32 * 24 db 0                  ; Buffer for 32 entries (24 bytes each)
    mem_entry_count dd 0                ; Number of entries found

; Messages
msg_remain db 'Remaining: ',0
msg_ftlba       db 'Filetable:',0
msg_ftsize      db 'Filetable Size: ', 0
msg_chunk       db 'CHUNK...',0
msg_load_fail   db 'ERROR: Kernel missing',0
msg_halt        db 'System Halted',0
msg_kern        db 'Kernel',0
msg_dap db 'DAP:',0
msg_ok          db 'OK',0
