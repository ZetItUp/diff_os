;
; DiffOS CD-ROM Stage 2 Bootloader
;
; This is loaded by boot_cd.asm and handles:
; - Reading the DiffFS filesystem from the CD
; - Loading the kernel into memory
; - Switching to protected mode
; - Jumping to the kernel
;
; CD-ROM specifics:
; - Sectors are 2048 bytes
; - DiffFS image is embedded in the ISO at a known offset
; - Uses INT 13h extensions for reading
;

[BITS 16]
[ORG 0x8000]

; Debugging: set to a step number to halt at that checkpoint (0 disables).
%define DEBUG_HALT_AT 0
%define DEBUG_VERBOSE 1

%macro DBG_HALT 2
%if DEBUG_HALT_AT = %1
    xor ax, ax
    mov ds, ax
    mov si, %2
    call print_string
    cli
%%halt:
    hlt
    jmp %%halt
%endif
%endmacro

%macro DBG_PRINT 1
%if DEBUG_VERBOSE = 1
    xor ax, ax
    mov ds, ax
    mov si, %1
    call print_string
%endif
%endmacro

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    mov [boot_drive], dl
    call serial_init
    jmp entry_stage2

; CD-ROM constants
CD_SECTOR_SIZE  equ 2048
SECTOR_SIZE     equ 512             ; DiffFS internal sector size

MAX_SECTORS     equ 16              ; Max CD sectors per read (16 * 2048 = 32KB, avoids 64KB boundary issues)

%define TSS_SIZE   104
%define TSS_LIMIT  (TSS_SIZE-1)

; Bounce buffer for 2048-byte CD reads
BOUNCE_SEG      equ 0x9000

; DiffFS superblock is at LBA 2048 (in 512-byte sectors) inside diffos.img
SUPERBLOCK_LBA512 equ 2048

SUPERBLOCK_SEG  equ 0x1000
FILETABLE_SEG   equ 0x3000
MAX_ROOTDIR_SECTORS equ 31

; ---- DiffFS on-disk layout constants ----
FILE_ENTRY_SIZE         equ 0x140   ; sizeof(FileEntry) = 320 bytes
ENTRY_OFF_ENTRY_ID      equ 0x000
ENTRY_OFF_PARENT_ID     equ 0x004
ENTRY_OFF_TYPE          equ 0x008
ENTRY_OFF_NAME          equ 0x00C
ENTRY_OFF_START_SECTOR  equ 0x10C
ENTRY_OFF_SECTOR_COUNT  equ 0x110

ENTRY_TYPE_FILE         equ 1
ENTRY_TYPE_DIR          equ 2
MAX_FILES_TABLE         equ 256

; Variables
file_lba_low:       dd 0            ; LBA (in CD sectors)
file_remain:        dw 0            ; Remaining CD sectors
buffer_segment:     dw 0
dest_segment:       dw 0            ; Destination segment for 512-byte-sector reads
saved_lba512:       dd 0            ; Scratch: preserve EAX across BIOS calls

; Disk Address Packet
align 4
dap:
    db 0x10                         ; Size
    db 0                            ; Reserved
    dw 0                            ; Sector count
    dw 0                            ; Buffer offset
    dw 0                            ; Buffer segment
    dd 0                            ; LBA low
    dd 0                            ; LBA high

entry_stage2:
    ; Print stage 2 message
    mov si, msg_stage2
    call print_string
    DBG_HALT 1, msg_dbg_1

    ; Get E820 memory map
    xor ebx, ebx
    mov edx, 0x534D4150             ; 'SMAP'
    mov edi, e820_buffer
    xor ax, ax
    mov es, ax
    mov ds, ax
    xor si, si

.get_e820:
    mov eax, 0xE820
    mov ecx, 24
    int 0x15
    jc .done_e820
    cmp eax, 0x534D4150
    jne .done_e820

    inc si
    add di, 24
    cmp si, 32
    jae .done_e820
    test ebx, ebx
    jnz .get_e820

.done_e820:
    mov word [mem_entry_count], si
    mov word [mem_entry_count+2], 0
    DBG_HALT 2, msg_dbg_2

start_loader:
    call find_diffos_img
    jc fail_load
    DBG_HALT 3, msg_dbg_3

    ; Read superblock (1 x 512-byte sector at LBA 2048 inside diffos.img)
    mov eax, SUPERBLOCK_LBA512
    mov cx, 1
    mov word [dest_segment], SUPERBLOCK_SEG
    call read_diffos_512_sectors
    DBG_HALT 4, msg_dbg_4

    ; Get filetable info from superblock
    mov ax, SUPERBLOCK_SEG
    mov es, ax

    ; SuperBlock offsets (512-byte sector LBAs):
    ; 0x0C: file_table_sector
    ; 0x10: file_table_size (in 512-byte sectors)
    mov eax, [es:0x0C]              ; Filetable LBA in 512-byte sectors

    ; Read the file table
    mov cx, [es:0x10]               ; Size in 512-byte sectors
    mov word [dest_segment], FILETABLE_SEG
    call read_diffos_512_sectors
    DBG_HALT 5, msg_dbg_5

    ; Search for /system/kernel.bin
    mov ax, FILETABLE_SEG
    mov es, ax

    ; Find "system" directory
    xor di, di
    mov cx, MAX_FILES_TABLE
    xor bp, bp

.find_system_loop:
    mov ax, [es:bp+ENTRY_OFF_TYPE]
    cmp ax, ENTRY_TYPE_DIR
    jne .next_sys

    cmp byte [es:bp+ENTRY_OFF_NAME+0], 's'
    jne .next_sys
    cmp byte [es:bp+ENTRY_OFF_NAME+1], 'y'
    jne .next_sys
    cmp byte [es:bp+ENTRY_OFF_NAME+2], 's'
    jne .next_sys
    cmp byte [es:bp+ENTRY_OFF_NAME+3], 't'
    jne .next_sys
    cmp byte [es:bp+ENTRY_OFF_NAME+4], 'e'
    jne .next_sys
    cmp byte [es:bp+ENTRY_OFF_NAME+5], 'm'
    jne .next_sys
    cmp byte [es:bp+ENTRY_OFF_NAME+6], 0
    jne .next_sys

    mov di, [es:bp+ENTRY_OFF_ENTRY_ID]
    jmp .have_system

.next_sys:
    add bp, FILE_ENTRY_SIZE
    dec cx
    jnz .find_system_loop

.have_system:
    test di, di
    jnz .search_kernel
    jmp fail_load

.search_kernel:
    mov cx, MAX_FILES_TABLE
    xor bp, bp

.find_kernel_loop:
    mov ax, [es:bp+ENTRY_OFF_TYPE]
    cmp ax, ENTRY_TYPE_FILE
    jne .next_kernel

    mov ax, [es:bp+ENTRY_OFF_PARENT_ID]
    cmp ax, di
    jne .next_kernel

    cmp byte [es:bp+ENTRY_OFF_NAME+0], 'k'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+1], 'e'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+2], 'r'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+3], 'n'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+4], 'e'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+5], 'l'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+6], '.'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+7], 'b'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+8], 'i'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+9], 'n'
    jne .next_kernel
    cmp byte [es:bp+ENTRY_OFF_NAME+10], 0
    jne .next_kernel

    ; Found kernel - get its location
    mov eax, [es:bp+ENTRY_OFF_START_SECTOR]  ; LBA in 512-byte sectors
    mov cx, [es:bp+ENTRY_OFF_SECTOR_COUNT]   ; Size in 512-byte sectors
    movzx edx, cx
    mov [kernel_sectors], edx               ; Save for PM move
    jmp .have_kernel

.next_kernel:
    add bp, FILE_ENTRY_SIZE
    dec cx
    jnz .find_kernel_loop
    jmp fail_load

.have_kernel:
    mov si, msg_loading
    call print_string
    DBG_HALT 6, msg_dbg_6

    ; Read kernel to 0x1000:0000 (physical 0x10000)
    mov word [dest_segment], 0x1000
    call read_diffos_512_sectors
    DBG_HALT 7, msg_dbg_7

    mov si, msg_done
    call print_string

    DBG_PRINT msg_a20_start
    call enable_a20
    jc fail_a20
    DBG_PRINT msg_a20_ok
    DBG_HALT 8, msg_dbg_8

    DBG_PRINT msg_pm_start
    call switch_pm

.halt:
    cli
    hlt
    jmp .halt

;
; Read CD sectors using INT 13h extensions
; Input: DX = number of CD sectors, [buffer_segment] = destination segment
;        [file_lba_low] = starting LBA
;
read_cd_sectors:
    push ds
    xor ax, ax
    mov ds, ax
    mov byte [dap], 0x10
    mov byte [dap+1], 0
    mov [dap+2], dx
    mov word [dap+4], 0
    mov ax, [buffer_segment]
    mov [dap+6], ax
    mov eax, [file_lba_low]
    mov [dap+8], eax
    mov dword [dap+12], 0

    mov si, dap
    mov dl, [boot_drive]
    mov ah, 0x42
    int 0x13
    jc .fail
    pop ds
    ret
.fail:
    pop ds
    jmp fail_load

;
; Read large file in chunks
;
read_large_file:
.next_chunk:
    mov ax, [file_remain]
    test ax, ax
    jz .done

    cmp ax, MAX_SECTORS
    jbe .use_ax
    mov dx, MAX_SECTORS
    jmp .have_dx

.use_ax:
    mov dx, ax

.have_dx:
    call read_cd_sectors

    ; Update buffer segment: add (sectors * 2048) / 16 = sectors * 128 paragraphs
    mov ax, dx
    shl ax, 7                       ; * 128
    add [buffer_segment], ax

    ; Update LBA
    movzx eax, dx
    add [file_lba_low], eax

    ; Update remaining
    sub [file_remain], dx
    jmp .next_chunk

.done:
    ret

;
; Read 512-byte sectors from diffos.img stored as an ISO file.
; Input: EAX = LBA in 512-byte sectors (inside diffos.img)
;        CX  = number of 512-byte sectors to read
;        [dest_segment] = destination segment (written contiguously, 512 bytes per segment+0x20)
;
read_diffos_512_sectors:
    push ds
    push es
    pusha

.next:
    test cx, cx
    jz .done

    DBG_HALT 31, msg_dbg_31

    ; Cache (lba512 % 4) before INT13 clobbers AX
    mov bx, ax
    and bx, 3
    xor dx, dx
    mov ds, dx

    ; CD LBA = diffos_start_cd + (lba512 / 4)
    mov edx, eax
    shr edx, 2
    add edx, [diffos_start_cd]
    mov [file_lba_low], edx

    ; Read 1 CD sector (2048 bytes) into bounce buffer
    mov word [buffer_segment], BOUNCE_SEG
    mov dx, 1
    mov [saved_lba512], eax
    push bx
    call read_cd_sectors
    pop bx
    mov eax, [saved_lba512]
    DBG_HALT 32, msg_dbg_32

    ; Offset within the 2048-byte sector: (lba512 % 4) * 512
    shl bx, 9

    ; Number of 512-byte sectors available in this CD sector
    mov bp, 4
    shr bx, 9                      ; restore remainder for the count math
    sub bp, bx
    shl bx, 9                      ; re-apply byte offset
    cmp cx, bp
    jae .have_count
    mov bp, cx
.have_count:

    ; Copy bp * 512 bytes from bounce to destination
    mov dx, [dest_segment]
    mov ax, BOUNCE_SEG
    mov ds, ax
    mov si, bx
    mov es, dx
    xor di, di
    push cx
    mov cx, bp
    shl cx, 8
    cld
    rep movsw
    pop cx
    xor ax, ax
    mov ds, ax
    DBG_HALT 33, msg_dbg_33

    ; Advance destination by bp * 512 bytes = bp * 0x20 paragraphs
    mov ax, bp
    shl ax, 5
    add [dest_segment], ax

    ; Advance LBA and remaining count
    movzx edx, bp
    add eax, edx
    sub cx, bp
    jmp .next

.done:
    popa
    pop es
    pop ds
    ret

;
; Enable A20 line (robust multi-method)
; CF set on failure
;
enable_a20:
    cli
    call a20_check
    jnc .ok

    ; BIOS A20 (INT 15h, AX=2401)
    DBG_PRINT msg_a20_bios
    mov ax, 0x2401
    int 0x15
    call a20_check
    jnc .ok

    ; Fast A20 gate (port 0x92)
    DBG_PRINT msg_a20_92
    in al, 0x92
    or al, 2
    and al, 0xFE                   ; don't reset
    out 0x92, al
    out 0x80, al                   ; I/O delay
    call a20_check
    jnc .ok

    ; Keyboard controller method (8042)
    DBG_PRINT msg_a20_kbc
    call a20_kbc_enable
    call a20_check
    jnc .ok

    stc
    ret
.ok:
    clc
    ret

;
; Check if A20 is enabled using two addresses that differ by 1MB.
; CF clear if enabled, CF set if disabled.
;
a20_check:
    ; Prefer BIOS query if available (INT 15h AX=2402)
    pushf
    pusha
    mov ax, 0x2402
    int 0x15
    jc .mem_test
    test ah, ah
    jnz .mem_test
    cmp al, 1
    je .bios_enabled
    cmp al, 0
    je .bios_disabled

.mem_test:
    xor ax, ax
    mov es, ax
    mov di, 0x0500                  ; low memory scratch
    mov ax, 0xFFFF
    mov ds, ax
    mov si, 0x0510                  ; wraps to 0x0500 if A20 is off

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

    xor ax, ax
    mov ds, ax
    mov es, ax

    jne .enabled
    popa
    popf
    stc
    ret

.bios_enabled:
    popa
    popf
    clc
    ret
.bios_disabled:
    popa
    popf
    stc
    ret
.enabled:
    popa
    popf
    clc
    ret

;
; Enable A20 using 8042 keyboard controller.
;
a20_kbc_enable:
    pusha
    ; flush output buffer
    in al, 0x64
    test al, 1
    jz .noflush
    in al, 0x60
.noflush:
    call .wait_ibf_clear
    mov al, 0xAD                  ; disable keyboard
    out 0x64, al

    call .wait_ibf_clear
    mov al, 0xD0                  ; read output port
    out 0x64, al

    call .wait_obf_set
    in al, 0x60
    push ax

    call .wait_ibf_clear
    mov al, 0xD1                  ; write output port
    out 0x64, al

    call .wait_ibf_clear
    pop ax
    or al, 2                      ; set A20 (bit 1)
    out 0x60, al

    call .wait_ibf_clear
    mov al, 0xAE                  ; enable keyboard
    out 0x64, al

    popa
    ret

.wait_ibf_clear:
    in al, 0x64
    test al, 2
    jnz .wait_ibf_clear
    ret

.wait_obf_set:
    in al, 0x64
    test al, 1
    jz .wait_obf_set
    ret

;
; Switch to protected mode
;
switch_pm:
    xor ax, ax
    mov ds, ax
    DBG_PRINT msg_pm_lgdt
    lgdt [gdt_descriptor]

    DBG_PRINT msg_pm_cr0
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp CODE_SEG:init_pm

[BITS 32]
init_pm:
    mov ax, DATA_SEG
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Ensure FPU/SSE is usable (avoid early #UD/#NM before kernel sets this up)
    mov eax, cr0
    and eax, 0xFFFFFFFB              ; clear EM
    or  eax, 0x00000022              ; set MP and NE
    mov cr0, eax
    mov eax, cr4
    or  eax, 0x00000600              ; set OSFXSR and OSXMMEXCPT
    mov cr4, eax
    fninit

    ; Clear kernel stack area
    mov edi, 0x8F000
    mov ecx, 0x400
    xor eax, eax
    rep stosd

    mov esp, 0x7FFFF
    mov ebp, esp
    push esp
    lidt [idt_descriptor]
%if DEBUG_VERBOSE = 1
    call serial_init_pm
    mov esi, msg_pm_entered
    call serial_write_pm
    mov esi, msg_pm_entered
    call vga_write_pm
%endif

%if DEBUG_VERBOSE = 1
    mov esi, msg_pm_tss
    call serial_write_pm
%endif
    ; Patch GDT TSS descriptor
    mov eax, tss
    mov word [gdt_tss + 2], ax
    shr eax, 16
    mov byte [gdt_tss + 4], al
    mov byte [gdt_tss + 7], ah

    ; Initialize TSS
    mov eax, kernel_stack_top
    mov [tss + 4], eax
    mov ax, DATA_SEG
    mov [tss + 8], ax
    mov word [tss + 102], 104

    mov ax, TSS_SEG
    ltr ax

%if DEBUG_VERBOSE = 1
    mov esi, msg_pm_copy
    call serial_write_pm
%endif
    ; Move kernel from 0x10000 to 0x100000 (1MB)
    mov esi, 0x10000
    mov edi, 0x100000
    mov ecx, [kernel_sectors]
    shl ecx, 7                      ; sectors * 512 / 4
    rep movsd

    ; Push E820 info for kernel
    push dword [mem_entry_count]
    push dword e820_buffer

%if DEBUG_VERBOSE = 1
    mov esi, msg_pm_jump
    call serial_write_pm
    mov esi, msg_pm_jump
    call vga_write_pm
%endif
    jmp CODE_SEG:0x100000

serial_init_pm:
    mov dx, 0x3F8 + 1
    mov al, 0x00
    out dx, al
    mov dx, 0x3F8 + 3
    mov al, 0x80
    out dx, al
    mov dx, 0x3F8 + 0
    mov al, 0x03
    out dx, al
    mov dx, 0x3F8 + 1
    mov al, 0x00
    out dx, al
    mov dx, 0x3F8 + 3
    mov al, 0x03
    out dx, al
    mov dx, 0x3F8 + 2
    mov al, 0xC7
    out dx, al
    mov dx, 0x3F8 + 4
    mov al, 0x0B
    out dx, al
    ret

serial_putc_pm:
    push edx
    push eax
.wait:
    mov dx, 0x3F8 + 5
    in al, dx
    test al, 0x20
    jz .wait
    pop eax
    mov dx, 0x3F8
    out dx, al
    pop edx
    ret

serial_write_pm:
    pushad
.loop:
    lodsb
    test al, al
    jz .done
    call serial_putc_pm
    jmp .loop
.done:
    popad
    ret

vga_write_pm:
    pushad
    mov edi, 0xB8000
    mov ah, 0x0F
.loop:
    lodsb
    test al, al
    jz .done
    stosw
    jmp .loop
.done:
    popad
    ret

; Minimal IDT to catch early faults before the kernel installs its own.
%macro IDT_ENTRY 1
    dw %1
    dw CODE_SEG
    db 0
    db 10001110b
    dw 0
%endmacro

idt_start:
%assign i 0
%rep 256
    IDT_ENTRY isr_stub
%assign i i+1
%endrep
idt_end:

idt_descriptor:
    dw idt_end - idt_start - 1
    dd idt_start

isr_stub:
    cli
    mov esi, msg_pm_fault
    call serial_write_pm
.halt:
    hlt
    jmp .halt

[BITS 16]
;
; Error handler
;
fail_a20:
    DBG_PRINT msg_a20_fail
    jmp fail_load

fail_load:
    mov si, msg_fail
    call print_string
    cli
    hlt
    jmp $

;
; Find diffos.img extent LBA on the CD via ISO9660 (root directory)
; Output: [diffos_start_cd] set to file extent (in 2048-byte sectors)
; CF set on failure
;
find_diffos_img:
    xor ax, ax
    mov ds, ax
    ; Read Primary Volume Descriptor at LBA 16
    mov dword [file_lba_low], 16
    mov word [buffer_segment], SUPERBLOCK_SEG
    mov dx, 1
    call read_cd_sectors
    DBG_HALT 21, msg_dbg_21

    mov ax, SUPERBLOCK_SEG
    mov es, ax

    ; Validate ISO9660 PVD header: type=1, "CD001", version=1
    cmp byte [es:0], 1
    jne .not_found
    cmp byte [es:1], 'C'
    jne .not_found
    cmp byte [es:2], 'D'
    jne .not_found
    cmp byte [es:3], '0'
    jne .not_found
    cmp byte [es:4], '0'
    jne .not_found
    cmp byte [es:5], '1'
    jne .not_found
    cmp byte [es:6], 1
    jne .not_found

    ; Root Directory Record is at offset 156 in the PVD
    mov eax, [es:156+2]             ; Extent LBA (LE)
    mov [root_dir_lba], eax
    mov eax, [es:156+10]            ; Data length in bytes (LE)
    mov [root_dir_size], eax
    DBG_HALT 22, msg_dbg_22

    ; Calculate how many 2048-byte sectors the root dir spans (cap to keep reads small)
    mov eax, [root_dir_size]
    add eax, 2047
    shr eax, 11                     ; / 2048
    mov [root_dir_sectors], ax
    test ax, ax
    jz .not_found
    cmp ax, MAX_ROOTDIR_SECTORS
    ja .not_found

    ; Scan directory records for "DIFFOS.IMG" by reading 1 CD sector at a time
    xor bx, bx                      ; sector index
.scan_sector:
    mov ax, bx
    cmp ax, [root_dir_sectors]
    jae .not_found

    mov eax, [root_dir_lba]
    movzx edx, bx
    add eax, edx
    mov [file_lba_low], eax
    mov word [buffer_segment], FILETABLE_SEG
    mov dx, 1
    call read_cd_sectors
    DBG_HALT 23, msg_dbg_23

    mov ax, FILETABLE_SEG
    mov es, ax
    xor si, si

.scan_next:
    cmp si, 2048
    jae .next_sector

    mov al, [es:si]                 ; record length
    test al, al
    jz .next_sector

    movzx bp, al                    ; record length
    test byte [es:si+25], 2         ; directory flag
    jnz .skip_record

    mov cl, [es:si+32]              ; identifier length
    cmp cl, 10
    jb .skip_record

    lea di, [si+33]                 ; identifier
    cmp byte [es:di+0], 'D'
    jne .skip_record
    cmp byte [es:di+1], 'I'
    jne .skip_record
    cmp byte [es:di+2], 'F'
    jne .skip_record
    cmp byte [es:di+3], 'F'
    jne .skip_record
    cmp byte [es:di+4], 'O'
    jne .skip_record
    cmp byte [es:di+5], 'S'
    jne .skip_record
    cmp byte [es:di+6], '.'
    jne .skip_record
    cmp byte [es:di+7], 'I'
    jne .skip_record
    cmp byte [es:di+8], 'M'
    jne .skip_record
    cmp byte [es:di+9], 'G'
    jne .skip_record

    mov eax, [es:si+2]              ; extent LBA (LE)
    mov [diffos_start_cd], eax
    clc
    ret

.skip_record:
    add si, bp
    jmp .scan_next

.next_sector:
    inc bx
    jmp .scan_sector

.not_found:
    stc
    ret

;
; Print string at DS:SI
;
print_string:
    pusha
    mov ah, 0x0E
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    push ax
    call serial_putc
    pop ax
    jmp .loop
.done:
    popa
    ret

serial_init:
    ; 115200/38400, 8n1, enable FIFO
    mov dx, 0x3F8 + 1
    mov al, 0x00
    out dx, al
    mov dx, 0x3F8 + 3
    mov al, 0x80
    out dx, al
    mov dx, 0x3F8 + 0
    mov al, 0x03
    out dx, al
    mov dx, 0x3F8 + 1
    mov al, 0x00
    out dx, al
    mov dx, 0x3F8 + 3
    mov al, 0x03
    out dx, al
    mov dx, 0x3F8 + 2
    mov al, 0xC7
    out dx, al
    mov dx, 0x3F8 + 4
    mov al, 0x0B
    out dx, al
    ret

serial_putc:
    push dx
    push ax
.wait:
    mov dx, 0x3F8 + 5
    in al, dx
    test al, 0x20
    jz .wait
    pop ax
    mov dx, 0x3F8
    out dx, al
    pop dx
    ret

; GDT
gdt_start:
    dd 0, 0                         ; Null descriptor

gdt_code:
    dw 0xFFFF, 0x0000
    db 0x00, 10011010b, 11001111b, 0x00

gdt_data:
    dw 0xFFFF, 0x0000
    db 0x00, 10010010b, 11001111b, 0x00

gdt_user_code:
    dw 0xFFFF, 0x0000
    db 0x00, 11111010b, 11001111b, 0x00

gdt_user_data:
    dw 0xFFFF, 0x0000
    db 0x00, 11110010b, 11001111b, 0x00

gdt_tss:
    dw TSS_LIMIT, 0
    db 0, 10001001b, 0, 0

gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start
USER_CODE_SEG equ (gdt_user_code - gdt_start) | 3
USER_DATA_SEG equ (gdt_user_data - gdt_start) | 3
TSS_SEG equ gdt_tss - gdt_start

; TSS
align 4
tss:
    times 104 db 0
tss_end:

section .bss
align 16
kernel_stack:
    resb 16384
kernel_stack_top:

e820_buffer:
    resb 32 * 24
mem_entry_count:
    resd 1

section .text
; Messages
msg_stage2  db 'Stage2 CD', 13, 10, 0
msg_loading db 'Loading kernel...', 13, 10, 0
msg_done    db 'OK', 13, 10, 0
msg_fail    db 'FAIL', 0
msg_a20_start db 'A20...', 13, 10, 0
msg_a20_ok    db 'A20 OK', 13, 10, 0
msg_a20_fail  db 'A20 FAIL', 13, 10, 0
msg_a20_bios  db 'A20 BIOS', 13, 10, 0
msg_a20_92    db 'A20 92', 13, 10, 0
msg_a20_kbc   db 'A20 KBC', 13, 10, 0
msg_pm_start  db 'PM...', 13, 10, 0
msg_pm_lgdt   db 'PM LGDT', 13, 10, 0
msg_pm_cr0    db 'PM CR0', 13, 10, 0
msg_pm_entered db '[PM] entered', 13, 10, 0
msg_pm_tss     db '[PM] tss', 13, 10, 0
msg_pm_copy    db '[PM] copy kernel', 13, 10, 0
msg_pm_jump    db '[PM] jump kernel', 13, 10, 0
msg_pm_fault   db '[PM] exception', 13, 10, 0
msg_dbg_1   db '[DBG] halt@1 after stage2 banner', 13, 10, 0
msg_dbg_2   db '[DBG] halt@2 after e820', 13, 10, 0
msg_dbg_3   db '[DBG] halt@3 after find_diffos_img', 13, 10, 0
msg_dbg_4   db '[DBG] halt@4 after superblock read', 13, 10, 0
msg_dbg_5   db '[DBG] halt@5 after filetable read', 13, 10, 0
msg_dbg_6   db '[DBG] halt@6 before kernel read', 13, 10, 0
msg_dbg_7   db '[DBG] halt@7 after kernel read', 13, 10, 0
msg_dbg_8   db '[DBG] halt@8 after A20 (before PM)', 13, 10, 0
msg_dbg_21  db '[DBG] halt@21 after PVD read', 13, 10, 0
msg_dbg_22  db '[DBG] halt@22 after root dir fields', 13, 10, 0
msg_dbg_23  db '[DBG] halt@23 after root dir read', 13, 10, 0
msg_dbg_31  db '[DBG] halt@31 in read512 (entry)', 13, 10, 0
msg_dbg_32  db '[DBG] halt@32 in read512 (after cd read)', 13, 10, 0
msg_dbg_33  db '[DBG] halt@33 in read512 (after copy)', 13, 10, 0

boot_drive      db 0
kernel_sectors  dd 0
diffos_start_cd dd 0
root_dir_lba    dd 0
root_dir_size   dd 0
root_dir_sectors dw 0
root_dir_bytes  dw 0
