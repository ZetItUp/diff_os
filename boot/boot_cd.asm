;
; DiffOS CD-ROM Boot Sector (El Torito No-Emulation Mode)
;
; This boot sector is loaded by the BIOS from a bootable CD-ROM.
; It relocates stage 2 from the boot image and transfers control to it.
;
; El Torito no-emulation mode:
; - Boot image loaded at 0x7C00
; - DL contains the boot drive number (CD-ROM)
; - CD sectors are 2048 bytes
; - Uses INT 13h extensions (function 42h)
;

[BITS 16]
[ORG 0x7C00]

; CD-ROM sector size
CD_SECTOR_SIZE equ 2048

; Boot image layout:
; - Sector 0: this stage 1 (2048 bytes)
; - Sector 1..: stage 2 appended (padded to whole 2048-byte sectors)
%ifndef STAGE2_SECTORS
STAGE2_SECTORS equ 2
%endif

; El Torito boot info table must start at offset 8 from the start of the boot image.
; When mkisofs is invoked with -boot-info-table, it overwrites these 56 bytes.
; Keep code/data out of this region and jump around it.
    jmp short entry
    nop
    times 8-($-$$) db 0
boot_info_table:
    dd 0                        ; PVD LBA (primary volume descriptor)
boot_info_lba:
    dd 0                        ; Boot file LBA (filled by mkisofs)
    dd 0                        ; Boot file length
    dd 0                        ; Checksum
    times 40 db 0               ; Reserved (total table size = 56 bytes)

entry:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov sp, 0x7C00              ; Stack below boot sector
    mov bp, sp

    mov [boot_drive], dl        ; Save boot drive (CD-ROM) from BIOS

    ; Print boot message
    mov si, msg_boot
    call print_string
    mov si, msg_boot
    call serial_write

    ; Try enabling A20 (stage 2 will also enable it before switching to PM)
    call enable_a20

    ; Reset DS/ES after A20 test
    xor ax, ax
    mov ds, ax
    mov es, ax

    ; The BIOS loads the whole boot image (as requested via -boot-load-size)
    ; at 0x7C00, so stage 2 is already present at 0x7C00 + 2048. Relocate it
    ; to 0x8000 (where stage 2 is assembled to run) and jump.
    cld
    mov si, 0x7C00 + CD_SECTOR_SIZE
    mov di, 0x8000
    mov cx, (CD_SECTOR_SIZE * STAGE2_SECTORS) / 2
    rep movsw

    ; Jump to stage 2
    mov dl, [boot_drive]
    jmp 0x0000:0x8000

;
; Enable A20 line
;
enable_a20:
    call a20_check
    jnc .ok

    ; BIOS A20 (INT 15h, AX=2401)
    mov ax, 0x2401
    int 0x15
    call a20_check
    jnc .ok

    ; Fast A20 gate (port 0x92)
    in al, 0x92
    or al, 2
    out 0x92, al
    call a20_check
    jnc .ok

    ; Keyboard controller method (8042)
    call a20_kbc_enable
    call a20_check
    jnc .ok

    stc
    ret
.ok:
    clc
    ret

;
; Check if A20 is enabled.
; CF clear if enabled, CF set if disabled.
;
a20_check:
    pushf
    pusha
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

    xor ax, ax
    mov ds, ax
    mov es, ax

    jne .enabled
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
; Print null-terminated string at DS:SI
;
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

;
; Write null-terminated string at DS:SI to COM1
;
serial_write:
    pusha
    call serial_init
.loop:
    lodsb
    test al, al
    jz .done
    call serial_putc
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

;
; Error handler - print message and halt
;
error:
    call print_string
    mov si, msg_halt
    call print_string
    cli
    hlt
    jmp $

; Data section
msg_boot        db 'Loading DiffOS...', 13, 10, 0
msg_halt        db ' - Halt', 0

boot_drive      db 0

; Pad to 2048 bytes (one CD sector)
times 2048-($-$$) db 0
