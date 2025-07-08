; boot.asm - Minimal bootloader
BITS 16         ; We are in 16-bit real mode (BIOS starts here)
ORG 0x7C00      ; BIOS Bootloader starts at 0x7C00

start:
    cli         ; Disable interrupts
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00      ; Simple stack (we're in real mode)

    ; Read 4 sectors from disk (pmode.bin) int 0x7E00
    mov bx, 0x7E00      ; Destination Address
    mov es, ax      ; Destination segment (0x0000:0x7E00 = 0x7E00 physical)
    mov dh, 0           ; Head
    mov dl, [boot_drive]           ; Boot drive passed from BIOS
    mov ch, 0           ; Cylinder
    mov cl, 2           ; Sector 2 (first sector after bootloader)
    mov al, 4           ; Number of sectors to read
   
    call disk_load

    ; Jump to loaded protected mode code (start of pmode.bin)
    jmp 0x0000:0x7E00

; Disk load routine (INT 13h)
; Inputs:
;       AL = Number of Sectors
;       CH = Cylinder
;       CL = Sector
;       DH = Head
;       DL = Drive
;       ES:BX = buffer
disk_load:
    pusha
    mov si, 10          ; Retry counter (Max 10 tries)
.read_retry:
    mov ah, 0x02        ; Function 2: Read sectors
    int 0x13
    jc  .error          ; If error, retry
    popa
    ret

.error:
    dec si
    jz .fail            ; If retries = 0, fail
    jmp .read_retry

.fail:
    popa
    ; Halt CPU on failure to avoid any damage
    cli
    hlt
    jmp $

boot_drive: db 0

; Fill remaining bytes with zeros up to 510 bytes total
times 510 - ($ - $$) db 0

; Boot sector signature (2 bytes) must be 0x55AA for BIOS to recognise
; the boot sector.
dw 0xAA55

