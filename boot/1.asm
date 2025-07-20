BITS 16
ORG 0x7C00

start:
    mov ax, 0x7000
    mov ss, ax
    mov sp, 0x0000
    mov bp, sp

    mov ax, 0x0600
    mov es, ax
    xor di, di

    mov byte  [es:di],   0x10
    mov byte  [es:di+1], 0x00
    mov word  [es:di+2], 1
    mov word  [es:di+4], 0x8000
    mov word  [es:di+6], 0x0000
    mov dword [es:di+8], 2048
    mov dword [es:di+12], 0

    ; (printa DAP här om du vill)

    mov dl, 0x80
    mov si, di
    mov ax, 0x0600
    mov ds, ax
    mov ah, 0x42
    int 0x13
    jc fail

    jmp 0x0000:0x8000

fail:
    mov ah, 0x0E
    mov al, 'F'
    int 0x10
    jmp $
TIMES 510-($-$$) db 0
DW 0xAA55

