[BITS 16]
[ORG 0x7C00]

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax

    mov ax, 0x7000          ; Säkert stackområde
    mov ss, ax
    mov sp, 0x0000
    sti
    cld

    mov [boot_drive], dl

    call enable_a20

    ; -------------------------------
    ; Load pmode.bin (LBA 1) to 0x8000
    ; -------------------------------
    mov cx, 3                  ; max 3 försök
pmode_try:
    ; Bygg DAP för pmode
    lea si, [dap_pmode]
    mov word [dap_pmode], 0x10         ; size
    mov word [dap_pmode+2], 1          ; count
    mov word [dap_pmode+4], 0x8000     ; offset
    mov word [dap_pmode+6], 0x0000     ; segment
    mov dword [dap_pmode+8], 1         ; LBA
    mov dword [dap_pmode+12], 0

    mov dl, [boot_drive]
    mov ah, 0x42
    int 0x13
    jnc pmode_ok
    loop pmode_try
    mov al, ah
    jmp disk_fail
pmode_ok:
    ; -------------------------------
    ; Load kernel.bin (LBA 2048) to 0x10000
    ; -------------------------------
    mov cx, 3
kernel_try:
    mov ax, [0x1FC]
    lea si, [dap_kernel]
    mov word [dap_kernel], 0x10        ; size
    mov word [dap_kernel+2], 4 ; (eller 1 om du bara vill ha 1 sektor)
    mov word [dap_kernel+4], 0x0000    ; offset
    mov word [dap_kernel+6], 0x9000    ; segment
    mov dword [dap_kernel+8], 2048     ; LBA
    mov dword [dap_kernel+12], 0

    mov dl, [boot_drive]
    mov ah, 0x42
    int 0x13

    jnc kernel_ok
    loop kernel_try
    mov al, ah
    jmp disk_fail
kernel_ok:
    cli    
    jmp 0x0000:0x8000           ; Hoppa till pmode.bin

disk_fail:
    mov ah, 0x0E
    mov bx, fail_msg
.printfail:
    mov al, [bx]
    cmp al, 0
    je .printcode
    int 0x10
    inc bx
    jmp .printfail
.printcode:
    mov al, ' '
    int 0x10
    mov ah, 0x0E
    mov al, '0'
    int 0x10
    mov al, 'x'
    int 0x10
    mov ah, 0x0E
    mov al, [esp]    ; AH = BIOS error code
    call print_hex8
    jmp $

print_hex8:
    push ax
    push cx
    mov cx, 2
.hexloop:
    rol al, 4
    mov ah, 0x0E
    mov bl, al
    and bl, 0x0F
    add bl, '0'
    cmp bl, '9'
    jbe .num
    add bl, 7
.num:
    mov al, bl
    int 0x10
    loop .hexloop
    pop cx
    pop ax
    ret

enable_a20:
    in   al, 0x64
    test al, 2
    jnz  enable_a20
    mov  al, 0xD1
    out  0x64, al

    in   al, 0x64
    test al, 2
    jnz  $ ; Fastna här? HW-problem.
    mov  al, 0xDF
    out  0x60, al
    ret


fail_msg: db 'FAIL (BIOS code):',0
boot_drive: db 0

dap_pmode:  times 16 db 0
dap_kernel: times 16 db 0

TIMES 510-($-$$) db 0
DW 0xAA55

