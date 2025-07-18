;boot.asm - Minimal bootloader med LBA-laddning av kernel.bin
BITS 16
ORG 0x7C00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov [BOOT_DRIVE], dl        ; Store boot device (0x80 för HDD)
    mov es, ax
    mov ss, ax
    mov bp, 0x6000
    mov sp, bp
    sti
    cld

    call enable_a20

    ; Läs antal sektorer (kernel) från offset 0x1FC i bootsektorn
    mov bx, 0x7C00
    mov cx, [bx + 0x1FC]    ; cx = kernel sectors
    
    mov ax, cx
    call print_hex16
    mov al, '-'
    call print_char

    mov cx, 2
    mov bx, 0               ; si = sektorindex

.loop:
    ; Bygg DAP på 0x0600:0
    mov ax, 0x0600
    mov es, ax
    xor di, di

    push ax
    mov ax, bx
    call print_hex16
    pop ax

    mov byte [es:di], 0x10         ; DAP size
    mov byte [es:di+1], 0
    mov word [es:di+2], 1          ; sector count = 1
    mov ax, bx
    shl ax, 9
    mov word [es:di+4], ax     ; offset
    mov word [es:di+6], 0x8000     ; segment (=> 0x80000)
    mov ax, 0x800                  ; 2048 (kernel start LBA)
    add ax, bx
    mov word [es:di+8], ax         ; lba low word
    mov word [es:di+10], 0         ; lba high word
    mov word [es:di+12], 0        ; lba high dword
    mov word [es:di+14], 0

    mov ax, 0x0600
    mov es, ax
    xor si, si

    ; Kör LBA read (INT 13h EXT)
    mov ah, 0x42
    mov dl, 0x80
    mov si, di                     ; SI = offset till DAP i ES
    int 0x13
    jc .fail

    inc bx
    cmp bx, cx
    jl .loop

    jmp $
    ; Hoppa till loaded kernel (protected mode loader)
    jmp 0x0000:0x8000

.fail:
    mov si, fail_msg
    call print_str
    jmp $

fail_msg db ' FAIL', 0

; -----------------------------------------------
; print_char: AH=0x0E, AL=tecken
print_char:
    mov ah, 0x0E
    int 0x10
    ret

; print_str: SI = offset till noll-terminerad sträng
print_str:
    lodsb
    test al, al
    jz .done
    call print_char
    jmp print_str
.done:
    ret

; print_hex16: AX = värde som ska printas (4 hex-siffror)
print_hex16:
    push ax
    push bx
    mov bx, ax
    mov cx, 4
.hex16_next:
    shl bx, 4
    mov al, bh
    shr al, 4
    cmp al, 0x0A
    jl .digit
    add al, 'A' - 0x0A
    jmp .out
.digit:
    add al, '0'
.out:
    mov ah, 0x0E
    int 0x10
    loop .hex16_next
    pop bx
    pop ax
    ret

enable_a20:
    pusha
.wait_input:
    in al, 0x64
    test al, 0x02
    jnz .wait_input
    mov al, 0xD1
    out 0x64, al
.wait_input2:
    in al, 0x64
    test al, 0x02
    jnz .wait_input2
    mov al, 0xDF
    out 0x60, al
    popa
    ret

; BIOS disk error reporting
disk_error:
    push ds
    mov ax, cs
    mov ds, ax
    mov si, err_msg
.print:
    lodsb
    or al, al
    jz .show_error
    mov ah, 0x0E
    int 0x10
    jmp .print
.show_error:
    mov ah, 0x0E
    mov al, ' '
    int 0x10
    mov al, 'H'
    int 0x10
    mov al, 'x'
    int 0x10
    mov al, [error_code]
    call print_hex8
    pop ds
    cli
    hlt

save_error:
    mov [cs:error_code], ah
    jmp disk_error

print_hex8:
    push ax
    mov ah, al
    shr al, 4
    call print_hex_digit
    mov al, ah
    and al, 0x0F
    call print_hex_digit
    pop ax
    ret

print_hex_digit:
    cmp al, 10
    jl .num
    add al, 'A'-10
    jmp .out
.num:
    add al, '0'
.out:
    mov ah, 0x0E
    int 0x10
    ret

error_code db 0
err_msg db "Disk error! AH=", 0
msg db "KLART!", 0
BOOT_DRIVE db 0

times 510-($-$$) db 0
dw 0xAA55

