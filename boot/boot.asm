; boot.asm - Minimal bootloader med LBA-laddning av kernel.bin
BITS 16
ORG 0x7C00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov [BOOT_DRIVE], dl        ; Store boot device (0x80 för HDD)
    mov es, ax
    mov ss, ax
    
    mov bp, 0x9000
    mov sp, bp

    sti
    cld

    call enable_a20

    mov bx, 0x7C00
    mov cx, [bx + 0x1FC]
    mov [0xA000], cx

    mov ax, 0x0600  
    mov es, ax
    xor di, di
    mov byte [es:di], 0x10           ; size
    mov byte [es:di+1], 0x00         ; reserved
    mov word [es:di+2], cx           ; sector count (t.ex. [0x8000])
    mov word [es:di+4], 0x0000       ; offset
    mov word [es:di+6], 0x8000       ; segment
    mov dword [es:di+8],  0x800        ; LBA low dword
    mov dword [es:di+12], 0x0 ; LBA high dword

    mov bx, 0x7C00          ; bootsektorn ligger här
    mov cx, [bx + 0x1FC]    ; CX = antal sektorer (skrivet av Makefile)

    ; Ladda Kernel‐Disk Address Packet (DAP) med CX

    mov cx, [bx + 0x1FC]        ; cx = antal sektorer (eller sätt cx = 10 för test)
    mov si, 0                   ; si = sectors lästa hittills

.loop:
    ; Skriv ut sektornumret (si)
    mov ax, si
    call print_hex16        ; <-- se funktion nedan
    mov al, ' '
    call print_char

    ; Bygg DAP för denna sektor
    mov ax, 0x0600
    mov es, ax
    xor di, di

    mov byte [es:di], 0x10         ; size
    mov byte [es:di+1], 0x00       ; reserved
    mov word [es:di+2], 1          ; sector count = 1
    mov word [es:di+4], 0x0000     ; offset
    mov word [es:di+6], 0x8000     ; segment (0x8000:0 = 0x80000)
    mov ax, 0x800                 ; start LBA (2048)
    add ax, si                    ; + sektor offset
    mov word [es:di+8], ax             ; lba low
    mov word [es:di+10], 0
    mov dword [es:di+12], 0        ; lba high

    ; Kör LBA read (INT 13h EXT)
    mov ah, 0x42
    mov dl, [BOOT_DRIVE]
    mov si, di                     ; SI = offset till DAP i ES
    int 0x13
    jc .fail

    inc si
    cmp si, cx
    jl .loop

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
    mov cx, 4
.next_nybble:
    shl ax, 4
    mov bl, ah
    shr bl, 4
    cmp bl, 0x0A
    jl .digit
    add bl, 'A' - 0x0A
    jmp .put
.digit:
    add bl, '0'
.put:
    mov al, bl
    call print_char
    loop .next_nybble
    pop ax
    ret

    ; ---- Läs pmode.bin (två sektorer) till 0x7E00 med CHS ----
    mov ax, 0x0000
    mov es, ax
    mov bx, 0x7E00              ; Buffer
    mov ah, 0x02                ; Funktion: Read sectors
    mov al, 2                   ; 2 sektorer
    mov ch, 0                   ; Cylinder 0
    mov cl, 2                   ; Sector 2 (bootloader=1)
    mov dh, 0                   ; Head 0
    mov dl, [BOOT_DRIVE]
    int 0x13
    jc save_error

    ; ---- Läs kernel.bin från sektor 2048 till 0x100000 med LBA (int 13h extensions) ----
    mov ax, 0x8000
    mov es, ax
    xor bx, bx

    mov ax, 0x0600
    mov si, 0
    mov ah, 0x42
    mov dl, [BOOT_DRIVE] 
    int 0x13
    jc save_error

    ; ---- Hoppa till protected mode loader ----

    jmp 0x0000:0x8000

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
    
    mov ah, 0x0E
    mov al, 'W'
    int 10
    
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


; Spara BIOS-felkod till minne före du går till disk_error:
; Direkt efter "jc disk_error" på alla int 13h:
;   mov [cs:error_code], ah

error_code db 0
err_msg db "Disk error! AH=", 0
BOOT_DRIVE db 0

; ---- Padding & boot signature ----
;dap:
;    idb 0x10        ; Size of DAP (16 bytes)
;    db 0x00        ; Reserved
;    dw 0x0000           ; Number of sectors to read (ändra efter kernel.bin storlek i sektorer)
;    dw 0x0000      ; Offset
;    dw 0x1000      ; Segment (0x1000:0 = 0x100000)
;    dq 2048        ; LBA-adress (startsektor för kernel.bin)

times 510-($-$$) db 0
dw 0xAA55

