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

    ; Load Stage 2 from disk (4 sectors) to 0x0000:0x8000
    mov byte [dap], 0x10                ; Size of DAP
    mov byte [dap+1], 0x00
    mov word [dap+2], 4                 ; Stage 2 = 4 sectors
    mov word [dap+4], 0x8000            ; Offset
    mov word [dap+6], 0x0000            ; Segment
    mov dword [dap+8], 1                ; LBA after boot sector
    mov dword [dap+12], 0
    mov si, dap
    mov dl, [boot_drive]
    mov ah, 0x42
    int 0x13
    jc .fail_stage2

    mov al, [boot_drive]
    mov [0x8000], al
    jmp 0x0000:0x8000                   ; Jump to Stage 2

.fail_stage2:
    mov si, msg_load_fail
    jmp error

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
    pop ax                              ; Restore old value as ES:DI
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

; Messages
msg_a20_fail    db 'ERROR: Setting A20 Gate Failed',0
msg_load_fail   db 'ERROR: Stage 2 boot missing',0
msg_halt        db 'System Halted',0

boot_drive      db 0                    ; Holds the boot drive number
dap: times 16 db 0

; Fill in the rest of the file with zeros and add the mandatory boot magic number at the end
times 510-($-$$) db 0
dw 0xAA55

