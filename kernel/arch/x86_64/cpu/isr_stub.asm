[BITS 32]

extern fault_handler  ; C-funktion som tar emot struct eller pointer

%macro ISR_NOERR 1
global isr%1
isr%1:
    cli
    push dword 0        ; fake error code
    push dword %1       ; exception number
    jmp isr_common_stub
%endmacro

%macro ISR_ERR 1
global isr%1
isr%1:
    cli
    push dword %1       ; exception number (error code är redan pushad av CPU)
    jmp isr_common_stub
%endmacro

; ----- Alla 0–31 -----
ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_NOERR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_NOERR 30
ISR_NOERR 31

; ---- Common handler ----

isr_common_stub:
    pusha
    push ds
    push es
    push fs
    push gs
    
    mov ax, 0x10       ; Kernel data selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    mov eax, esp       ; Ge C-funktionen en pointer till structen på stacken
  
    push eax
    call fault_handler
    add esp, 4
        
    pop gs
    pop fs
    pop es
    pop ds
    popa
    add esp, 8         ; 2 x 4 bytes (error code, exception number)
    iret

