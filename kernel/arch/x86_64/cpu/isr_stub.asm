[BITS 32]
global  system_call_stub
extern  system_call_dispatch

section .text

; Helpers and macros
%macro ISR_NOERR 1
global isr%1
isr%1:
    push dword 0            ; fake error code
    push dword %1           ; exception number
    jmp  isr_common_stub
%endmacro

%macro ISR_ERR 1
global isr%1
isr%1:
    push dword %1           ; exception number CPU pushes error code before this
    jmp  isr_common_stub
%endmacro

%macro MAKE_IRQ 2
global irq%1
irq%1:
    push dword 0            ; fake error code keep stack layout consistent
    push dword %2           ; IRQ vector 0x20-0x2F
    jmp  irq_common_stub
%endmacro

; ISRs 0-31 + 127
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
ISR_NOERR 127

; Common ISR stub
extern  fault_handler
isr_common_stub:
    pusha
    push ds
    push es
    push fs
    push gs

    ; Switch to kernel data in ring0
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Context pointer is ESP after saves
    mov eax, esp
    push eax                 ; arg context
    call fault_handler
    add  esp, 4

    pop gs
    pop fs
    pop es
    pop ds
    popa
    add  esp, 8              ; drop error_code int_no
    iret


; IRQ stubs PIC 0-15
MAKE_IRQ 0, 32
MAKE_IRQ 1, 33
MAKE_IRQ 2, 34
MAKE_IRQ 3, 35
MAKE_IRQ 4, 36
MAKE_IRQ 5, 37
MAKE_IRQ 6, 38
MAKE_IRQ 7, 39
MAKE_IRQ 8, 40
MAKE_IRQ 9, 41
MAKE_IRQ 10, 42
MAKE_IRQ 11, 43
MAKE_IRQ 12, 44
MAKE_IRQ 13, 45
MAKE_IRQ 14, 46
MAKE_IRQ 15, 47

extern  irq_handler_c
irq_common_stub:
    pusha
    push ds
    push es
    push fs
    push gs

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Stack layout top to bottom
    ;   [esp+00] gs
    ;   [esp+04] fs
    ;   [esp+08] es
    ;   [esp+0C] ds
    ;   [esp+10-2C] pusha edi-eax 32 bytes
    ;   [esp+30] int_no from MAKE_IRQ
    ;   [esp+34] error_code 0
   
    ; IRQ number is at [esp+48] 0x30
    mov edx, [esp + 48]      ; edx is irq number
    mov eax, esp             ; eax is context

    push eax                 ; ctx
    push edx                 ; irq
    call irq_handler_c
    add  esp, 8

    pop gs
    pop fs
    pop es
    pop ds
    popa
    add  esp, 8              ; drop error_code int_no
    iret


; Syscall stub for int 0x66 or 0x80
; DPL for this gate is 3 in IDT other gates DPL 0
system_call_stub:
    cld
    push ds
    push es
    push fs
    push gs
    pushad
    
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    mov eax, esp
    push eax
    call system_call_dispatch
    add  esp, 4

    mov [esp + 4*7], eax

    popad
    pop gs
    pop fs
    pop es
    pop ds
    iretd


section .bss
    resb 8192
