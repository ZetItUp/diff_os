;
; context_switch.asm
; void context_switch(cpu_context_t *save, const cpu_context_t *load);
; Saves callee-saved regs + synthetic EIP/ESP for the current thread, restores next, and jumps.

[BITS 32]

global context_switch
global thread_entry_thunk
extern thread_exit

%define OFF_EDI  0
%define OFF_ESI  4
%define OFF_EBX  8
%define OFF_EBP  12
%define OFF_EIP  16
%define OFF_ESP  20

section .text

; -----------------------------------------------------------------------------
; context_switch(save, load)
; -----------------------------------------------------------------------------
context_switch:
    ; Arguments
    mov     eax, [esp + 4]         ; save
    mov     edx, [esp + 8]         ; load

    ; Save callee-saved registers
    mov     [eax + OFF_EDI], edi
    mov     [eax + OFF_ESI], esi
    mov     [eax + OFF_EBX], ebx
    mov     [eax + OFF_EBP], ebp

    ; Save synthetic return EIP and post-ret ESP
    mov     ecx, [esp]             ; return address to caller
    mov     [eax + OFF_EIP], ecx
    lea     ecx, [esp + 4]         ; ESP as it will be after 'ret'
    mov     [eax + OFF_ESP], ecx

    ; Restore next thread's context
    mov     edi, [edx + OFF_EDI]
    mov     esi, [edx + OFF_ESI]
    mov     ebx, [edx + OFF_EBX]
    mov     ebp, [edx + OFF_EBP]
    mov     esp, [edx + OFF_ESP]
    jmp     dword [edx + OFF_EIP]  ; continue as if we had returned

; -----------------------------------------------------------------------------
; thread_entry_thunk
; Stack layout for a brand new kernel thread:
;   [esp+0] = entry
;   [esp+4] = arg
; -----------------------------------------------------------------------------
thread_entry_thunk:
    ; Caller ensured interrupts state as appropriate before jumping here.
    mov     eax, [esp + 0]         ; entry
    mov     ecx, [esp + 4]         ; arg
    push    ecx
    call    eax

    ; If the entry returns, terminate the thread
    call    thread_exit
    hlt
    jmp     $

