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

; void context_switch(cpu_context_t* old_ctx, cpu_context_t* new_ctx)
; cdecl: [esp+4]=old, [esp+8]=new
context_switch:
    cli                         ; interrupts off during switch

    mov     eax, [esp + 4]      ; eax is old
    mov     edx, [esp + 8]      ; edx is new

    ; save callee saved in old
    mov     [eax + OFF_EDI], edi
    mov     [eax + OFF_ESI], esi
    mov     [eax + OFF_EBX], ebx
    mov     [eax + OFF_EBP], ebp

    ; save return EIP for debug
    mov     ecx, [esp]          ; return EIP
    mov     [eax + OFF_EIP], ecx

    ; save current ESP points to return
    mov     [eax + OFF_ESP], esp

    ; load callee saved from new
    mov     edi, [edx + OFF_EDI]
    mov     esi, [edx + OFF_ESI]
    mov     ebx, [edx + OFF_EBX]
    mov     ebp, [edx + OFF_EBP]

    ; switch to new stack and jump
    mov     esp, [edx + OFF_ESP]
    ret                         ; return with interrupts still disabled

; new kernel threads return here first
; stack at start
;   [esp+0] = entry (void (*)(void*))
;   [esp+4] = arg
thread_entry_thunk:
    sti                         ; ensure IF=1 for first entry
    mov     eax, [esp]          ; eax is entry
    mov     ecx, [esp + 4]      ; ecx is arg
    push    ecx
    call    eax                 ; entry(arg)
    call    thread_exit         ; if entry returns terminate the thread
    hlt
    jmp     $
