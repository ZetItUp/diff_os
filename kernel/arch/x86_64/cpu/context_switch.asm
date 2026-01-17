[BITS 32]

global context_switch
global thread_entry_thunk
extern thread_exit

; thread_t structure offsets (must match threads.h)
; thread_id:        0
; state:            4
; context:          8  (cpu_context_t, 24 bytes)
; fpu_state:       32  (fpu_state_t, 512 bytes, 16-byte aligned)
; fpu_initialized: 544

%define OFF_CONTEXT     8
%define OFF_EDI         (OFF_CONTEXT + 0)
%define OFF_ESI         (OFF_CONTEXT + 4)
%define OFF_EBX         (OFF_CONTEXT + 8)
%define OFF_EBP         (OFF_CONTEXT + 12)
%define OFF_EIP         (OFF_CONTEXT + 16)
%define OFF_ESP         (OFF_CONTEXT + 20)
%define OFF_FPU_STATE   32
%define OFF_FPU_INIT    544

section .text

; void context_switch(thread_t* old_thread, thread_t* new_thread)
; cdecl: [esp+4]=old, [esp+8]=new
context_switch:
    cli                         ; interrupts off during switch

    mov     eax, [esp + 4]      ; eax = old thread
    mov     edx, [esp + 8]      ; edx = new thread

    ; save callee-saved registers in old thread
    mov     [eax + OFF_EDI], edi
    mov     [eax + OFF_ESI], esi
    mov     [eax + OFF_EBX], ebx
    mov     [eax + OFF_EBP], ebp

    ; save return EIP for debug
    mov     ecx, [esp]          ; return EIP
    mov     [eax + OFF_EIP], ecx

    ; save current ESP
    mov     [eax + OFF_ESP], esp

    ; save FPU/SSE state for old thread
    lea     ecx, [eax + OFF_FPU_STATE]
    fxsave  [ecx]
    mov     dword [eax + OFF_FPU_INIT], 1

    ; restore FPU/SSE state for new thread
    cmp     dword [edx + OFF_FPU_INIT], 0
    je      .init_fpu           ; if not initialized, init fresh FPU state
    lea     ecx, [edx + OFF_FPU_STATE]
    fxrstor [ecx]
    jmp     .fpu_done

.init_fpu:
    ; initialize fresh FPU state for new thread
    fninit
    sub     esp, 4
    mov     dword [esp], 0x1F80
    ldmxcsr [esp]
    add     esp, 4
    mov     dword [edx + OFF_FPU_INIT], 1

.fpu_done:
    ; load callee-saved registers from new thread
    mov     edi, [edx + OFF_EDI]
    mov     esi, [edx + OFF_ESI]
    mov     ebx, [edx + OFF_EBX]
    mov     ebp, [edx + OFF_EBP]

    ; switch to new stack and return
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
