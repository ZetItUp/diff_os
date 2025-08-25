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
    cli                         ; avbrott av under själva bytet

    mov     eax, [esp + 4]      ; eax = old
    mov     edx, [esp + 8]      ; edx = new

    ; Spara callee-saved i old
    mov     [eax + OFF_EDI], edi
    mov     [eax + OFF_ESI], esi
    mov     [eax + OFF_EBX], ebx
    mov     [eax + OFF_EBP], ebp

    ; Spara "ret till C"-EIP för debug (retaddr på stacken)
    mov     ecx, [esp]          ; return EIP
    mov     [eax + OFF_EIP], ecx

    ; Spara nuvarande ESP (pekar på retaddr)
    mov     [eax + OFF_ESP], esp

    ; Ladda callee-saved från new
    mov     edi, [edx + OFF_EDI]
    mov     esi, [edx + OFF_ESI]
    mov     ebx, [edx + OFF_EBX]
    mov     ebp, [edx + OFF_EBP]

    ; Byt till new:s stack och hoppa dit
    mov     esp, [edx + OFF_ESP]
    sti                         ; *** viktigt: slå på avbrott innan vi ret:ar ***
    ret

; För nyskapade kernel-trådar: ret hoppar hit först
; Stack vid start:
;   [esp+0] = entry (void (*)(void*))
;   [esp+4] = arg
thread_entry_thunk:
    sti                         ; se till att IF=1 även för "första" hoppen
    mov     eax, [esp]          ; eax = entry
    mov     ecx, [esp + 4]      ; ecx = arg
    push    ecx
    call    eax                 ; entry(arg)
    call    thread_exit         ; om entry returnerar: terminera tråden
    hlt
    jmp     $

