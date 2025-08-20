section .text
bits 32

global context_switch
global thread_entry_thunk
extern thread_yield
extern thread_exit

context_switch:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov eax,[ebp+8]
    mov [eax+0],edi
    mov [eax+4],esi
    mov [eax+8],ebx
    mov [eax+12],ebp
    mov dword [eax+16],.ret_here
    mov [eax+20],esp

    mov eax,[ebp+12]
    mov edi,[eax+0]
    mov esi,[eax+4]
    mov ebx,[eax+8]
    mov ebp,[eax+12]
    mov edx,[eax+16]
    mov esp,[eax+20]
    jmp edx

.ret_here:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

thread_entry_thunk:
    sti
    mov eax,ebx
    pop ecx
    push ecx
    call eax
    call thread_exit
    hlt
    jmp $

