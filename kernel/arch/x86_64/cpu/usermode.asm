[BITS 32]
global enter_user_mode
%define USER_CODE_SEG   0x1B
%define USER_DATA_SEG   0x23

section .text
enter_user_mode:
    cli

    mov eax, [esp+4]    ; user EIP
    mov edx, [esp+8]    ; user ESP

    mov ecx, 0x23       ; user data selector
    mov ds, cx
    mov es, cx
    mov fs, cx
    mov gs, cx

    push dword 0x23     ; SS
    push edx            ; ESP
    pushfd              ; EFLAGS
    pop ebx
    or ebx, 0x200       ; IF=1
    push ebx
    push dword 0x1B     ; CS
    push eax            ; EIP

    iretd
