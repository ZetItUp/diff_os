[BITS 32]

global enter_user_mode
extern thread_exit

%define USER_CS  0x1B
%define USER_DS  0x23

section .text

; void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top)
enter_user_mode:
    cld                             ; ensure DF=0

    ; Load user data segments (DPL=3 descriptors assumed present)
    mov     ax, USER_DS
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ; Read arguments
    mov     eax, [esp + 4]          ; eax = user EIP
    mov     ecx, [esp + 8]          ; ecx = user ESP

    ; Build IRET frame: SS, ESP, EFLAGS, CS, EIP
    push    dword USER_DS           ; SS
    push    ecx                     ; ESP
    pushfd                          ; EFLAGS
    or      dword [esp], 0x200      ; IF=1
    push    dword USER_CS           ; CS
    push    eax                     ; EIP

    iretd                           ; switch to ring 3

    ; Should never return; terminate thread if it does
    call    thread_exit
    hlt
    jmp     $

