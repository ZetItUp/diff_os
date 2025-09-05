[BITS 32]

global enter_user_mode
extern thread_exit

%define USER_CS  0x1B
%define USER_DS  0x23

section .text

; void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top)
enter_user_mode:
    cld

    ; Enable SSE in CR0/CR4: set OSFXSR/OSXMMEXCPT, clear EM, set MP
    mov     eax, cr4
    or      eax, (1 << 9) | (1 << 10)     ; OSFXSR=1, OSXMMEXCPT=1
    mov     cr4, eax

    mov     eax, cr0
    and     eax, ~(1 << 2)                ; EM=0 (no emulation)
    or      eax,  (1 << 1)                ; MP=1 (monitor coprocessor)
    mov     cr0, eax

    ; Init x87/SSE state and set MXCSR to default (0x1F80)
    fninit
    sub     esp, 4
    mov     dword [esp], 0x1F80
    ldmxcsr [esp]
    add     esp, 4

    ; Load user data segments (DPL=3)
    mov     ax, USER_DS
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     eax, [esp + 4]                ; entry_eip
    mov     ecx, [esp + 8]                ; user_stack_top

    ; Build IRET frame: SS, ESP, EFLAGS, CS, EIP
    push    dword USER_DS
    push    ecx
    pushfd
    or      dword [esp], 0x200            ; IF=1
    push    dword USER_CS
    push    eax
    iretd

    ; Should never return; terminate thread if it does
    call    thread_exit
    hlt
    jmp     $

