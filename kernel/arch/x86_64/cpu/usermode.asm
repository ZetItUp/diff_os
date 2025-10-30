[BITS 32]
extern GDT_USER_CS_SEL
extern GDT_USER_DS_SEL

global enter_user_mode
global enter_user_mode_ex

%define USER_BASE        0x40000000
%define EFLAGS_IF        0x00000200
%define EFLAGS_RF        0x00010000
%define EFLAGS_IOPL      0x00003000

; ---------------------------------------------------------
; Konfig: IOPL för användarläge (0 = strikt, 3 = tillåt in/out i ring3)
; Detta behövs i din miljö eftersom user-koden gör IN/OUT omedelbart.
; ---------------------------------------------------------
%ifndef USR_IOPL_LEVEL
%define USR_IOPL_LEVEL   3
%endif

%if USR_IOPL_LEVEL = 0
%define USR_IOPL_BITS    0x00000000
%elif USR_IOPL_LEVEL = 1
%define USR_IOPL_BITS    0x00001000
%elif USR_IOPL_LEVEL = 2
%define USR_IOPL_BITS    0x00002000
%elif USR_IOPL_LEVEL = 3
%define USR_IOPL_BITS    0x00003000
%else
%error "USR_IOPL_LEVEL must be 0..3"
%endif

; enter_user_mode(entry_eip, user_stack_top)
enter_user_mode:
    push    ebp
    mov     ebp, esp

    ; Vi vill ha IF=1 och RF=1 (samma som tidigare),
    ; men EFLAGS_IOPL hanteras i enter_user_mode_ex via USR_IOPL_LEVEL
    push    dword 0                        ; clr_mask
    push    dword (EFLAGS_IF|EFLAGS_RF)    ; set_mask
    push    dword [ebp+12]                 ; user_stack_top
    push    dword [ebp+8]                  ; entry_eip
    call    enter_user_mode_ex
    add     esp, 16

    mov     esp, ebp
    pop     ebp
    ret

; enter_user_mode_ex(entry, user_esp, set_mask, clr_mask) noreturn
;  - Bygger EFLAGS från nuvarande, applicerar clr/set, FORCERAR bit1=1,
;    OCH sätter IOPL enligt USR_IOPL_LEVEL (default 3 för att undvika #GP på IN/OUT).
;  - Preloadar DS/ES/FS/GS med user-DS|3 för att undvika segmenttrash efter iret.
;  - Verifierar att både EIP och ESP ligger i user-VA (>= USER_BASE).
enter_user_mode_ex:
    push    ebp
    mov     ebp, esp

    ; Plocka argument till STABILA register
    mov     edi, [ebp+8]           ; EDI = entry_eip
    mov     ebx, [ebp+12]          ; EBX = user_stack_top

    ; Sanity: kräver user-VA
    cmp     edi, USER_BASE
    jb      .bad_eip
    cmp     ebx, USER_BASE
    jb      .bad_esp

    ; Selectorer (OR med RPL=3)
    movzx   ecx, word [GDT_USER_CS_SEL]
    or      ecx, 3                 ; ECX = USER_CS|3
    movzx   esi, word [GDT_USER_DS_SEL]
    or      esi, 3                 ; ESI = USER_DS|3

    ; Bygg EFLAGS i EAX: (kernelflags & ~clr) | set
    pushfd
    pop     eax

    mov     edx, [ebp+20]          ; clr_mask
    not     edx
    and     eax, edx               ; maska bort clr
    or      eax, [ebp+16]          ; lägg på set

    ; Bit 1 måste alltid vara satt
    or      eax, 0x00000002

    ; Rensa IOPL-bitarna och sätt enligt USR_IOPL_LEVEL (0..3)
    and     eax, (0xFFFFFFFF ^ EFLAGS_IOPL)
    or      eax, USR_IOPL_BITS

    ; Preload DS/ES/FS/GS med user-DS (ok i ring0 -> lägre privilegier, DPL=3)
    mov     dx, si                 ; DX = USER_DS|3
    mov     ds, dx
    mov     es, dx
    mov     fs, dx
    mov     gs, dx

    ; Viktigt: IRQ:er slås av här; IF i EFLAGS bestämmer om de slås på i ring3
    cli

    ; IRET-ram: SS, ESP, EFLAGS, CS, EIP (överst)
    push    dword esi              ; SS (user DS|3)
    push    dword ebx              ; ESP (user stack top)
    push    dword eax              ; EFLAGS med IF, RF och IOPL enligt policy
    push    dword ecx              ; CS (user CS|3)
    push    dword edi              ; EIP (entry)

    ; Byt CPL till 3
    iretd

.bad_eip:
    ; Hårt stopp vid felaktig EIP – behåll samma signatur som tidigare (noreturn)
    hlt
    jmp     .bad_eip

.bad_esp:
    ; Hårt stopp vid felaktig ESP
    hlt
    jmp     .bad_esp

