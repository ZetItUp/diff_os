#pragma once
#include <stdint.h>

/* Offentliga GDT-selektor-symboler så ASM/C är överens vid länkning.
   Default matchar en klassisk flat 32-bit GDT (0x08,0x10,0x1B,0x23,0x28).
   Kärnan kan kalla tss_set_selectors() eller tss_install_*() om layouten skiljer sig. */
extern uint16_t GDT_KERNEL_CS_SEL;
extern uint16_t GDT_KERNEL_DS_SEL;
extern uint16_t GDT_USER_CS_SEL;
extern uint16_t GDT_USER_DS_SEL;
extern uint16_t GDT_TSS_SEL;

/* 32-bit Task State Segment enligt Intel SDM (104 bytes). */
typedef struct __attribute__((packed)) {
    uint16_t link, _r0;
    uint32_t esp0;
    uint16_t ss0, _r1;
    uint32_t esp1;
    uint16_t ss1, _r2;
    uint32_t esp2;
    uint16_t ss2, _r3;
    uint32_t cr3, eip, eflags;
    uint32_t eax, ecx, edx, ebx;
    uint32_t esp, ebp, esi, edi;
    uint16_t es, _r4;
    uint16_t cs, _r5;
    uint16_t ss, _r6;
    uint16_t ds, _r7;
    uint16_t fs, _r8;
    uint16_t gs, _r9;
    uint16_t ldt, _r10;
    uint16_t trap, iobase;
} tss_t;

/* Initiera TSS med nuvarande kernelstack-topp (esp0_init).
   Sätter ss0 till GDT_KERNEL_DS_SEL och iobase till sizeof(tss_t).
   Laddar TR med GDT_TSS_SEL (förutsätter giltig GDT-deskriptor för TSS). */
void tss_init(uint32_t esp0_init);

/* Uppdatera esp0 dynamiskt vid trådswitch etc. */
void tss_set_esp0(uint32_t esp0);

/* Valfritt: skriv över selektorvärdena om din GDT-layout skiljer sig. */
void tss_set_selectors(uint16_t kcs, uint16_t kds, uint16_t ucs, uint16_t uds, uint16_t tss_sel);

/* Installera/patcha en TSS-deskriptor i en existerande GDT i RAM.
   gdt_base: linjär adress till GDT-basen i minnet (inte GDTR), tss_sel: den selektor du vill använda.
   Skriver deskriptorfält för g_tss, uppdaterar GDT_TSS_SEL och returnerar pekare till TSS. */
tss_t* tss_install_in_gdt(void* gdt_base, uint16_t tss_sel);

/* Variant som samtidigt sätter selektorvärden (om du vill synka allt på en gång). */
tss_t* tss_install_with_gdt(void* gdt_base,
                            uint16_t kcs, uint16_t kds, uint16_t ucs, uint16_t uds,
                            uint16_t tss_sel);

/* För debug/introspection. */
tss_t* tss_get(void);

