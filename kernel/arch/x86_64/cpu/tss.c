#include "system/tss.h"
#include <stdint.h>
#include <string.h>

#ifndef KERNEL_DS
#define KERNEL_DS 0x10   /* matchar DATA_SEG (=0x10) från boot_stage2.asm */
#endif

/* ----- GDTR/TR & GDT-deskriptorer -------------------------------------- */

typedef struct __attribute__((packed)) {
    uint16_t limit;
    uint32_t base;
} gdtr_t;

typedef struct __attribute__((packed)) {
    uint16_t limit0_15;
    uint16_t base0_15;
    uint8_t  base16_23;
    uint8_t  access;
    uint8_t  flags_limit16_19;
    uint8_t  base24_31;
} gdt_desc_t;

static volatile tss_t *g_tssp = 0;

static inline void read_gdtr(gdtr_t *gdtr) {
    __asm__ __volatile__("sgdt %0" : "=m"(*gdtr));
}

static inline uint16_t read_tr(void) {
    uint16_t sel;
    __asm__ __volatile__("str %0" : "=r"(sel));
    return sel;
}

static volatile tss_t *locate_tss_via_tr(void) {
    gdtr_t gdtr;
    read_gdtr(&gdtr);

    uint16_t tr = read_tr();
    if ((tr & ~7u) == 0) return 0;               /* TR = null? */

    uint32_t index = tr >> 3;                    /* selector -> GDT-index */
    const gdt_desc_t *d = (const gdt_desc_t *)((uintptr_t)gdtr.base + index * 8);

    /* 32-bit TSS (Avail=0x9 / Busy=0xB). Vi behöver inte validera typ hårt. */
    (void)d; /* valfri sanity: uint8_t typ = d->access & 0x0F; */

    uint32_t base = ((uint32_t)d->base0_15) |
                    ((uint32_t)d->base16_23 << 16) |
                    ((uint32_t)d->base24_31 << 24);

    return (volatile tss_t *)(uintptr_t)base;
}

/* ----- Publika API:t ---------------------------------------------------- */

void tss_init(uint32_t esp0_init)
{
    /* Hitta TSS som redan är laddad av boot_stage2.asm (LTR gjort där). */
    g_tssp = locate_tss_via_tr();
    if (!g_tssp) {
        /* Om detta händer saknas TSS i GDT/TR – låt bli att krascha här. */
        return;
    }

    g_tssp->ss0  = KERNEL_DS;   /* kernel stack-segment */
    g_tssp->esp0 = esp0_init;   /* första kernelstack-toppen */
    /* I/O-bitmap pekar redan utanför TSS (bootkoden satte iobase), rör inte. */
}

void tss_set_esp0(uint32_t esp0)
{
    if (!g_tssp) {
        g_tssp = locate_tss_via_tr();   /* robusthet om init ej hunnit köras */
        if (!g_tssp) return;
    }
    g_tssp->esp0 = esp0;
}

