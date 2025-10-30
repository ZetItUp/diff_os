// system/tss.c
#include "system/tss.h"
#include "system/gdt.h"
#include <stdint.h>
#include <stddef.h>

// Single 32-bit TSS for the kernel
static tss_t g_tss;

// Tiny zero helper (no libc)
static inline void bzero(void *p, size_t n)
{
    unsigned char *q = (unsigned char *)p;

    while (n--)
    {
        *q++ = 0;
    }
}

static inline void do_ltr(uint16_t sel)
{
    // sel must be GDT selector with RPL=0
    __asm__ __volatile__("ltr %0" : : "r"(sel) : "memory");
}

// Write a 32-bit Available TSS descriptor (type=0x9) into an existing GDT in RAM
static void write_tss_descriptor(uint8_t *gdt_base, uint16_t sel, const void *base_ptr, uint32_t limit)
{
    // Compute descriptor slot: (sel & ~7) >> 3
    uint32_t index = (sel & 0xFFF8) >> 3;
    uint8_t *d = gdt_base + (index * 8);
    uint32_t base = (uint32_t)(uintptr_t)base_ptr;

    // Layout for 32-bit system segment (8 bytes)
    d[0] = (uint8_t)(limit & 0xFF);           // limit 0..7
    d[1] = (uint8_t)((limit >> 8) & 0xFF);    // limit 8..15
    d[2] = (uint8_t)(base & 0xFF);            // base 0..7
    d[3] = (uint8_t)((base >> 8) & 0xFF);     // base 8..15
    d[4] = (uint8_t)((base >> 16) & 0xFF);    // base 16..23
    d[5] = 0x89;                               // P=1, DPL=0, S=0, type=0x9 (available TSS)
    d[6] = (uint8_t)((limit >> 16) & 0x0F);   // G=0, D/B=0, L=0, AVL=0, limit 16..19
    d[7] = (uint8_t)((base >> 24) & 0xFF);    // base 24..31
}

/* --------------------------------------------------------------------------
   Public API
   -------------------------------------------------------------------------- */

tss_t *tss_get(void)
{
    return &g_tss;
}

void tss_set_selectors(uint16_t kcs, uint16_t kds,
                       uint16_t ucs, uint16_t uds,
                       uint16_t tss_sel)
{
    // These globals come from your GDT module
    GDT_KERNEL_CS_SEL = kcs;
    GDT_KERNEL_DS_SEL = kds;
    GDT_USER_CS_SEL   = ucs;
    GDT_USER_DS_SEL   = uds;
    GDT_TSS_SEL       = tss_sel;
}

// Install/patch the TSS descriptor into the current in-RAM GDT
tss_t *tss_install_in_gdt(void *gdt_base, uint16_t tss_sel)
{
    // First time: clear and set iobase so there is no IO bitmap
    if (g_tss.iobase == 0)
    {
        bzero(&g_tss, sizeof(g_tss));
        g_tss.iobase = (uint16_t)sizeof(tss_t); // no bitmap after TSS
    }

    write_tss_descriptor((uint8_t *)gdt_base, tss_sel, &g_tss, (uint32_t)(sizeof(tss_t) - 1));

    // Keep the global in sync so the rest of the kernel uses the same selector
    GDT_TSS_SEL = tss_sel;

    return &g_tss;
}

// Variant that also updates the CS/DS selectors (kernel+user)
tss_t *tss_install_with_gdt(void *gdt_base,
                            uint16_t kcs, uint16_t kds, uint16_t ucs, uint16_t uds,
                            uint16_t tss_sel)
{
    tss_set_selectors(kcs, kds, ucs, uds, tss_sel);

    return tss_install_in_gdt(gdt_base, tss_sel);
}

// Initialize TSS with current kernel stack top and load TR
void tss_init(uint32_t esp0_init)
{
    if (g_tss.iobase == 0)
    {
        bzero(&g_tss, sizeof(tss_t));
        g_tss.iobase = (uint16_t)sizeof(tss_t);
    }

    // These are required for ring3->ring0 stack switch on interrupt
    g_tss.ss0  = GDT_KERNEL_DS_SEL;
    g_tss.esp0 = esp0_init;

    // Not required, but nice for debugging to keep user segments coherent
    g_tss.cs = GDT_USER_CS_SEL;
    g_tss.ds = GDT_USER_DS_SEL;
    g_tss.es = GDT_USER_DS_SEL;
    g_tss.fs = GDT_USER_DS_SEL;
    g_tss.gs = GDT_USER_DS_SEL;
    g_tss.ss = GDT_USER_DS_SEL;

    // Ensure the TSS descriptor exists in the GDT that is currently active
    tss_install_in_gdt((void *)gdt_get_base(), GDT_TSS_SEL);

    // Finally, load TR
    do_ltr(GDT_TSS_SEL);
}

// Scheduler should call this on every kernel-thread context switch
void tss_set_esp0(uint32_t esp0)
{
    g_tss.esp0 = esp0;
}

