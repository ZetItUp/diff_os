#include "system/tss.h"
#include <stdint.h>
#include <string.h>

#ifndef KERNEL_DS
#define KERNEL_DS 0x10 // Matches DATA_SEG 0x10 from boot_stage2 asm
#endif

// GDTR TR and GDT descriptors
typedef struct __attribute__((packed))
{
    uint16_t limit;
    uint32_t base;
} gdtr_t;

typedef struct __attribute__((packed))
{
    uint16_t limit0_15;
    uint16_t base0_15;
    uint8_t base16_23;
    uint8_t access;
    uint8_t flags_limit16_19;
    uint8_t base24_31;
} gdt_desc_t;

static volatile tss_t *g_tssp = 0;

static inline void read_gdtr(gdtr_t *gdtr)
{
    __asm__ __volatile__("sgdt %0" : "=m"(*gdtr));
}

static inline uint16_t read_tr(void)
{
    uint16_t selector;
    __asm__ __volatile__("str %0" : "=r"(selector));

    return selector;
}

static volatile tss_t *locate_tss_via_tr(void)
{
    gdtr_t gdtr;
    read_gdtr(&gdtr);

    uint16_t task_register_selector = read_tr();
    if ((task_register_selector & ~7u) == 0)
    {
        return 0;
    }

    // Selector to GDT index
    uint32_t index = task_register_selector >> 3;
    const gdt_desc_t *descriptor =
        (const gdt_desc_t *)((uintptr_t)gdtr.base + index * 8);

    // 32 bit TSS and no strict type check
    (void)descriptor;

    uint32_t base = ((uint32_t)descriptor->base0_15) |
                    ((uint32_t)descriptor->base16_23 << 16) |
                    ((uint32_t)descriptor->base24_31 << 24);

    return (volatile tss_t *)(uintptr_t)base;
}

void tss_init(uint32_t esp0_init)
{
    // Find the TSS already loaded by boot_stage2 asm
    g_tssp = locate_tss_via_tr();
    if (!g_tssp)
    {
        // If this happens the TSS is missing in GDT TR
        // Return for now.
        // TODO: Fix?
        return;
    }

    // Kernel stack segment
    g_tssp->ss0 = KERNEL_DS;
    g_tssp->esp0 = esp0_init;
}

void tss_set_esp0(uint32_t esp0)
{
    if (!g_tssp)
    {
        // Init if no tssp
        g_tssp = locate_tss_via_tr();

        if (!g_tssp)
        {
            return;
        }
    }

    g_tssp->esp0 = esp0;
}
