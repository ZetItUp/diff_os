// kernel/arch/x86_64/cpu/gdt.c
#include "system/gdt.h"
#include <stdint.h>
#include <stddef.h>

/* --- Små hjälpare --- */
static inline void lgdt(const gdtr_t* gdtr) {
    __asm__ __volatile__("lgdt (%0)" :: "r"(gdtr) : "memory");
}

/* Far jump via 6-byte memory operand (offset32 + selector16) för att byta CS */
struct far_ptr32 {
    uint32_t offset;
    uint16_t selector;
} __attribute__((packed));

static void gdt_flush_segments(uint16_t new_cs, uint16_t new_ds) {
    struct far_ptr32 fp;
    /* Hoppa till nästa label med new_cs i CS */
    fp.offset   = (uint32_t)(uintptr_t)&&after_ljmp;
    fp.selector = new_cs;
    __asm__ __volatile__("ljmp *%0" :: "m"(fp) : "memory");
after_ljmp:
    /* Ladda data-segment efter att CS bytts */
    __asm__ __volatile__ (
        "mov %0, %%ax \n\t"
        "mov %%ax, %%ds \n\t"
        "mov %%ax, %%es \n\t"
        "mov %%ax, %%fs \n\t"
        "mov %%ax, %%gs \n\t"
        "mov %%ax, %%ss \n\t"
        :
        : "r"(new_ds)
        : "ax", "memory");
}

/* --- GDT-tabell och GDTR i kärnans minne --- */
static gdt_entry_t gdt[GDT_COUNT];
static gdtr_t      gdtr;

/* Exporterade selektorer – faktiska konstanter enligt layouten ovan */
uint16_t GDT_KERNEL_CS_SEL = GDT_SEL(GDT_IDX_KCODE, 0); /* 0x08 */
uint16_t GDT_KERNEL_DS_SEL = GDT_SEL(GDT_IDX_KDATA, 0); /* 0x10 */
uint16_t GDT_USER_CS_SEL   = GDT_SEL(GDT_IDX_UCODE, 3); /* 0x1B */
uint16_t GDT_USER_DS_SEL   = GDT_SEL(GDT_IDX_UDATA, 3); /* 0x23 */
uint16_t GDT_TSS_SEL       = GDT_SEL(GDT_IDX_TSS,   0); /* 0x28 */

/* Flaggar/konstanter för GDT-entries */
enum {
    /* Access byte (gemensamma bitar) */
    ACC_P    = 0x80, /* Present */
    ACC_DPL0 = 0x00,
    ACC_DPL3 = 0x60,
    ACC_S    = 0x10, /* Descriptor type: 1=code/data, 0=system */

    /* Code/Data type */
    ACC_EX   = 0x08, /* Executable (1=code, 0=data) */
    ACC_DC   = 0x04, /* Direction/Conforming */
    ACC_RW   = 0x02, /* Readable for code / Writable for data */
    ACC_A    = 0x01, /* Accessed */

    /* System (TSS etc.) type */
    SYS_TSS_AVAIL = 0x09, /* 32-bit available TSS */

    /* Granularity byte (övre nibble) */
    GR_L     = 0x20, /* 64-bit (irrelevant här) */
    GR_DB    = 0x40, /* 0=16-bit, 1=32-bit segment */
    GR_G     = 0x80  /* 0=byte limit, 1=4K pages */
};

static void gdt_set_entry(int idx, uint32_t base, uint32_t limit,
                          uint8_t access, uint8_t flags_upper_nibble)
{
    gdt[idx].limit_lo = (uint16_t)(limit & 0xFFFF);
    gdt[idx].base_lo  = (uint16_t)(base & 0xFFFF);
    gdt[idx].base_mid = (uint8_t)((base >> 16) & 0xFF);
    gdt[idx].access   = access;
    /* gran = [7:4]=flags, [3:0]=limit[19:16] */
    gdt[idx].gran     = (uint8_t)(((limit >> 16) & 0x0F) | (flags_upper_nibble & 0xF0));
    gdt[idx].base_hi  = (uint8_t)((base >> 24) & 0xFF);
}

void gdt_init(void)
{
    /* Null */
    gdt_set_entry(GDT_IDX_NULL, 0, 0, 0, 0);

    /* Kernel code: base=0, limit=4GiB-1, ring0, Code|R, 32-bit, 4K gran */
    gdt_set_entry(
        GDT_IDX_KCODE,
        0, 0xFFFFF,
        (uint8_t)(ACC_P | ACC_DPL0 | ACC_S | ACC_EX | ACC_RW),
        (uint8_t)(GR_G | GR_DB | 0x0F)
    );

    /* Kernel data: base=0, limit=4GiB-1, ring0, Data|W, 32-bit, 4K gran */
    gdt_set_entry(
        GDT_IDX_KDATA,
        0, 0xFFFFF,
        (uint8_t)(ACC_P | ACC_DPL0 | ACC_S | /*data*/ ACC_RW),
        (uint8_t)(GR_G | GR_DB | 0x0F)
    );

    /* User code: base=0, limit=4GiB-1, ring3, Code|R, 32-bit, 4K gran */
    gdt_set_entry(
        GDT_IDX_UCODE,
        0, 0xFFFFF,
        (uint8_t)(ACC_P | ACC_DPL3 | ACC_S | ACC_EX | ACC_RW),
        (uint8_t)(GR_G | GR_DB | 0x0F)
    );

    /* User data: base=0, limit=4GiB-1, ring3, Data|W, 32-bit, 4K gran */
    gdt_set_entry(
        GDT_IDX_UDATA,
        0, 0xFFFFF,
        (uint8_t)(ACC_P | ACC_DPL3 | ACC_S | /*data*/ ACC_RW),
        (uint8_t)(GR_G | GR_DB | 0x0F)
    );

    /* TSS: fylls/uppdateras via gdt_install_tss() efter att TSS allokerats */
    gdt_set_entry(
        GDT_IDX_TSS,
        0, 0,
        0, 0
    );

    /* Ladda GDT */
    gdtr.base  = (uint32_t)(uintptr_t)&gdt[0];
    gdtr.limit = (uint16_t)(sizeof(gdt) - 1);
    lgdt(&gdtr);

    /* Flush segmentregister till vår nya GDT */
    gdt_flush_segments(GDT_KERNEL_CS_SEL, GDT_KERNEL_DS_SEL);
}

void gdt_install_tss(uint32_t base, uint32_t limit)
{
    // Access = Present | DPL0 | System | TSS(available)
    uint8_t access = 0x89; // 10001001b

    // Granularity = (limit >> 16) & 0x0F | 0x00 (G=0, DB=0)
    uint8_t gran = (uint8_t)((limit >> 16) & 0x0F);

    gdt_set_entry(GDT_IDX_TSS, base, limit, access, gran);
}

/* Accessor till GDT-bas/storlek (om någon initkod vill titta) */
const void* gdt_get_base(void) { return (const void*)gdtr.base; }
uint16_t    gdt_get_size(void) { return (uint16_t)(gdtr.limit + 1); }

