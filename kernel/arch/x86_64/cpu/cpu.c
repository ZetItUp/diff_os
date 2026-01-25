#include "cpu.h"
#include "serial.h"
#include "system/tss.h"
#include "string.h"

#define KERNEL_CS 0x08
#define KERNEL_DS 0x10
#define USER_CS 0x1B
#define USER_DS 0x23
#define TSS_SELECTOR 0x28

typedef struct __attribute__((packed))
{
    uint16_t limit;
    uint32_t base;
} gdt_ptr_t;

typedef struct __attribute__((packed))
{
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t granularity;
    uint8_t base_high;
} gdt_entry_t;

static gdt_entry_t g_gdt[6];
static gdt_ptr_t g_gdt_ptr;
static tss_t g_tss;

static void gdt_set_entry(int index, uint32_t base, uint32_t limit, uint8_t access, uint8_t granularity)
{
    g_gdt[index].limit_low = (uint16_t)(limit & 0xFFFFu);
    g_gdt[index].base_low = (uint16_t)(base & 0xFFFFu);
    g_gdt[index].base_mid = (uint8_t)((base >> 16) & 0xFFu);
    g_gdt[index].access = access;
    g_gdt[index].granularity = (uint8_t)((limit >> 16) & 0x0Fu);
    g_gdt[index].granularity |= (uint8_t)(granularity & 0xF0u);
    g_gdt[index].base_high = (uint8_t)((base >> 24) & 0xFFu);
}

static void gdt_flush(void)
{
    g_gdt_ptr.limit = (uint16_t)(sizeof(g_gdt) - 1u);
    g_gdt_ptr.base = (uint32_t)(uintptr_t)&g_gdt[0];

    __asm__ __volatile__("lgdt %0" : : "m"(g_gdt_ptr));

    __asm__ __volatile__(
        "mov %0, %%ds\n\t"
        "mov %0, %%es\n\t"
        "mov %0, %%fs\n\t"
        "mov %0, %%gs\n\t"
        "mov %0, %%ss\n\t"
        "ljmp $0x08, $1f\n\t"
        "1:\n\t"
        : : "r"(KERNEL_DS) : "memory");
}

static void gdt_init(void)
{
    memset(&g_gdt, 0, sizeof(g_gdt));

    gdt_set_entry(0, 0, 0, 0, 0);
    gdt_set_entry(1, 0, 0xFFFFFFFFu, 0x9A, 0xCF);
    gdt_set_entry(2, 0, 0xFFFFFFFFu, 0x92, 0xCF);
    gdt_set_entry(3, 0, 0xFFFFFFFFu, 0xFA, 0xCF);
    gdt_set_entry(4, 0, 0xFFFFFFFFu, 0xF2, 0xCF);

    memset(&g_tss, 0, sizeof(g_tss));
    g_tss.iobase = (uint16_t)sizeof(g_tss);
    gdt_set_entry(5, (uint32_t)(uintptr_t)&g_tss, sizeof(g_tss) - 1u, 0x89, 0x00);

    gdt_flush();

    __asm__ __volatile__("ltr %0" : : "r"((uint16_t)TSS_SELECTOR));
}

static inline uint32_t read_cr0(void)
{
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));

    return cr0;
}

static inline void write_cr0(uint32_t cr0)
{
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

static inline uint32_t read_cr4(void)
{
    uint32_t cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));

    return cr4;
}

static inline void write_cr4(uint32_t cr4)
{
    asm volatile("mov %0, %%cr4" :: "r"(cr4));
}

static inline uint32_t read_eflags(void)
{
    uint32_t eflags;
    asm volatile("pushf\n\tpop %0" : "=r"(eflags));

    return eflags;
}

static inline void write_eflags(uint32_t eflags)
{
    asm volatile("push %0\n\tpopf" :: "r"(eflags) : "cc");
}

static bool cpu_has_cpuid(void)
{
    uint32_t eflags = read_eflags();
    uint32_t toggled = eflags ^ (1u << 21);

    write_eflags(toggled);

    uint32_t check = read_eflags();

    write_eflags(eflags);

    if (((check ^ eflags) & (1u << 21)) == 0)
    {
        return false;
    }

    return true;
}

static inline void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    asm volatile("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf));
}

bool cpu_has_sse(void)
{
    if (!cpu_has_cpuid())
    {
        return false;
    }

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    cpuid(1, &eax, &ebx, &ecx, &edx);

    if ((edx & (1u << 25)) == 0)
    {
        return false;
    }

    return true;
}

void cpu_enable_sse(void)
{
    uint32_t cr0 = read_cr0();
    cr0 &= ~(1u << 2);
    cr0 |= (1u << 1);
    cr0 |= (1u << 5);
    write_cr0(cr0);

    uint32_t cr4 = read_cr4();
    cr4 |= (1u << 9) | (1u << 10);
    write_cr4(cr4);
}

void cpu_init(void)
{
    gdt_init();

    if (!cpu_has_sse())
    {
        serial_write("[CPU] ERROR: SSE not supported\n");

        for (;;)
        {
            asm volatile("hlt");
        }
    }

    cpu_enable_sse();
    serial_write("[CPU] SSE enabled\n");
}
