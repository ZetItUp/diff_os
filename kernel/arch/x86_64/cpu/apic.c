#include "apic.h"
#include "io.h"
#include "stdio.h"
#include "paging.h"
#include "timer.h"
#include "irq.h"

static volatile uint32_t *g_apic_base = NULL;
static volatile uint32_t *g_ioapic_base = NULL;
static uint32_t g_apic_timer_ticks_per_ms = 0;

/* Read MSR (Model Specific Register) */
static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t low, high;
    __asm__ __volatile__("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

/* Write MSR (Model Specific Register) */
static inline void wrmsr(uint32_t msr, uint64_t value)
{
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);
    __asm__ __volatile__("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}

/* Read from Local APIC register */
static inline uint32_t apic_read(uint32_t reg)
{
    if (!g_apic_base)
    {
        return 0;
    }

    return g_apic_base[reg / 4];
}

/* Write to Local APIC register */
static inline void apic_write(uint32_t reg, uint32_t value)
{
    if (!g_apic_base)
    {
        return;
    }

    g_apic_base[reg / 4] = value;
}

/* Read from I/O APIC register */
static uint32_t ioapic_read(uint8_t reg)
{
    if (!g_ioapic_base)
    {
        return 0;
    }

    g_ioapic_base[0] = reg;
    return g_ioapic_base[4];
}

/* Write to I/O APIC register */
static void ioapic_write(uint8_t reg, uint32_t value)
{
    if (!g_ioapic_base)
    {
        return;
    }

    g_ioapic_base[0] = reg;
    g_ioapic_base[4] = value;
}

bool apic_is_supported(void)
{
    uint32_t eax, ebx, ecx, edx;

    // CPUID function 1, EDX bit 9 indicates APIC support
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1));

    return (edx & (1 << 9)) != 0;
}

uint32_t apic_get_base(void)
{
    uint64_t msr = rdmsr(MSR_APIC_BASE);
    return (uint32_t)(msr & 0xFFFFF000);
}

void apic_set_base(uint32_t base)
{
    uint64_t msr = rdmsr(MSR_APIC_BASE);
    msr &= 0x0FFF;
    msr |= (base & 0xFFFFF000);
    msr |= APIC_BASE_ENABLE;
    wrmsr(MSR_APIC_BASE, msr);
}

void apic_send_eoi(void)
{
    apic_write(APIC_REG_EOI, 0);
}

uint8_t apic_get_id(void)
{
    return (uint8_t)(apic_read(APIC_REG_ID) >> 24);
}

void apic_init(void)
{
    if (!apic_is_supported())
    {
        printf("[APIC] Not supported by CPU\n");
        return;
    }

    // Get APIC base address from MSR
    uint32_t apic_phys = apic_get_base();
    if (apic_phys == 0)
    {
        apic_phys = APIC_DEFAULT_BASE;
        apic_set_base(apic_phys);
    }

    printf("[APIC] Physical base: 0x%08x\n", apic_phys);

    // Map APIC registers to virtual memory
    map_4kb_page_flags((uint32_t)APIC_DEFAULT_BASE, apic_phys, PAGE_FLAGS_IO);
    g_apic_base = (volatile uint32_t *)APIC_DEFAULT_BASE;

    // Enable APIC by setting spurious interrupt vector
    uint32_t spurious = apic_read(APIC_REG_SPURIOUS);
    spurious |= 0x100;  // APIC Software Enable bit
    spurious |= 0xFF;   // Spurious vector number
    apic_write(APIC_REG_SPURIOUS, spurious);

    // Disable LINT0 and LINT1
    apic_write(APIC_REG_LINT0, 0x10000);  // Masked
    apic_write(APIC_REG_LINT1, 0x10000);  // Masked

    // Disable performance counter and thermal sensor
    apic_write(APIC_REG_PERF, 0x10000);
    apic_write(APIC_REG_THERMAL, 0x10000);

    // Clear error status
    apic_write(APIC_REG_ESR, 0);
    apic_write(APIC_REG_ESR, 0);

    // Send EOI to clear any pending interrupts
    apic_send_eoi();

    // Set task priority to accept all interrupts
    apic_write(APIC_REG_TPR, 0);

    printf("[APIC] Initialized (ID: %u)\n", apic_get_id());
}

static void apic_timer_calibrate(void)
{
    /*
     * Calibrate APIC timer using a simple delay loop
     * We use a rough estimate: assume APIC timer runs at ~1GHz with divider 16
     * This gives us approximately 62.5 MHz effective rate
     * For 1ms, we need approximately 62500 ticks
     */

    // Set a reasonable default based on typical CPU speeds
    // Most modern CPUs have APIC timer running at CPU frequency / 16
    // Assuming ~1GHz CPU, with div-by-16 = 62.5MHz = 62500 ticks/ms
    g_apic_timer_ticks_per_ms = 62500;

    printf("[APIC] Timer calibrated (estimated): %u ticks/ms\n", g_apic_timer_ticks_per_ms);
}

void apic_timer_init(uint32_t frequency)
{
    if (!g_apic_base)
    {
        printf("[APIC] Timer init failed: APIC not initialized\n");
        return;
    }

    // Calibrate timer if not done yet
    if (g_apic_timer_ticks_per_ms == 0)
    {
        apic_timer_calibrate();
    }

    // Calculate initial count for desired frequency
    uint32_t ms_per_tick = 1000 / frequency;
    uint32_t init_count = g_apic_timer_ticks_per_ms * ms_per_tick;

    // Set timer divide configuration (divide by 16)
    apic_write(APIC_REG_TIMER_DIV, APIC_TIMER_DIV_16);

    // Set timer in periodic mode with vector 32 (NOT masked)
    apic_write(APIC_REG_TIMER, 32 | APIC_TIMER_PERIODIC);

    // Set initial count (this starts the timer)
    apic_write(APIC_REG_TIMER_INIT, init_count);

    printf("[APIC] Timer initialized: %u Hz (init_count: %u)\n", frequency, init_count);
}

void apic_timer_start(void)
{
    if (!g_apic_base)
    {
        return;
    }

    uint32_t timer_reg = apic_read(APIC_REG_TIMER);
    timer_reg &= ~0x10000;  // Unmask
    apic_write(APIC_REG_TIMER, timer_reg);
}

void apic_timer_stop(void)
{
    if (!g_apic_base)
    {
        return;
    }

    uint32_t timer_reg = apic_read(APIC_REG_TIMER);
    timer_reg |= 0x10000;  // Mask
    apic_write(APIC_REG_TIMER, timer_reg);
}

void ioapic_init(void)
{
    uint32_t ioapic_phys = IOAPIC_DEFAULT_BASE;

    // Map I/O APIC registers to virtual memory
    map_4kb_page_flags((uint32_t)IOAPIC_DEFAULT_BASE, ioapic_phys, PAGE_FLAGS_IO);
    g_ioapic_base = (volatile uint32_t *)IOAPIC_DEFAULT_BASE;

    // Read I/O APIC version and max redirection entries
    uint32_t version = ioapic_read(IOAPIC_REG_VERSION);
    uint8_t max_irqs = (uint8_t)((version >> 16) & 0xFF) + 1;

    printf("[IOAPIC] Initialized (version: 0x%02x, max IRQs: %u)\n",
           (version & 0xFF), max_irqs);

    // Mask all IRQs initially
    for (uint8_t i = 0; i < max_irqs; i++)
    {
        ioapic_mask_irq(i);
    }
}

void ioapic_map_irq(uint8_t irq, uint8_t vector, uint32_t flags)
{
    if (!g_ioapic_base)
    {
        return;
    }

    // Each redirection entry is 64 bits (2 registers)
    uint8_t reg_low = IOAPIC_REDTBL_BASE + (irq * 2);
    uint8_t reg_high = reg_low + 1;

    // Set destination APIC ID (for now, always send to BSP = APIC ID 0)
    uint32_t high = 0x00000000;  // Destination field (bits 56-63)
    ioapic_write(reg_high, high);

    // Set vector and flags
    uint32_t low = vector | flags | IOAPIC_MASKED;
    ioapic_write(reg_low, low);
}

void ioapic_unmask_irq(uint8_t irq)
{
    if (!g_ioapic_base)
    {
        return;
    }

    uint8_t reg_low = IOAPIC_REDTBL_BASE + (irq * 2);
    uint32_t value = ioapic_read(reg_low);
    value &= ~IOAPIC_MASKED;
    ioapic_write(reg_low, value);
}

void ioapic_mask_irq(uint8_t irq)
{
    if (!g_ioapic_base)
    {
        return;
    }

    uint8_t reg_low = IOAPIC_REDTBL_BASE + (irq * 2);
    uint32_t value = ioapic_read(reg_low);
    value |= IOAPIC_MASKED;
    ioapic_write(reg_low, value);
}

uint8_t ioapic_get_max_irqs(void)
{
    if (!g_ioapic_base)
    {
        return 0;
    }

    uint32_t version = ioapic_read(IOAPIC_REG_VERSION);
    return (uint8_t)((version >> 16) & 0xFF) + 1;
}
