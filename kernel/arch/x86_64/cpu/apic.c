#include "apic.h"
#include "io.h"
#include "stdio.h"
#include "paging.h"
#include "timer.h"
#include "irq.h"

static volatile uint32_t *g_apic_base = NULL;
static volatile uint32_t *g_ioapic_base = NULL;
static uint32_t g_apic_timer_ticks_per_ms = 0;

// Read model specific register
static inline uint64_t read_model_specific_register(uint32_t msr)
{
    uint32_t eax;
    uint32_t edx;

    __asm__ __volatile__("rdmsr" : "=a"(eax), "=d"(edx) : "c"(msr));

    return ((uint64_t)edx << 32) | eax;
}

// Write model specific register
static inline void write_model_specific_register(uint32_t msr, uint64_t value)
{
    uint32_t eax = (uint32_t)value;
    uint32_t edx = (uint32_t)(value >> 32);

    __asm__ __volatile__("wrmsr" : : "c"(msr), "a"(eax), "d"(edx));
}

// Read from local APIC register
static inline uint32_t apic_read(uint32_t reg)
{
    if (!g_apic_base)
    {
        return 0;
    }

    return g_apic_base[reg / 4];
}

// Write to local APIC register
static inline void apic_write(uint32_t reg, uint32_t value)
{
    if (!g_apic_base)
    {
        return;
    }

    g_apic_base[reg / 4] = value;
}

// Read from IO APIC register
static uint32_t ioapic_read(uint8_t reg)
{
    if (!g_ioapic_base)
    {
        return 0;
    }

    g_ioapic_base[0] = reg;

    return g_ioapic_base[4];
}

// Write to IO APIC register
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
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    // CPUID function 1 and EDX bit 9 shows APIC support
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1));

    return (edx & (1 << 9)) != 0;
}

uint32_t apic_get_base(void)
{
    uint64_t msr = read_model_specific_register(MSR_APIC_BASE);

    return (uint32_t)(msr & 0xFFFFF000);
}

void apic_set_base(uint32_t base)
{
    uint64_t msr = read_model_specific_register(MSR_APIC_BASE);

    msr &= 0x0FFF;
    msr |= (base & 0xFFFFF000);
    msr |= APIC_BASE_ENABLE;
    write_model_specific_register(MSR_APIC_BASE, msr);
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
    spurious |= 0x100;
    spurious |= 0xFF;
    apic_write(APIC_REG_SPURIOUS, spurious);

    // Disable LINT0 and LINT1
    apic_write(APIC_REG_LINT0, 0x10000);
    apic_write(APIC_REG_LINT1, 0x10000);

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
    // Calibrate APIC timer using a simple delay loop
    // Use a rough estimate for CPU frequency and divider
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

    // Set timer divide configuration
    apic_write(APIC_REG_TIMER_DIV, APIC_TIMER_DIV_16);

    // Set timer in periodic mode with vector 32
    apic_write(APIC_REG_TIMER, 32 | APIC_TIMER_PERIODIC);

    // Set initial count to start the timer
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
    timer_reg &= ~0x10000;
    apic_write(APIC_REG_TIMER, timer_reg);
}

void apic_timer_stop(void)
{
    if (!g_apic_base)
    {
        return;
    }

    uint32_t timer_reg = apic_read(APIC_REG_TIMER);
    timer_reg |= 0x10000;
    apic_write(APIC_REG_TIMER, timer_reg);
}

void ioapic_init(void)
{
    uint32_t ioapic_phys = IOAPIC_DEFAULT_BASE;

    // Map IO APIC registers to virtual memory
    map_4kb_page_flags((uint32_t)IOAPIC_DEFAULT_BASE, ioapic_phys, PAGE_FLAGS_IO);
    g_ioapic_base = (volatile uint32_t *)IOAPIC_DEFAULT_BASE;

    // Read IO APIC version and max redirection entries
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

    // Each redirection entry is 64 bits
    uint8_t register_low = IOAPIC_REDTBL_BASE + (irq * 2);
    uint8_t register_high = register_low + 1;

    // Set destination APIC ID to BSP
    uint32_t high_value = 0x00000000;
    ioapic_write(register_high, high_value);

    // Set vector and flags
    uint32_t low_value = vector | flags | IOAPIC_MASKED;
    ioapic_write(register_low, low_value);
}

void ioapic_unmask_irq(uint8_t irq)
{
    if (!g_ioapic_base)
    {
        return;
    }

    uint8_t register_low = IOAPIC_REDTBL_BASE + (irq * 2);
    uint32_t value = ioapic_read(register_low);
    value &= ~IOAPIC_MASKED;
    ioapic_write(register_low, value);
}

void ioapic_mask_irq(uint8_t irq)
{
    if (!g_ioapic_base)
    {
        return;
    }

    uint8_t register_low = IOAPIC_REDTBL_BASE + (irq * 2);
    uint32_t value = ioapic_read(register_low);
    value |= IOAPIC_MASKED;
    ioapic_write(register_low, value);
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
