#pragma once

#include "stdint.h"
#include <stdbool.h>

// APIC Base MSR
#define MSR_APIC_BASE           0x1B
#define APIC_BASE_ENABLE        (1 << 11)
#define APIC_BASE_BSP           (1 << 8)

// Local APIC Register Offsets (from base address)
#define APIC_REG_ID             0x020   // Local APIC ID
#define APIC_REG_VERSION        0x030   // Local APIC Version
#define APIC_REG_TPR            0x080   // Task Priority Register
#define APIC_REG_EOI            0x0B0   // End of Interrupt
#define APIC_REG_LDR            0x0D0   // Logical Destination Register
#define APIC_REG_DFR            0x0E0   // Destination Format Register
#define APIC_REG_SPURIOUS       0x0F0   // Spurious Interrupt Vector Register
#define APIC_REG_ESR            0x280   // Error Status Register
#define APIC_REG_ICR_LOW        0x300   // Interrupt Command Register (bits 0-31)
#define APIC_REG_ICR_HIGH       0x310   // Interrupt Command Register (bits 32-63)
#define APIC_REG_TIMER          0x320   // LVT Timer Register
#define APIC_REG_THERMAL        0x330   // LVT Thermal Sensor Register
#define APIC_REG_PERF           0x340   // LVT Performance Counter Register
#define APIC_REG_LINT0          0x350   // LVT LINT0 Register
#define APIC_REG_LINT1          0x360   // LVT LINT1 Register
#define APIC_REG_ERROR          0x370   // LVT Error Register
#define APIC_REG_TIMER_INIT     0x380   // Timer Initial Count
#define APIC_REG_TIMER_CURRENT  0x390   // Timer Current Count
#define APIC_REG_TIMER_DIV      0x3E0   // Timer Divide Configuration

// APIC Timer Modes
#define APIC_TIMER_ONESHOT      0x00000000
#define APIC_TIMER_PERIODIC     0x00020000
#define APIC_TIMER_TSCDEADLINE  0x00040000

// APIC Timer Divide Values
#define APIC_TIMER_DIV_1        0x0B
#define APIC_TIMER_DIV_2        0x00
#define APIC_TIMER_DIV_4        0x01
#define APIC_TIMER_DIV_8        0x02
#define APIC_TIMER_DIV_16       0x03
#define APIC_TIMER_DIV_32       0x08
#define APIC_TIMER_DIV_64       0x09
#define APIC_TIMER_DIV_128      0x0A

// APIC Interrupt Command Register bits
#define APIC_ICR_DELIVERY_FIXED         0x00000000
#define APIC_ICR_DELIVERY_LOWEST        0x00000100
#define APIC_ICR_DELIVERY_SMI           0x00000200
#define APIC_ICR_DELIVERY_NMI           0x00000400
#define APIC_ICR_DELIVERY_INIT          0x00000500
#define APIC_ICR_DELIVERY_STARTUP       0x00000600
#define APIC_ICR_DEST_PHYSICAL          0x00000000
#define APIC_ICR_DEST_LOGICAL           0x00000800
#define APIC_ICR_DELIVERY_PENDING       0x00001000
#define APIC_ICR_LEVEL_ASSERT           0x00004000
#define APIC_ICR_LEVEL_DEASSERT         0x00000000
#define APIC_ICR_TRIGGER_EDGE           0x00000000
#define APIC_ICR_TRIGGER_LEVEL          0x00008000
#define APIC_ICR_DEST_SELF              0x00040000
#define APIC_ICR_DEST_ALL               0x00080000
#define APIC_ICR_DEST_ALL_EXCL_SELF     0x000C0000

// I/O APIC Registers
#define IOAPIC_REG_ID           0x00
#define IOAPIC_REG_VERSION      0x01
#define IOAPIC_REG_ARB          0x02
#define IOAPIC_REDTBL_BASE      0x10

// I/O APIC Redirection Entry bits
#define IOAPIC_MASKED           (1 << 16)
#define IOAPIC_TRIGGER_LEVEL    (1 << 15)
#define IOAPIC_TRIGGER_EDGE     (0 << 15)
#define IOAPIC_POLARITY_LOW     (1 << 13)
#define IOAPIC_POLARITY_HIGH    (0 << 13)
#define IOAPIC_DEST_LOGICAL     (1 << 11)
#define IOAPIC_DEST_PHYSICAL    (0 << 11)
#define IOAPIC_DELIVERY_FIXED   (0 << 8)
#define IOAPIC_DELIVERY_LOWEST  (1 << 8)
#define IOAPIC_DELIVERY_SMI     (2 << 8)
#define IOAPIC_DELIVERY_NMI     (4 << 8)
#define IOAPIC_DELIVERY_INIT    (5 << 8)
#define IOAPIC_DELIVERY_EXTINT  (7 << 8)

// Default APIC/IOAPIC addresses
#define APIC_DEFAULT_BASE       0xFEE00000
#define IOAPIC_DEFAULT_BASE     0xFEC00000

// Initialize and enable the Local APIC
void apic_init(void);

// Check if APIC is supported by the CPU
bool apic_is_supported(void);

// Get the Local APIC base address
uint32_t apic_get_base(void);

// Set the Local APIC base address and enable it
void apic_set_base(uint32_t base);

// Send End of Interrupt signal to Local APIC
void apic_send_eoi(void);

// Initialize the APIC timer (frequency in Hz)
void apic_timer_init(uint32_t frequency);

// Start the APIC timer
void apic_timer_start(void);

// Stop the APIC timer
void apic_timer_stop(void);

// Get the Local APIC ID of the current CPU
uint8_t apic_get_id(void);

// Initialize the I/O APIC
void ioapic_init(void);

// Map an IRQ line to an interrupt vector
void ioapic_map_irq(uint8_t irq, uint8_t vector, uint32_t flags);

// Unmask an IRQ line (enable it)
void ioapic_unmask_irq(uint8_t irq);

// Mask an IRQ line (disable it)
void ioapic_mask_irq(uint8_t irq);

// Get the number of IRQ entries supported by I/O APIC
uint8_t ioapic_get_max_irqs(void);
