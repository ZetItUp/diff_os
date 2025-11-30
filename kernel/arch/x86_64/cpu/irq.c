#include "irq.h"
#include "idt.h"
#include "io.h"
#include "pic.h"
#include "console.h"
#include "stdio.h"
#include "drivers/driver.h"
#include "system/scheduler.h"

irq_handler_t irq_handlers[NUM_IRQS];

volatile int g_in_irq = 0;

void irq_handler_c(unsigned irq_ptr, void *context)
{
    g_in_irq = 1;
//    uint32_t *stack = (uint32_t*)irq_ptr;
    uint32_t irq = irq_ptr; 

    uint32_t real_irq = irq - 32;

    if(irq >= 32 && real_irq < NUM_IRQS && irq_handlers[real_irq])
    {
        irq_handlers[real_irq](real_irq, context);
    }
    else if(irq < NUM_IRQS && irq_handlers[irq])
    {
        irq_handlers[irq](irq, context);
    }
    else
    {
        printf("[IRQ] Unhandled vector %u (real=%u)\n", irq, real_irq);
    }
    
    // Always send EOI
    if(irq >= 32)
    {
        pic_send_eoi((unsigned char)irq - 32);
    }
    else
    {
        pic_send_eoi((unsigned char)irq);
    }

    g_in_irq = 0;
}

void irq_install_handler(uint8_t irq, irq_handler_t handler)
{
    if(irq < NUM_IRQS)
    {
        irq_handlers[irq] = handler;
    }
}

void irq_uninstall_handler(uint8_t irq)
{
    if(irq < NUM_IRQS)
    {
        irq_handlers[irq] = 0;
    }
}

void irq_init(void) {
    idt_set_entry(32, (unsigned)irq0, 0x08, 0x8E);
    idt_set_entry(33, (unsigned)irq1, 0x08, 0x8E);
    idt_set_entry(34, (unsigned)irq2, 0x08, 0x8E);
    idt_set_entry(35, (unsigned)irq3, 0x08, 0x8E);
    idt_set_entry(36, (unsigned)irq4, 0x08, 0x8E);
    idt_set_entry(37, (unsigned)irq5, 0x08, 0x8E);
    idt_set_entry(38, (unsigned)irq6, 0x08, 0x8E);
    idt_set_entry(39, (unsigned)irq7, 0x08, 0x8E);
    idt_set_entry(40, (unsigned)irq8, 0x08, 0x8E);
    idt_set_entry(41, (unsigned)irq9, 0x08, 0x8E);
    idt_set_entry(42, (unsigned)irq10, 0x08, 0x8E);
    idt_set_entry(43, (unsigned)irq11, 0x08, 0x8E);
    idt_set_entry(44, (unsigned)irq12, 0x08, 0x8E);
    idt_set_entry(45, (unsigned)irq13, 0x08, 0x8E);
    idt_set_entry(46, (unsigned)irq14, 0x08, 0x8E);
    idt_set_entry(47, (unsigned)irq15, 0x08, 0x8E);
}
