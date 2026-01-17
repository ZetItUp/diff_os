#include "irq.h"
#include "idt.h"
#include "io.h"
#include "pic.h"
#include "apic.h"
#include "console.h"
#include "stdio.h"
#include "drivers/driver.h"
#include "system/scheduler.h"
#include "system/signal.h"
#include "system/spinlock.h"
#include "system/profiler.h"
#include "system/process.h"
#include "heap.h"

irq_handler_t irq_handlers[NUM_IRQS];
static int g_use_apic = 0;

volatile int g_in_irq = 0;

typedef struct irq_hook
{
    irq_handler_t handler;
    void *context;
    struct irq_hook *next;
} irq_hook_t;

static irq_hook_t *g_irq_hooks[NUM_IRQS];
static spinlock_t g_irq_locks[NUM_IRQS];
static int g_irq_locks_inited = 0;

static void irq_locks_init(void)
{
    if (g_irq_locks_inited)
    {
        return;
    }

    for (int i = 0; i < NUM_IRQS; i++)
    {
        spinlock_init(&g_irq_locks[i]);
    }

    g_irq_locks_inited = 1;
}

static void irq_clear_hooks(uint8_t irq)
{
    irq_hook_t *node = g_irq_hooks[irq];

    while (node)
    {
        irq_hook_t *next = node->next;
        kfree(node);
        node = next;
    }

    g_irq_hooks[irq] = NULL;
}

void irq_handler_c(unsigned irq_number, void *context)
{
    g_in_irq = 1;
    uint32_t irq = irq_number;

    uint32_t real_irq = irq - 32;
    uint32_t idx = (irq >= 32) ? real_irq : irq;

    // Sample user EIP on timer interrupt for profiling
    if (idx == 0 && profiler_is_active())
    {
        struct stack_frame *frame = (struct stack_frame *)context;
        process_t *proc = process_current();
        if (proc && frame)
        {
            profiler_record_sample(frame->eip, proc->pid);
        }
    }

    int have_hooks = 0;

    if (idx < NUM_IRQS)
    {
        irq_locks_init();

        uint32_t flags = 0;
        spin_lock_irqsave(&g_irq_locks[idx], &flags);

        for (irq_hook_t *node = g_irq_hooks[idx]; node; node = node->next)
        {
            have_hooks = 1;
            node->handler(idx, node->context);
        }

        spin_unlock_irqrestore(&g_irq_locks[idx], flags);
    }

    if (idx < NUM_IRQS && !have_hooks && irq_handlers[idx])
    {
        irq_handlers[idx](idx, context);
    }
    else if (idx >= NUM_IRQS || (!have_hooks && idx < NUM_IRQS && !irq_handlers[idx]))
    {
        printf("[IRQ] Unhandled vector %u (real=%u)\n", irq, real_irq);
    }

    signal_maybe_deliver_frame(process_current(), (struct stack_frame *)context);

    if (g_use_apic)
    {
        apic_send_eoi();
    }
    else
    {
        if (irq >= 32)
        {
            pic_send_eoi((unsigned char)irq - 32);
        }
        else
        {
            pic_send_eoi((unsigned char)irq);
        }
    }

    g_in_irq = 0;
}

void irq_install_handler(uint8_t irq, irq_handler_t handler)
{
    if (irq < NUM_IRQS)
    {
        irq_locks_init();

        uint32_t flags = 0;
        spin_lock_irqsave(&g_irq_locks[irq], &flags);

        irq_clear_hooks(irq);
        irq_handlers[irq] = handler;

        spin_unlock_irqrestore(&g_irq_locks[irq], flags);
    }
}

void irq_uninstall_handler(uint8_t irq)
{
    if (irq < NUM_IRQS)
    {
        irq_locks_init();

        uint32_t flags = 0;
        spin_lock_irqsave(&g_irq_locks[irq], &flags);

        irq_clear_hooks(irq);
        irq_handlers[irq] = 0;

        spin_unlock_irqrestore(&g_irq_locks[irq], flags);
    }
}

int irq_register_handler(uint8_t irq, irq_handler_t handler, void *context)
{
    if (irq >= NUM_IRQS || !handler)
    {
        return -1;
    }

    irq_locks_init();

    irq_hook_t *node = (irq_hook_t*)kmalloc(sizeof(irq_hook_t));

    if (!node)
    {
        return -1;
    }

    node->handler = handler;
    node->context = context;

    uint32_t flags = 0;
    spin_lock_irqsave(&g_irq_locks[irq], &flags);

    node->next = g_irq_hooks[irq];
    g_irq_hooks[irq] = node;
    irq_handlers[irq] = 0;

    spin_unlock_irqrestore(&g_irq_locks[irq], flags);

    return 0;
}

int irq_unregister_handler(uint8_t irq, irq_handler_t handler, void *context)
{
    if (irq >= NUM_IRQS || !handler)
    {
        return -1;
    }

    irq_locks_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_irq_locks[irq], &flags);

    irq_hook_t **node_p = &g_irq_hooks[irq];

    while (*node_p)
    {
        if ((*node_p)->handler == handler && (*node_p)->context == context)
        {
            irq_hook_t *node = *node_p;
            *node_p = node->next;
            spin_unlock_irqrestore(&g_irq_locks[irq], flags);
            kfree(node);

            return 0;
        }

        node_p = &(*node_p)->next;
    }

    spin_unlock_irqrestore(&g_irq_locks[irq], flags);

    return -1;
}

void irq_init(void)
{
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

void irq_set_use_apic(int use_apic)
{
    g_use_apic = use_apic;
}
