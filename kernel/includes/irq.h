#pragma once

#include "stdint.h"

#define NUM_IRQS    16
#define IRQ_INVALID 0xFFFFFFFFu

typedef void (*irq_handler_t)(unsigned irq, void* context);
extern irq_handler_t irq_handlers[NUM_IRQS];

extern void irq0(void);
extern void irq1(void);
extern void irq2(void);
extern void irq3(void);
extern void irq4(void);
extern void irq5(void);
extern void irq6(void);
extern void irq7(void);
extern void irq8(void);
extern void irq9(void);
extern void irq10(void);
extern void irq11(void);
extern void irq12(void);
extern void irq13(void);
extern void irq14(void);
extern void irq15(void);

int irq_register_handler(uint8_t irq, irq_handler_t handler, void *context);
int irq_unregister_handler(uint8_t irq, irq_handler_t handler, void *context);
void irq_install_handler(uint8_t irq, irq_handler_t handler);
void irq_uninstall_handler(uint8_t irq);
void irq_init(void);
void irq_set_use_apic(int use_apic);
