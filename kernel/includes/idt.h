#pragma once

#include "stdint.h"
#include "system.h"

#define IDT_SIZE 256

struct IDTEntry
{
    uint16_t offset_low;        // Offset bits 0 - 15
    uint16_t selector;          // Code segment selector in GDT
    uint8_t zero;               // Reserved
    uint8_t type_attr;          // Type and Attributes
    uint16_t offset_high;       // Offset bits 16 - 31
} __attribute__((packed));

struct IDTDescriptor
{
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

extern struct IDTEntry idt[IDT_SIZE];

void idt_set_entry(int num, uint32_t handler_addr, uint16_t selector, uint8_t type_attr);
void idt_init();

void fault_handler(struct err_stack_frame *frame);

void dump_idt(void);
