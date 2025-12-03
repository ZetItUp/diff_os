#pragma once

#include "stdint.h"

// PIC 8592 Primary/Secondary ports
#define PIC1_COMMAND    0x20
#define PIC1_DATA       0x21
#define PIC2_COMMAND    0xA0
#define PIC2_DATA       0xA1

// End of Interrupt Command
#define PIC_EOI         0x20

/*
 * Remaps the PIC Interrupts
 * offset1 = Primary PIC offset
 * offset2 = Secondary PIC offset
 */
void pic_remap(int offset1, int offset2);

/*
 * Send End of Interrupt signal to PICs after handling an IRQ
 */
void pic_send_eoi(unsigned char irq);

/*
 * Mask an IRQ line. (Disable it)
 */
void pic_set_mask(uint8_t irq_line);

// Unmask an IRQ line. (Enable it)
void pic_clear_mask(uint8_t irq_line);

// Disable the PIC by masking all IRQs
void pic_disable(void);
