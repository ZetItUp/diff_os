#include "pic.h"
#include "io.h"
#include "stdio.h"

// Remap the PICs to the given interrupt offsets
// Standard values are offset1 0x20 and offset2 0x28
void pic_remap(int offset1, int offset2)
{
    // Start init
    outb(PIC1_COMMAND, 0x11);
    io_wait();
    outb(PIC2_COMMAND, 0x11);
    io_wait();

    // Set offsets
    outb(PIC1_DATA, offset1);
    io_wait();
    outb(PIC2_DATA, offset2);
    io_wait();

    // Tell primary PIC there is a secondary PIC at IRQ2
    outb(PIC1_DATA, 0x04);
    io_wait();
    // Tell secondary PIC its identity
    outb(PIC2_DATA, 0x02);
    io_wait();

    // Set 8086 80 mode
    outb(PIC1_DATA, 0x01);
    io_wait();
    outb(PIC2_DATA, 0x01);
    io_wait();

    // Restore saved masks
    outb(PIC1_DATA, 0x0);
    outb(PIC2_DATA, 0x0);
}

// Send end of interrupt signal to PICs
void pic_send_eoi(unsigned char irq_number)
{
    if (irq_number >= 8)
    {
        outb(PIC2_COMMAND, PIC_EOI);
    }

    outb(PIC1_COMMAND, PIC_EOI);
}

// Mask a given IRQ line
void pic_set_mask(uint8_t irq_line)
{
    uint16_t port;
    uint8_t value;

    if (irq_line < 8)
    {
        port = PIC1_DATA;
    }
    else
    {
        port = PIC2_DATA;
        irq_line -= 8;
    }

    value = inb(port) | (1 << irq_line);
    outb(port, value);
}

// Unmask a given IRQ line
void pic_clear_mask(uint8_t irq_line)
{
    uint16_t port = 0;
    uint8_t value = 0;

    if (irq_line < 8)
    {
        port = PIC1_DATA;
    }
    else
    {
        port = PIC2_DATA;
        irq_line -= 8;
    }

    value = inb(port) & ~(1 << irq_line);
    outb(port, value);
}

// Disable the PIC by masking all IRQs
void pic_disable(void)
{
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
}
