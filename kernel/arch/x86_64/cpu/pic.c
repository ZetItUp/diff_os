#include "pic.h"
#include "io.h"
#include "stdio.h"

/*
 * Remap the PICs to the given interrupt offsets-
 * "Standard" values:
 *          offset1 = 0x20
 *          offset2 = 0x28
 */
void pic_remap(int offset1, int offset2)
{
    // Start Initialization
    outb(PIC1_COMMAND, 0x11);
    io_wait();
    outb(PIC2_COMMAND, 0x11);
    io_wait();

    // Set offsets
    outb(PIC1_DATA, offset1);
    io_wait();
    outb(PIC2_DATA, offset2);
    io_wait();

    // Tell Primary PIC that there is a Secondary PIC at IRQ2 (0000 0100)
    outb(PIC1_DATA, 0x04);
    io_wait();
    // Tell Secondary PIC it's identity
    outb(PIC2_DATA, 0x02);
    io_wait();

    // Set 8086/80 Mode
    outb(PIC1_DATA, 0x01);
    io_wait();
    outb(PIC2_DATA, 0x01);
    io_wait();

    // Restore saved masks
    outb(PIC1_DATA, 0x0);
    outb(PIC2_DATA, 0x0);
}

// Send End of Interrupt Signal (EOI) to PICs
void pic_send_eoi(unsigned char irq)
{
    if(irq >= 8)
    {
        outb(PIC2_COMMAND, PIC_EOI);
    }

    outb(PIC1_COMMAND, PIC_EOI);
}

// Mask a given IRQ line. (Disable it)
void pic_set_mask(uint8_t irq_line)
{
    uint16_t port;
    uint8_t value;

    if(irq_line < 8)
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

// Unmask a given IRQ line. (Enable it)
void pic_clear_mask(uint8_t irq_line)
{
    uint16_t port = 0;
    uint8_t value = 0;

    if(irq_line < 8)
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
