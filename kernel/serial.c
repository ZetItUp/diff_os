#include "io.h"
#include "stdint.h"
#include "serial.h"

#define COM1 0x3F8

void serial_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03); 
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

void serial_putc(char c)
{
    while((inb(COM1 + 5) & 0x20)==0)
    {}
    
    outb(COM1, (uint8_t)c);
}

