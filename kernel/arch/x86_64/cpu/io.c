#include "io.h"

unsigned char inb(unsigned short port)
{
    unsigned char value;

    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));

    return value;
}

void outb(unsigned short port, unsigned char data)
{
    __asm__ volatile("outb %0, %1" : : "a"(data), "Nd"(port));
}

unsigned short inw(unsigned short port)
{
    unsigned short value;

    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));

    return value;
}

void outw(unsigned short port, unsigned short data)
{
    __asm__ volatile("outw %0, %1" : : "a"(data), "Nd"(port));
}

void outl(uint16_t port, uint32_t value)
{
    __asm__ __volatile__("outl %0, %1" : : "a"(value), "dN"(port));
}

uint32_t inl(uint16_t port)
{
    uint32_t value;

    __asm__ __volatile__("inl %1, %0" : "=a"(value) : "dN"(port));

    return value;
}

void io_wait(void)
{
    __asm__ __volatile__("outb %0, $0x80" : : "a"((uint8_t)0));
}
