#include "io.h"

unsigned char inb(unsigned short port)
{
    unsigned char ret;

    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));

    return ret;
}

void outb(unsigned short port, unsigned char data)
{
    __asm__ volatile("outb %0, %1" : : "a"(data), "Nd"(port));
}

unsigned short inw(unsigned short port)
{
    unsigned short ret;

    __asm__ volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));

    return ret;
}

void outw(unsigned short port, unsigned short data)
{
    __asm__ volatile("outw %0, %1" : : "a"(data), "Nd"(port));
}

