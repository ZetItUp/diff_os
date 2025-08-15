#ifndef IO_H
#define IO_H

#include "stdint.h"

unsigned char inb(unsigned short port);
void outb(unsigned short port, unsigned char data);
unsigned short inw(unsigned short port);
void outw(unsigned short port, unsigned short data);
void outl(uint16_t port, uint32_t value);
uint32_t inl(uint16_t port);
void io_wait(void);

#endif
