#include "interfaces.h"
#include "io.h"
#include "stdio.h"
#include "pic.h"

kernel_exports_t g_exports = 
{
    .inw = inw,
    .outw = outw,
    .inb = inb,
    .outb = outb,
    .outl = outl,
    .inl = inl,
    .io_wait = io_wait,
    .printf = printf,
    .vprintf = vprintf,
    .pic_clear_mask = pic_clear_mask,
    .pic_set_mask = pic_set_mask,
    .keyboard_register = keyboard_register,
    .map_physical = kernel_map_physical_addr,
    .vbe_register = vbe_register,
};

