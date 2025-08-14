#include "interfaces.h"
#include "io.h"
#include "stdio.h"
#include "pic.h"

kernel_exports_t g_exports = 
{
    .inb = inb,
    .outb = outb,
    .printf = printf,
    .vprintf = vprintf,
    .pic_clear_mask = pic_clear_mask,
    .pic_set_mask = pic_set_mask,
    .keyboard_register = keyboard_register,
};

