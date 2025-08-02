#pragma once

#include "drivers/ddf.h"
#include "stdio.h"
#include "stdint.h"

kernel_exports_t g_exports =
{
    .inb = inb,
    .outb = outb,
    .printf = printf,
    .pic_clear_mask = pic_clear_mask,
    .pic_set_mask = pic_set_mask
};
