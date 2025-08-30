#pragma once

#include "stdint.h"

void vbe_putpixel(uint32_t x, uint32_t y, uint32_t argb);
void vbe_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t argb);
void vbe_clear(uint32_t argb);
int vbe_set_mode(uint32_t w, uint32_t h, uint32_t bpp);
