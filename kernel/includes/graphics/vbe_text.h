#pragma once

#include "interfaces.h"
#include "stdint.h"

int vbe_text_init(void);
int vga_capture_rom_font_early(void);
void vbe_text_clear(uint32_t argb_bg);
void vbe_text_set_colors(uint32_t argb_fg, uint32_t argb_bg);
void vbe_text_putchar(char c);

void vbe_text_set_cursor(uint32_t cx, uint32_t cy);
void vbe_text_get_cursor(uint32_t *out_x, uint32_t *out_y);

