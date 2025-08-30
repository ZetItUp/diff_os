#pragma once

#include <stdint.h>
#include <syscall.h>

int vbe_graphics_mode(void);
int vbe_toggle_graphics_mode(void);
int vbe_set_video_mode(int width, int height, int bpp);
int vbe_present(const void *argb32, int pitch_bytes, int width, int height);
