#pragma once

#include <stdint.h>

#define CONSOLE_COLOR_BLACK             0x0
#define CONSOLE_COLOR_BLUE              0x1
#define CONSOLE_COLOR_GREEN             0x2
#define CONSOLE_COLOR_CYAN              0x3
#define CONSOLE_COLOR_RED               0x4
#define CONSOLE_COLOR_MAGENTA           0x5
#define CONSOLE_COLOR_BROWN             0x6
#define CONSOLE_COLOR_LIGHT_GRAY        0x7
#define CONSOLE_COLOR_DARK_GRAY         0x8
#define CONSOLE_COLOR_LIGHT_BLUE        0x9
#define CONSOLE_COLOR_LIGHT_GREEN       0xA
#define CONSOLE_COLOR_LIGHT_CYAN        0xB
#define CONSOLE_COLOR_LIGHT_RED         0xC
#define CONSOLE_COLOR_LIGHT_MAGENTA     0xD
#define CONSOLE_COLOR_YELLOW            0xE
#define CONSOLE_COLOR_WHITE             0xF
#define CONSOLE_COLOR_DEFAULT           0xFF  // Reset to terminal default

int console_set_color(uint8_t fg, uint8_t bg);
int console_get_color(uint8_t *fg, uint8_t *bg);
int console_set_bgcolor(uint8_t bg);
int console_get_bgcolor(uint8_t *bg);
int console_set_fgcolor(uint8_t fg);
int console_get_fgcolor(uint8_t *fg);
