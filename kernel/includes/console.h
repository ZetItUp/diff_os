#ifndef CONSOLE_H
#define CONSOLE_H

// Foreground Colors
#define FG_BLACK      0x0
#define FG_BLUE       0x1
#define FG_GREEN      0x2
#define FG_CYAN       0x3
#define FG_RED        0x4
#define FG_MAGENTA    0x5
#define FG_BROWN      0x6
#define FG_GRAY       0x7
#define FG_DARKGRAY   0x8
#define FG_LIGHTBLUE  0x9
#define FG_LIGHTGREEN 0xA
#define FG_LIGHTCYAN  0xB
#define FG_LIGHTRED   0xC
#define FG_PINK       0xD
#define FG_YELLOW     0xE
#define FG_WHITE      0xF

// Background Colors
#define BG_BLACK      0x0
#define BG_BLUE       0x10
#define BG_GREEN      0x20
#define BG_CYAN       0x30
#define BG_RED        0x40
#define BG_MAGENTA    0x50
#define BG_BROWN      0x60
#define BG_LIGHTGRAY  0x70

// Combine Colors (foreground | background)
#define MAKE_COLOR(fg, bg)   ((fg) | (bg))

void putch_color(unsigned char attrib, char c);
void putch(char c);
int puts(const char *str);
void set_x(int x);
void set_y(int y);
void set_pos(int x, int y);
void set_color(unsigned char attrib);
void clear(void);
void puthex(int value);
void set_cursor_pos(unsigned short col, unsigned short row);

unsigned short get_cursor_pos(void);
unsigned short get_row(void);
unsigned short get_col(void);

#endif
