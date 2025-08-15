// All comments are written in English.
// Allman brace style is used consistently.

#include "io.h"
#include "console.h"
#include "stdint.h"
#include "stdio.h"
#include "serial.h"
#include "graphics/vbe_text.h"

#define SCREEN_WIDTH    80
#define SCREEN_HEIGHT   25
#define VIDEO_MEMORY    ((volatile unsigned short*)0xB8000)

#ifndef CONSOLE_LOG_CAP
#define CONSOLE_LOG_CAP 16384  // 16 KB Console log
#endif

static int cursor_x = 0;
static int cursor_y = 0;

static int floor_enabled = 0;
static int floor_x = 0;
static int floor_y = 0;

static int s_vbe_console_active = 0;   // When 1, route output to VBE text backend

unsigned char current_attrib = MAKE_COLOR(FG_GRAY, BG_BLACK);

typedef struct console_log_entry
{
    unsigned char attrib;
    char ch;
} console_log_entry_t;

static console_log_entry_t s_logbuf[CONSOLE_LOG_CAP];
static unsigned s_log_head = 0;
static unsigned s_log_count = 0;
static int s_replaying = 0;

// VGA 16-color palette mapped to 24-bit RGB (no alpha here)
static const uint32_t s_vga_rgb[16] =
{
    0x000000, // 0 black
    0x0000AA, // 1 blue
    0x00AA00, // 2 green
    0x00AAAA, // 3 cyan
    0xAA0000, // 4 red
    0xAA00AA, // 5 magenta
    0xAA5500, // 6 brown
    0xAAAAAA, // 7 light gray
    0x555555, // 8 dark gray
    0x5555FF, // 9 bright blue
    0x55FF55, // 10 bright green
    0x55FFFF, // 11 bright cyan
    0xFF5555, // 12 bright red
    0xFF55FF, // 13 bright magenta
    0xFFFF55, // 14 yellow
    0xFFFFFF  // 15 white
};

static inline void vbe_apply_colors_from_attrib(unsigned char attrib)
{
    uint8_t fg = attrib & 0x0F;
    uint8_t bg = (attrib >> 4) & 0x0F;

    // Make them opaque ARGB
    uint32_t argb_fg = 0xFF000000u | s_vga_rgb[fg];
    uint32_t argb_bg = 0xFF000000u | s_vga_rgb[bg];

    vbe_text_set_colors(argb_fg, argb_bg);
}

static void log_append(unsigned char attrib, char c)
{
    if (s_replaying)
    {
        return;
    }

    s_logbuf[s_log_head].attrib = attrib;
    s_logbuf[s_log_head].ch = c;

    s_log_head = (s_log_head + 1) % CONSOLE_LOG_CAP;

    if (s_log_count < CONSOLE_LOG_CAP)
    {
        s_log_count++;
    }
    // else: overwrite oldest silently
}

static inline char vga_cell_to_ascii(uint16_t cell)
{
    uint8_t ch = (uint8_t)(cell & 0x00FF);

    // Replace control chars and CP437 (>0x7E) with space
    if (ch < 0x20 || ch >= 0x7F)
    {
        return ' ';
    }

    return (char)ch;
}

void console_flush_from_vga_text(void)
{
    if (!g_vbe.frame_buffer)
    {
        return;
    }

    vbe_text_set_cursor(0, 0);

    for (uint32_t row = 0; row < SCREEN_HEIGHT; row++)
    {
        for (uint32_t col = 0; col < SCREEN_WIDTH; col++)
        {
            uint16_t cell = VIDEO_MEMORY[row * SCREEN_WIDTH + col];
            vbe_text_putchar(vga_cell_to_ascii(cell));
        }

        // End of line
        vbe_text_putchar('\n');
    }
}

void console_flush_log(void)
{
    // Disable input floor while replaying to avoid backspace filtering
    int saved_floor_enabled = floor_enabled;
    int saved_floor_x = floor_x;
    int saved_floor_y = floor_y;

    floor_enabled = 0;

    // Clear current backend so replay starts from top-left
    clear();

    s_replaying = 1;

    unsigned idx = (s_log_head + CONSOLE_LOG_CAP - s_log_count) % CONSOLE_LOG_CAP;
    idx = 0;
    for (unsigned i = 0; i < s_log_count; i++)
    {
        console_log_entry_t e = s_logbuf[idx];
        putch_color(e.attrib, e.ch);

        idx++;
        if (idx == CONSOLE_LOG_CAP)
        {
            idx = 0;
        }
    }

    s_replaying = 0;
    
    // Restore floor state
    floor_enabled = saved_floor_enabled;
    floor_x = saved_floor_x;
    floor_y = saved_floor_y;
}

uint8_t vga_cell_height(void)
{
    if (s_vbe_console_active)
    {
        // In VBE mode, cell height is controlled by the text backend (8x16).
        return 16;
    }

    outb(0x3D4, 0x09);                 // Maximum Scan Line register
    return (inb(0x3D5) & 0x1F) + 1;    // Height in scanlines
}

void vga_cursor_enable(uint8_t start, uint8_t end)
{
    if (s_vbe_console_active)
    {
        // No hardware cursor in VBE text backend. Ignore.
        return;
    }

    outb(0x3D4, 0x0A);                 // Cursor Start
    uint8_t cur = inb(0x3D5);
    outb(0x3D5, (cur & 0xC0) | (start & 0x1F));  // bit5 = 0 => enable

    outb(0x3D4, 0x0B);                 // Cursor End
    cur = inb(0x3D5);
    outb(0x3D5, (cur & 0xE0) | (end & 0x1F));
}

void vga_cursor_disable(void)
{
    if (s_vbe_console_active)
    {
        return;
    }

    outb(0x3D4, 0x0A);
    uint8_t cur = inb(0x3D5);
    outb(0x3D5, cur | 0x20);           // bit5 = 1 => disable
}

// Switch console backend between VGA text and VBE text framebuffer.
void console_use_vbe(int active)
{
    if (active)
    {
        if (vbe_text_init())
        {
            s_vbe_console_active = 1;
            vbe_apply_colors_from_attrib(current_attrib);
            vbe_text_clear(0xFF000000u); // Clear to background (black)
            cursor_x = 0;
            cursor_y = 0;
            vbe_text_set_cursor(0, 0);
            return;
        }
        // If init failed, fall back to VGA
    }

    s_vbe_console_active = 0;
}

// Print a character to the screen
void putch(char c)
{
#ifdef DIFF_DEBUG
    serial_putc(c);
#endif

    putch_color(current_attrib, c);
}

static inline int at_floor(void)
{
    if (!floor_enabled)
    {
        return 0;
    }

    if (cursor_y < floor_y)
    {
        return 1;
    }

    if (cursor_y > floor_y)
    {
        return 0;
    }

    return cursor_x <= floor_x;
}

void set_input_floor(int x, int y)
{
    if (x < 0)
    {
        x = 0;
    }

    if (x >= SCREEN_WIDTH)
    {
        x = SCREEN_WIDTH - 1;
    }

    if (y < 0)
    {
        y = 0;
    }

    if (y >= SCREEN_HEIGHT)
    {
        y = SCREEN_HEIGHT - 1;
    }

    floor_enabled = 1;
    floor_x = x;
    floor_y = y;
}

void clear_input_floor(void)
{
    floor_enabled = 0;
}

void set_cursor_pos(unsigned short col, unsigned short row)
{
    cursor_x = col;
    cursor_y = row;

    if (s_vbe_console_active)
    {
        // VBE text backend uses cell coordinates directly
        vbe_text_set_cursor(col, row);
        return;
    }

    unsigned short pos = row * SCREEN_WIDTH + col;

    // VGA hardware cursor
    outb(0x3D4, 0x0F);
    outb(0x3D5, (unsigned char)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (unsigned char)((pos >> 8) & 0xFF));
}

unsigned short get_cursor_pos(void)
{
    if (s_vbe_console_active)
    {
        // Synthesize from our shadow cursor
        return (unsigned short)(cursor_y * SCREEN_WIDTH + cursor_x);
    }

    unsigned short pos = 0;
    outb(0x3D4, 0x0F);
    pos |= inb(0x3D5);
    outb(0x3D4, 0x0E);
    pos |= ((unsigned short)inb(0x3D5)) << 8;
    return pos;
}

void get_cursor(int *x, int *y)
{
    if (x)
    {
        *x = cursor_x;
    }

    if (y)
    {
        *y = cursor_y;
    }
}

unsigned short get_row(void)
{
    return get_cursor_pos() / SCREEN_WIDTH;
}

unsigned short get_col(void)
{
    return get_cursor_pos() % SCREEN_WIDTH;
}

int console_is_vbe_active(void)
{
    return s_vbe_console_active;
}

void putch_color(unsigned char attrib, char c)
{
    log_append(attrib, c);

    if (s_vbe_console_active)
    {
        // Respect input floor for backspace
        if (c == '\b')
        {
            if (at_floor())
            {
                return;
            }
        }

        // Update colors if attribute changed
        if (attrib != current_attrib)
        {
            current_attrib = attrib;
            vbe_apply_colors_from_attrib(current_attrib);
        }

        // Handle tabs manually to align with 4-space stops
        if (c == '\t')
        {
            uint32_t x, y;
            vbe_text_get_cursor(&x, &y);
            uint32_t next = (x + 4) & ~3u;

            while (x < next)
            {
                vbe_text_putchar(' ');
                vbe_text_get_cursor(&x, &y);
            }

            cursor_x = (int)x;
            cursor_y = (int)y;
            return;
        }

        // Forward the character to VBE renderer
        vbe_text_putchar(c);

        // Sync our shadow cursor with backend
        uint32_t cx, cy;
        vbe_text_get_cursor(&cx, &cy);
        cursor_x = (int)cx;
        cursor_y = (int)cy;

        return;
    }

    // ----- VGA text mode path -----

    if (c == '\n')
    {
        cursor_x = 0;
        cursor_y++;
    }
    else if (c == '\r')
    {
        cursor_x = 0;
    }
    else if (c == '\t')
    {
        cursor_x += 4;
        set_x(cursor_x);
    }
    else if (c == '\b')
    {
        if (!at_floor() && cursor_x > 0)
        {
            cursor_x--;
            putch(' ');
            cursor_x--;
            set_x(cursor_x);
            return;
        }
    }
    else
    {
        if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) &&
            (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
        {
            VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] =
                ((unsigned short)attrib << 8) | (unsigned char)c;
        }

        cursor_x++;

        if (cursor_x >= SCREEN_WIDTH)
        {
            cursor_x = 0;
            cursor_y++;
        }
    }

    if (cursor_y >= SCREEN_HEIGHT)
    {
        for (int y = 1; y < SCREEN_HEIGHT; y++)
        {
            for (int x = 0; x < SCREEN_WIDTH; x++)
            {
                VIDEO_MEMORY[x + SCREEN_WIDTH * (y - 1)] =
                    VIDEO_MEMORY[x + SCREEN_WIDTH * y];
            }
        }

        for (int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * (SCREEN_HEIGHT - 1)] =
                ((unsigned short)current_attrib << 8) | ' ';
        }

        cursor_y = SCREEN_HEIGHT - 1;
    }

    set_cursor_pos(cursor_x, cursor_y);
}

int puts(const char *str)
{
    while (*str)
    {
        putch(*str++);
    }

    return 0;
}

void set_color(unsigned char attrib)
{
    current_attrib = attrib;

    if (s_vbe_console_active)
    {
        vbe_apply_colors_from_attrib(current_attrib);
    }
}

void set_x(int x)
{
    if (x >= 0 && x < SCREEN_WIDTH)
    {
        cursor_x = x;
        set_cursor_pos(cursor_x, cursor_y);
    }
}

void set_y(int y)
{
    if (y >= 0 && y < SCREEN_HEIGHT)
    {
        cursor_y = y;
        set_cursor_pos(cursor_x, cursor_y);
    }
}

void set_pos(int x, int y)
{
    set_x(x);
    set_y(y);
}

void clear(void)
{
    if (s_vbe_console_active)
    {
        // Clear to the current background color derived from VGA attribute
        uint8_t bg = (current_attrib >> 4) & 0x0F;
        uint32_t argb_bg = 0xFF000000u | s_vga_rgb[bg];
        vbe_text_clear(argb_bg);
        vbe_text_set_cursor(0, 0);
        cursor_x = 0;
        cursor_y = 0;
        return;
    }

    for (int y = 0; y < SCREEN_HEIGHT; y++)
    {
        for (int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * y] =
                ((unsigned short)current_attrib << 8) | ' ';
        }
    }

    set_pos(0, 0);
}

void puthex(int value)
{
    for (int i = 7; i >= 0; i--)
    {
        int nibble = (value >> (i * 4)) & 0xF;
        char hex_char = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
        putch(hex_char);
    }
}

void console_set_background_color(uint32_t bg_argb)
{
    uint32_t fg, x, y;
    vbe_text_get_cursor(&x, &y); 
    fg = 0xFFD0D0D0u;
    vbe_text_set_colors(fg, bg_argb);
    vbe_text_clear(bg_argb);
    vbe_text_set_cursor(x, y);
}
