#include "io.h"
#include "console.h"
#include "stdint.h"
#include "stdio.h"
#include "serial.h"
#include "graphics/vbe_text.h"
#include "interfaces.h"

#define SCREEN_WIDTH 80
#define SCREEN_HEIGHT 25
#define VIDEO_MEMORY ((volatile unsigned short*)0xB8000)
#ifndef CONSOLE_LOG_CAP
#define CONSOLE_LOG_CAP 16384
#endif

static int cursor_x = 0;
static int cursor_y = 0;
static int floor_enabled = 0;
static int floor_x = 0;
static int floor_y = 0;
static int s_vbe_console_active = 0;
static int s_console_disabled = 0;
static int s_replaying = 0;
unsigned char current_attrib = MAKE_COLOR(FG_GRAY, BG_BLACK);

typedef struct console_log_entry
{
    unsigned char attrib;
    char ch;
} console_log_entry_t;

static console_log_entry_t s_logbuf[CONSOLE_LOG_CAP];
static unsigned s_log_head = 0;
static unsigned s_log_count = 0;

static const uint32_t s_vga_rgb[16] =
{
    0x000000, 
    0x0000AA, 
    0x00AA00, 
    0x00AAAA, 
    0xAA0000, 
    0xAA00AA, 
    0xAA5500, 
    0xAAAAAA,
    0x555555, 
    0x5555FF, 
    0x55FF55, 
    0x55FFFF, 
    0xFF5555, 
    0xFF55FF, 
    0xFFFF55, 
    0xFFFFFF
};

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

static inline void vbe_apply_colors_from_attrib(unsigned char attrib)
{
    uint8_t fg = (uint8_t)(attrib & 0x0F);
    uint8_t bg = (uint8_t)((attrib >> 4) & 0x0F);
    uint32_t argb_fg = 0xFF000000u | s_vga_rgb[fg];
    uint32_t argb_bg = 0xFF000000u | s_vga_rgb[bg];

    vbe_text_set_colors(argb_fg, argb_bg);
}

static inline void render_raw(unsigned char attrib, char c)
{
    if (console_is_vbe_active())
    {
        /* PATCH: golvskydd för backspace i VBE-väg */
        if (c == '\b')
        {
            if (at_floor())
            {
                return;
            }

            uint32_t x, y;
            vbe_text_get_cursor(&x, &y);

            if (x > 0)
            {
                vbe_text_set_cursor(x - 1, y);
                vbe_text_putchar(' ');
                vbe_text_set_cursor(x - 1, y);
                cursor_x = (int)(x - 1);
                cursor_y = (int)y;
            }

            return;
        }

        if (attrib != current_attrib)
        {
            current_attrib = attrib;
        }

        vbe_apply_colors_from_attrib(current_attrib);

        if (c == '\t')
        {
            uint32_t x, y;

            vbe_text_get_cursor(&x, &y);

            uint32_t next = (x + 4u) & ~3u;

            while (x < next)
            {
                vbe_text_putchar(' ');
                vbe_text_get_cursor(&x, &y);
            }

            cursor_x = (int)x;
            cursor_y = (int)y;

            return;
        }

        /* PATCH: CR får inte hoppa över golvet i VBE-väg */
        if (c == '\r')
        {
            uint32_t x, y;

            vbe_text_get_cursor(&x, &y);
            if (!at_floor())
            {
                vbe_text_set_cursor(0, y);
                cursor_x = 0;
            }
            else
            {
                /* behåll x om vi står vid eller före golvet */
                cursor_x = (int)x;
            }
            cursor_y = (int)y;

            return;
        }

        if (c == '\n')
        {
            uint32_t x0, y0;
            vbe_text_get_cursor(&x0, &y0);
            vbe_text_putchar('\n');

            uint32_t x1, y1;
            vbe_text_get_cursor(&x1, &y1);
            vbe_text_set_cursor(0, y1);
            cursor_x = 0;
            cursor_y = (int)y1;

            return;
        }

        vbe_text_putchar(c);

        uint32_t cx, cy;
        vbe_text_get_cursor(&cx, &cy);
        cursor_x = (int)cx;
        cursor_y = (int)cy;

        return;
    }

    /* TEXT-VGA-väg */

    if (c == '\n')
    {
        cursor_x = 0;
        cursor_y++;
    }
    else if (c == '\r')
    {
        /* PATCH: CR ska inte flytta förbi golvet */
        if (!at_floor())
        {
            cursor_x = 0;
        }
        /* annars behåll positionen */
    }
    else if (c == '\t')
    {
        int next = (cursor_x + 4) & ~3;

        while (cursor_x < next)
        {
            if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) && (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
            {
                VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | ' ';
            }
            cursor_x++;
        }

        set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);

        return;
    }
    else if (c == '\b')
    {
        /* PATCH: backspace ska respektera golvet även i render_raw */
        if (!at_floor() && cursor_x > 0)
        {
            cursor_x--;

            if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) && (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
            {
                VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | ' ';
            }

            set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);
        }

        return;
    }
    else
    {
        if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) && (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
        {
            VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | (unsigned char)c;
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
                VIDEO_MEMORY[x + SCREEN_WIDTH * (y - 1)] = VIDEO_MEMORY[x + SCREEN_WIDTH * y];
            }
        }

        for (int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * (SCREEN_HEIGHT - 1)] = ((unsigned short)current_attrib << 8) | ' ';
        }

        cursor_y = SCREEN_HEIGHT - 1;
    }

    set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);
}

static inline void log_append(unsigned char attrib, char c)
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
}

uint8_t vga_cell_height(void)
{
    if (s_vbe_console_active)
    {
        return 16;
    }

    outb(0x3D4, 0x09);

    return (uint8_t)((inb(0x3D5) & 0x1F) + 1);
}

void vga_cursor_enable(uint8_t start, uint8_t end)
{
    if (s_vbe_console_active)
    {
        return;
    }

    outb(0x3D4, 0x0A);
    uint8_t cur = inb(0x3D5);
    outb(0x3D5, (unsigned char)((cur & 0xC0) | (start & 0x1F)));
    outb(0x3D4, 0x0B);
    cur = inb(0x3D5);
    outb(0x3D5, (unsigned char)((cur & 0xE0) | (end & 0x1F)));
}

void vga_cursor_disable(void)
{
    if (s_vbe_console_active)
    {
        return;
    }

    outb(0x3D4, 0x0A);
    uint8_t cur = inb(0x3D5);
    outb(0x3D5, (unsigned char)(cur | 0x20));
}

void console_use_vbe(int active)
{
    if (active)
    {
        if (vbe_text_init())
        {
            s_vbe_console_active = 1;
            vbe_apply_colors_from_attrib(current_attrib);
            uint8_t bg = (uint8_t)((current_attrib >> 4) & 0x0F);
            uint32_t argb_bg = 0xFF000000u | s_vga_rgb[bg];

            vbe_text_clear(argb_bg);
            vbe_text_set_cursor(0, 0);
            cursor_x = 0;
            cursor_y = 0;

            return;
        }
    }

    s_vbe_console_active = 0;
}

void putch(char c)
{
    unsigned long eflags;

    asm volatile("pushf; pop %0" : "=r"(eflags));
    asm volatile("cli");

    if (!s_replaying)
    {
        if (c == '\n')
        {
            serial_putc('\r');
            serial_putc('\n');
        }
        else
        {
            serial_putc(c);
        }
    }

    log_append(current_attrib, c);
    putch_color(current_attrib, c);

    if (eflags & (1u << 9))
    {
        asm volatile("sti");
    }
}

void putch_color(unsigned char attrib, char c)
{
    if (s_vbe_console_active)
    {
        if (attrib != current_attrib)
        {
            current_attrib = attrib;
        }

        vbe_apply_colors_from_attrib(current_attrib);

        if (c == '\b')
        {
            if (!at_floor())
            {
                uint32_t x, y;

                vbe_text_get_cursor(&x, &y);
                if (x > 0)
                {
                    vbe_text_set_cursor(x - 1, y);
                    vbe_text_putchar(' ');
                    vbe_text_set_cursor(x - 1, y);
                    cursor_x = (int)(x - 1);
                    cursor_y = (int)y;
                }
            }

            return;
        }

        if (c == '\r')
        {
            uint32_t x, y;

            vbe_text_get_cursor(&x, &y);
            vbe_text_set_cursor(0, y);
            cursor_x = 0;
            cursor_y = (int)y;

            return;
        }

        if (c == '\n')
        {
            vbe_text_putchar('\n');
            uint32_t cx, cy;
            vbe_text_get_cursor(&cx, &cy);
            cursor_x = (int)cx;
            cursor_y = (int)cy;

            return;
        }

        if (c == '\t')
        {
            uint32_t x, y;

            vbe_text_get_cursor(&x, &y);
            uint32_t next = (x + 4u) & ~3u;
            while (x < next)
            {
                vbe_text_putchar(' ');
                vbe_text_get_cursor(&x, &y);
            }
            cursor_x = (int)x;
            cursor_y = (int)y;

            return;
        }

        vbe_text_putchar(c);

        uint32_t cx, cy;
        vbe_text_get_cursor(&cx, &cy);
        cursor_x = (int)cx;
        cursor_y = (int)cy;

        return;
    }

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
        int next = (cursor_x + 4) & ~3;

        while (cursor_x < next)
        {
            if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) && (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
            {
                VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | ' ';
            }
            cursor_x++;
        }

        set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);

        return;
    }
    else if (c == '\b')
    {
        if (!at_floor() && cursor_x > 0)
        {
            cursor_x--;

            if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) && (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
            {
                VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | ' ';
            }

            set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);
        }

        return;
    }
    else
    {
        if ((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) && (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
        {
            VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | (unsigned char)c;
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
                VIDEO_MEMORY[x + SCREEN_WIDTH * (y - 1)] = VIDEO_MEMORY[x + SCREEN_WIDTH * y];
            }
        }

        for (int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * (SCREEN_HEIGHT - 1)] = ((unsigned short)current_attrib << 8) | ' ';
        }

        cursor_y = SCREEN_HEIGHT - 1;
    }

    set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);
}

void console_flush_log(void)
{
    int saved_floor_enabled = floor_enabled;
    int saved_floor_x = floor_x;
    int saved_floor_y = floor_y;

    floor_enabled = 0;
    s_replaying = 1;
    clear();

    unsigned idx = (s_log_head + CONSOLE_LOG_CAP - s_log_count) % CONSOLE_LOG_CAP;

    for (unsigned i = 0; i < s_log_count; i++)
    {
        console_log_entry_t e = s_logbuf[idx];

        render_raw(e.attrib, e.ch);
        idx++;

        if (idx == CONSOLE_LOG_CAP)
        {
            idx = 0;
        }
    }

    s_replaying = 0;
    floor_enabled = saved_floor_enabled;
    floor_x = saved_floor_x;
    floor_y = saved_floor_y;
}

int console_puts(const char* str)
{
    if (!str)
    {
        return -1;
    }

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

        set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);
    }
}

void set_y(int y)
{
    if (y >= 0 && y < SCREEN_HEIGHT)
    {
        cursor_y = y;

        set_cursor_pos((unsigned short)cursor_x, (unsigned short)cursor_y);
    }
}

void set_pos(int x, int y)
{
    set_x(x);
    set_y(y);
}

void get_cursor(int* x, int* y)
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

unsigned short get_cursor_pos(void)
{
    if (s_vbe_console_active)
    {
        return (unsigned short)(cursor_y * SCREEN_WIDTH + cursor_x);
    }

    unsigned short pos = 0;

    outb(0x3D4, 0x0F);
    pos |= inb(0x3D5);
    outb(0x3D4, 0x0E);
    pos |= ((unsigned short)inb(0x3D5)) << 8;

    return pos;
}

unsigned short get_row(void)
{
    return (unsigned short)(get_cursor_pos() / (unsigned short)SCREEN_WIDTH);
}

unsigned short get_col(void)
{
    return (unsigned short)(get_cursor_pos() % (unsigned short)SCREEN_WIDTH);
}

void clear(void)
{
    if (s_vbe_console_active)
    {
        vbe_text_clear(0xFF000000);
        vbe_text_set_cursor(0, 0);
        cursor_x = 0;
        cursor_y = 0;

        return;
    }

    for (int y = 0; y < SCREEN_HEIGHT; y++)
    {
        for (int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * y] = ((unsigned short)current_attrib << 8) | ' ';
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

int console_is_vbe_active(void)
{
    return s_vbe_console_active;
}

void set_cursor_pos(unsigned short x, unsigned short y)
{
    cursor_x = x;
    cursor_y = y;

    if (s_vbe_console_active)
    {
        vbe_text_set_cursor((uint32_t)x, (uint32_t)y);

        return;
    }

    unsigned short pos = (unsigned short)(y * SCREEN_WIDTH + x);

    outb(0x3D4, 0x0F);
    outb(0x3D5, (unsigned char)(pos & 0xFF));
    outb(0x3D4, 0x0E);
    outb(0x3D5, (unsigned char)((pos >> 8) & 0xFF));
}

int console_toggle_graphics_mode(void)
{
    if (!s_vbe_console_active)
    {
        console_use_vbe(1);
        console_flush_log();
    }
    else
    {
        console_use_vbe(0);
    }

    return s_vbe_console_active;
}

int console_get_graphics_mode(void)
{
    return s_vbe_console_active;
}

void console_restore_text_mode(void)
{
    if (s_console_disabled)
    {
        return;
    }

    int console_off = !console_is_vbe_active();
    int mode_changed = !vbe_is_default_mode();

    if (!console_off && !mode_changed)
    {
        return;
    }

    if (mode_changed && vbe_restore_default_mode() == 0)
    {
        vbe_clear(0xFF000000u);
    }

    if (console_off)
    {
        console_use_vbe(1);
    }
    console_flush_log();
}

void console_disable(void)
{
    s_console_disabled = 1;
}
