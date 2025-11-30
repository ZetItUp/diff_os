#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <diffwm/diffwm.h>
#include <diffgfx/draw.h>
#include <difffonts/fonts.h>
#include <system/threads.h>

#define WIN_W 640
#define WIN_H 400

#define MAX_LINES 128
#define MAX_COLS  256

static char g_lines[MAX_LINES][MAX_COLS];
static int g_line_count = 0;

static void append_text(const char *data, int len)
{
    int row = g_line_count - 1;
    if (row < 0)
    {
        row = 0;
        g_line_count = 1;
        g_lines[0][0] = '\0';
    }

    for (int i = 0; i < len; ++i)
    {
        char c = data[i];
        if (c == '\r')
        {
            continue;
        }

        if (c == '\n' || (int)strlen(g_lines[row]) >= (MAX_COLS - 1))
        {
            if (g_line_count < MAX_LINES) g_line_count++;
            row = g_line_count - 1;
            g_lines[row][0] = '\0';
            if (c == '\n')
            {
                continue;
            }
        }

        size_t len_row = strlen(g_lines[row]);
        if (len_row < (size_t)(MAX_COLS - 1))
        {
            g_lines[row][len_row] = c;
            g_lines[row][len_row + 1] = '\0';
        }
    }
}

static void render(uint32_t *pix, int pitch_pixels, font_t *font)
{
    size_t total = (size_t)WIN_W * WIN_H;
    for (size_t i = 0; i < total; ++i)
    {
        pix[i] = color_rgb(16, 16, 24);
    }

    if (!font)
    {
        return;
    }

    int fh = font_height(font);
    int y = 8;
    for (int i = 0; i < g_line_count; ++i)
    {
        font_draw_text(font, pix, pitch_pixels, 8, y, g_lines[i], color_rgb(235, 235, 235));
        y += fh;
        if (y >= WIN_H - fh)
        {
            break;
        }
    }
}

int main(void)
{
    printf("[gdterm] start\n");
    window_t *win = window_create(80, 80, WIN_W, WIN_H, 0);
    if (!win)
    {
        printf("[gdterm] failed to create window\n");
        return -1;
    }

    uint32_t *back = (uint32_t*)malloc((size_t)WIN_W * WIN_H * sizeof(uint32_t));
    if (!back)
    {
        printf("[gdterm] failed to alloc backbuffer\n");
        window_destroy(win);
        return -2;
    }

    font_t *font = font_load_bdf("/system/fonts/spleen-8x16.bdf");
    if (!font)
    {
        printf("[gdterm] failed to load font\n");
    }

    const char *hello = "Hello World\n";
    write(1, hello, (unsigned)strlen(hello));
    printf("[gdterm] wrote hello\n");

    char buf[256];
    int dirty = 1;
    uint32_t idle = 0;

    while (1)
    {
        int n = system_tty_read(buf, (uint32_t)sizeof(buf));
        if (n > 0)
        {
            append_text(buf, n);
            dirty = 1;
        }

        if (dirty)
        {
            render(back, WIN_W, font);
            window_draw(win, back);
            dirty = 0;
            printf("[gdterm] redraw\n");
        }
        else
        {
            if ((idle++ % 500) == 0)
            {
                printf("[gdterm] idle\n");
            }
        }

        thread_sleep_ms(10);
    }

    font_destroy(font);
    free(back);
    window_destroy(win);
    return 0;
}
