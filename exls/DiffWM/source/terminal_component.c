#include <diffwm/terminal_component.h>
#include <diffwm/window_component.h>
#include <string.h>

static void ensure_line(terminal_component_t *term, int y)
{
    if (!term)
        return;

    while (term->line_count <= y)
    {
        if (term->line_count >= TERM_MAX_LINES)
        {
            // Scroll up
            for (int i = 0; i < TERM_MAX_LINES - 1; i++)
            {
                term->lines[i] = term->lines[i + 1];
            }
            term->line_count = TERM_MAX_LINES - 1;
        }

        term->lines[term->line_count].len = 0;
        term->lines[term->line_count].text[0] = '\0';
        term->line_count++;
    }
}

static void putc_at(terminal_component_t *term, int x, int y, char c, term_color_t color)
{
    if (!term)
        return;

    if (y < 0 || y >= TERM_MAX_LINES || x < 0 || x >= TERM_MAX_COLS)
        return;

    ensure_line(term, y);

    if (x >= term->lines[y].len)
    {
        // Extend line
        for (int i = term->lines[y].len; i < x; i++)
        {
            term->lines[y].text[i] = ' ';
            term->lines[y].colors[i] = color;
        }
        term->lines[y].len = x + 1;
    }

    term->lines[y].text[x] = c;
    term->lines[y].colors[x] = color;
    term->lines[y].text[term->lines[y].len] = '\0';
}

void terminal_component_init(terminal_component_t *term, int x, int y, int width, int height, font_t *font)
{
    if (!term)
        return;

    // Initialize base component
    window_component_init(&term->base, x, y, width, height);

    // Initialize terminal state
    term->line_count = 0;
    term->cursor_x = 0;
    term->cursor_y = 0;
    term->font = font;

    // Default colors (white on black)
    term->current_color.r = 255;
    term->current_color.g = 255;
    term->current_color.b = 255;
    term->current_color.a = 255;

    term->bg_color.r = 0;
    term->bg_color.g = 0;
    term->bg_color.b = 0;
    term->bg_color.a = 255;

    term->selection_color = 0xFF3366CC;

    // Initialize selection
    text_selection_init(&term->selection);

    // Set polymorphic function pointers
    term->base.update = terminal_component_update;
    term->base.draw = terminal_component_paint;
}

void terminal_putchar(terminal_component_t *term, char c)
{
    if (!term)
        return;

    if (c == '\n')
    {
        term->cursor_y++;
        term->cursor_x = 0;
        return;
    }

    if (c == '\r')
    {
        term->cursor_x = 0;
        return;
    }

    putc_at(term, term->cursor_x, term->cursor_y, c, term->current_color);
    term->cursor_x++;

    if (term->cursor_x >= TERM_MAX_COLS)
    {
        term->cursor_x = 0;
        term->cursor_y++;
    }
}

void terminal_puts(terminal_component_t *term, const char *s)
{
    if (!term || !s)
        return;

    while (*s)
    {
        terminal_putchar(term, *s++);
    }
}

void terminal_set_color(terminal_component_t *term, term_color_t color)
{
    if (!term)
        return;

    term->current_color = color;
}

void terminal_clear(terminal_component_t *term)
{
    if (!term)
        return;

    term->line_count = 0;
    term->cursor_x = 0;
    term->cursor_y = 0;
    text_selection_clear(&term->selection);
}

void terminal_backspace(terminal_component_t *term)
{
    if (!term)
        return;

    if (term->cursor_x > 0)
    {
        term->cursor_x--;

        // Ensure line exists
        ensure_line(term, term->cursor_y);

        // Replace character with space
        if (term->cursor_x < term->lines[term->cursor_y].len)
        {
            term->lines[term->cursor_y].text[term->cursor_x] = ' ';
            term->lines[term->cursor_y].colors[term->cursor_x] = term->current_color;

            // If we're backspacing the last character, shrink the line
            if (term->cursor_x == term->lines[term->cursor_y].len - 1)
            {
                // Trim trailing spaces
                while (term->lines[term->cursor_y].len > 0 &&
                       term->lines[term->cursor_y].text[term->lines[term->cursor_y].len - 1] == ' ')
                {
                    term->lines[term->cursor_y].len--;
                }
                term->lines[term->cursor_y].text[term->lines[term->cursor_y].len] = '\0';
            }
        }
    }
}

void terminal_component_update(window_component_t *self)
{
    // No update logic needed for now
    (void)self;
}

void terminal_component_paint(window_component_t *self)
{
    // Placeholder for polymorphic interface
    // Direct rendering is done via terminal_component_render()
    (void)self;
}

void terminal_component_render(terminal_component_t *term, uint32_t *pixels, int pitch_pixels)
{
    if (!term || !pixels || !term->font)
        return;

    int width = term->base.width;
    int height = term->base.height;
    int fh = font_height(term->font);
    int fw = font_width(term->font);

    // Clear background to bg_color
    uint32_t bg = (term->bg_color.a << 24) | (term->bg_color.r << 16) |
                  (term->bg_color.g << 8) | term->bg_color.b;

    size_t total = (size_t)width * height;
    for (size_t i = 0; i < total; i++)
    {
        pixels[i] = bg;
    }

    // Render selection highlight (if any)
    // text_render_selection(pixels, pitch_pixels, width, height,
    //                      &term->selection, 8, 8, term->font, term->selection_color);

    // Render text lines
    int y_pos = 8;
    for (int i = 0; i < term->line_count && i < TERM_MAX_LINES; i++)
    {
        int x_pos = 8;
        for (int j = 0; j < term->lines[i].len && j < TERM_MAX_COLS; j++)
        {
            term_color_t fg = term->lines[i].colors[j];
            uint32_t fg_color = (fg.a << 24) | (fg.r << 16) | (fg.g << 8) | fg.b;
            char buf[2] = {term->lines[i].text[j], '\0'};
            font_draw_text(term->font, pixels, pitch_pixels, x_pos, y_pos, buf, fg_color);
            x_pos += fw;
        }
        y_pos += fh;
        if (y_pos >= height - fh)
            break;
    }

    // Draw cursor as underscore
    if (term->cursor_y >= 0 && term->cursor_y < term->line_count)
    {
        int cursor_screen_y = 8 + term->cursor_y * fh;
        int cursor_screen_x = 8 + term->cursor_x * fw;

        if (cursor_screen_y < height - fh)
        {
            for (int x = 0; x < fw - 1; x++)
            {
                int px = cursor_screen_x + x;
                int py = cursor_screen_y + fh - 5;
                if (px < width && py < height)
                {
                    uint32_t cursor_color = (term->current_color.a << 24) |
                                           (term->current_color.r << 16) |
                                           (term->current_color.g << 8) |
                                           term->current_color.b;
                    pixels[py * pitch_pixels + px] = cursor_color;
                }
            }
        }
    }
}
